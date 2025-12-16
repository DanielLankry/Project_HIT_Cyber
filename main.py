import hashlib
import secrets
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session
from validator import validate_password_security
from DB_MANAGMENT import (
    Establish_DB_Connection,
    CloseDBConnection,
    CheckIfUserExists,
    AddUserToDB,
    SaveResetToken,
    GetResetTokenRow,
    DeleteResetToken,
)

app = Flask(__name__)
app.secret_key = "REMOVED_SESSION_SECRET"

def _get_user_password(conn, email: str):
    cur = conn.cursor()
    cur.execute("SELECT password FROM comunication_ltd.users WHERE email=%s LIMIT 1", (email,))
    row = cur.fetchone()
    cur.close()
    return row[0] if row else None


def _update_user_password(conn, email: str, new_password: str) -> bool:
    cur = conn.cursor()
    cur.execute("UPDATE comunication_ltd.users SET password=%s WHERE email=%s", (new_password, email))
    conn.commit()
    ok = cur.rowcount > 0
    cur.close()
    return ok


@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        pwd = request.form.get("password", "")

        if not email or not pwd:
            return render_template("login.html", error_msg="Please fill email and password")

        conn = Establish_DB_Connection()
        if not conn:
            return render_template("login.html", error_msg="connection error")

        if not CheckIfUserExists(conn, email):
            CloseDBConnection(conn)
            return render_template("login.html", error_msg="User not found")

        db_pwd = _get_user_password(conn, email)
        CloseDBConnection(conn)

        if db_pwd is None:
            return render_template("login.html", error_msg="User not found")

        if pwd != db_pwd:
            return render_template("login.html", error_msg="Wrong password")

        session.pop("reset_email", None)
        session["user_email"] = email
        return redirect(url_for("change_password"))

    return render_template("login.html")


@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"].strip().lower()

        conn = Establish_DB_Connection()
        if not conn:
            return render_template("forgot_password.html", error_msg="connection error")

        if not CheckIfUserExists(conn, email):
            CloseDBConnection(conn)
            return render_template("forgot_password.html", error_msg="User not found")

        random_value = secrets.token_hex(16)
        token_sha1 = hashlib.sha1(random_value.encode("utf-8")).hexdigest()
        expires_at = datetime.now() + timedelta(minutes=10)

        SaveResetToken(conn, email, token_sha1, expires_at)
        CloseDBConnection(conn)

        print("RESET CODE (SHA-1):", token_sha1)

        return redirect(url_for("verify_reset_code", email=email))

    return render_template("forgot_password.html")


@app.route("/verify_reset_code", methods=["GET", "POST"])
def verify_reset_code():
    if request.method == "GET":
        email = request.args.get("email", "").strip().lower()
        return render_template("verify_reset_code.html", email=email)

    email = request.form["email"].strip().lower()
    code = request.form["code"].strip()

    conn = Establish_DB_Connection()
    if not conn:
        return render_template("verify_reset_code.html", email=email, error_msg="connection error")

    row = GetResetTokenRow(conn, email)
    if not row:
        CloseDBConnection(conn)
        return render_template("verify_reset_code.html", email=email, error_msg="No reset request found")

    if datetime.now() > row["expires_at"]:
        DeleteResetToken(conn, email)
        CloseDBConnection(conn)
        return render_template("verify_reset_code.html", email=email, error_msg="Code expired")

    if code != row["token_sha1"]:
        CloseDBConnection(conn)
        return render_template("verify_reset_code.html", email=email, error_msg="Invalid code")

    CloseDBConnection(conn)

    session.pop("user_email", None)
    session["reset_email"] = email
    return redirect(url_for("change_password"))


@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    if request.method == "GET":
        return render_template("change_password.html")

    current_pwd = request.form.get("currentPassword", "")
    new_pwd = request.form.get("newPassword", "")
    confirm_pwd = request.form.get("confirmPassword", "")

    email = session.get("reset_email") or session.get("user_email")
    if not email:
        return redirect(url_for("login"))

    if new_pwd != confirm_pwd:
        return render_template("change_password.html", error_msg="Passwords do not match")

    error = validate_password_security(new_pwd)
    if error:
        return render_template("change_password.html", error_msg=error)

    conn = Establish_DB_Connection()
    if not conn:
        return render_template("change_password.html", error_msg="connection error")

    db_pwd = _get_user_password(conn, email)
    if db_pwd is None:
        CloseDBConnection(conn)
        return render_template("change_password.html", error_msg="User not found")

    if session.get("reset_email") is None:
        if current_pwd != db_pwd:
            CloseDBConnection(conn)
            return render_template("change_password.html", error_msg="Current password is incorrect")

    ok = _update_user_password(conn, email, new_pwd)
    if ok:
        DeleteResetToken(conn, email)

    CloseDBConnection(conn)

    if not ok:
        return render_template("change_password.html", error_msg="Failed to update password")

    session.pop("reset_email", None)
    session.pop("user_email", None)
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        conn = Establish_DB_Connection()
        if not conn:
            return render_template("register.html", error_msg="Connection Error")

        fname = request.form["first_name"]
        lname = request.form["last_name"]
        email = request.form["email"].strip().lower()
        pwd = request.form["password"]
        dob = request.form["date_of_birth"]

        error = validate_password_security(pwd)
        if error:
            CloseDBConnection(conn)
            return render_template("register.html", error_msg=error)

        if CheckIfUserExists(conn, email):
            CloseDBConnection(conn)
            return render_template("register.html", error_msg="User already exists")

        success = AddUserToDB(conn, fname, lname, email, pwd, dob)
        CloseDBConnection(conn)

        if success:
            return redirect(url_for("login"))
        return render_template("register.html", error_msg="Error with DB")

    return render_template("register.html")


if __name__ == "__main__":
    app.run(debug=False)
