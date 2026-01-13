import hashlib
import secrets
import os
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session
# from validator import validate_password_security, validate_email_format, validate_phone_number  <-- נוטרל
from DB_MANAGMENT import (
    Establish_DB_Connection,
    CloseDBConnection,
    CheckIfUserExists,
    AddUserToDB,
    SaveResetToken,
    GetResetTokenRow,
    DeleteResetToken,
    AddCustomer,
    ListCustomers,
    GetUserPassword,
    UpdateUserPassword,
    VulnerableLogin
)

app = Flask(__name__)
app.secret_key = os.urandom(32)
@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        pwd = request.form.get("password", "")

        conn = Establish_DB_Connection()
        if not conn:
            return render_template("login.html", error_msg="connection error")

        # === שינוי קריטי: שימוש בפונקציה הפריצה ===
        user = VulnerableLogin(conn, email, pwd)
        CloseDBConnection(conn)

        if user:
            # התחברות מוצלחת
            session.pop("reset_email", None)
            session["user_email"] = user["email"]
            return redirect(url_for("dashboard"))
        else:
            return render_template("login.html", error_msg="Wrong credentials")

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

    # ====================================================
    # Vulnerability: Validation Removed
    # ====================================================
    # error = validate_password_security(new_pwd)
    # if error:
    #     return render_template("change_password.html", error_msg=error)
    # ====================================================

    conn = Establish_DB_Connection()
    if not conn:
        return render_template("change_password.html", error_msg="connection error")

    db_pwd = GetUserPassword(conn, email)
    if db_pwd is None:
        CloseDBConnection(conn)
        return render_template("change_password.html", error_msg="User not found")
    
    if session.get("reset_email") is None:
        if current_pwd != db_pwd:
            CloseDBConnection(conn)
            return render_template("change_password.html", error_msg="Current password is incorrect")

    ok = UpdateUserPassword(conn, email, new_pwd)
    if ok:
        DeleteResetToken(conn, email)

    CloseDBConnection(conn)

    if not ok:
        return render_template("change_password.html", error_msg="Failed to update password")

    session.pop("reset_email", None)
    session.pop("user_email", None)
    return redirect(url_for("login"))


@app.route("/dashboard", methods=["GET"])
def dashboard():
    email = session.get("user_email")
    if not email:
        return redirect(url_for("login"))

    conn = Establish_DB_Connection()
    if not conn:
        return render_template("dashboard.html", customers=[], error_msg="connection error")

    customers = ListCustomers(conn)
    CloseDBConnection(conn)
    return render_template("dashboard.html", customers=customers)


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

        # ====================================================
        # Vulnerability: Validation Removed (Email & Password)
        # ====================================================
        # error = validate_email_format(email)
        # if error:
        #     CloseDBConnection(conn)
        #     return render_template("register.html", error_msg=error)

        # error = validate_password_security(pwd)
        # if error:
        #     CloseDBConnection(conn)
        #     return render_template("register.html", error_msg=error)
        # ====================================================

        if CheckIfUserExists(conn, email):
            CloseDBConnection(conn)
            return render_template("register.html", error_msg="User already exists")

        success = AddUserToDB(conn, fname, lname, email, pwd, dob)
        CloseDBConnection(conn)

        if success:
            return redirect(url_for("login"))
        return render_template("register.html", error_msg="Error with DB")

    return render_template("register.html")

@app.route("/add_customer", methods=["GET", "POST"])
def add_customer():
    email = session.get("user_email")
    if not email:
        return redirect(url_for("login"))

    if request.method == "POST":
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        email_cust = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()

        if not first_name or not last_name:
            return render_template(
                "add_customer_form.html",
                error_msg="Please fill all required fields",
                first_name=first_name,
                last_name=last_name,
                email=email_cust,
                phone=phone
            )

        # ====================================================
        # Vulnerability: Validation Removed (Email & Phone)
        # ====================================================
        # if email_cust:
        #     error = validate_email_format(email_cust)
        #     if error:
        #         return render_template(
        #             "add_customer_form.html",
        #             error_msg=error,
        #             first_name=first_name,
        #             last_name=last_name,
        #             email=email_cust,
        #             phone=phone
        #         )

        # error = validate_phone_number(phone)
        # if error:
        #     return render_template(
        #         "add_customer_form.html",
        #         error_msg=error,
        #         first_name=first_name,
        #         last_name=last_name,
        #         email=email_cust,
        #         phone=phone
        #     )
        # ====================================================

        conn = Establish_DB_Connection()
        if not conn:
            return render_template(
                "add_customer_form.html",
                error_msg="Database connection error",
                first_name=first_name,
                last_name=last_name,
                email=email_cust,
                phone=phone
            )

        success = AddCustomer(conn, first_name, last_name, email_cust, phone)
        CloseDBConnection(conn)

        if success:
            return redirect(url_for("dashboard"))
        else:
            return render_template(
                "add_customer_form.html",
                error_msg="Failed to add customer",
                first_name=first_name,
                last_name=last_name,
                email=email_cust,
                phone=phone
            )

    return render_template("add_customer_form.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)