import hashlib
import secrets
import os
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session

from validator import (
    validate_password_security,
    validate_email_format,
    validate_phone_number,
    get_max_login_attempts,
)

from DB_MANAGMENT import (
    Establish_DB_Connection,
    CloseDBConnection,
    CheckIfUserExists,
    AddUserToDB,
    SaveResetToken,
    GetResetTokenRow,
    DeleteResetToken,
    IncrementResetAttempts,
    AddCustomer,
    ListCustomers,
    GetUserPassword,
    UpdateUserPassword,
    hash_password,
    verify_password,
    GetLoginState,
    IncrementFailedLogin,
    ResetFailedLogin,
    LockUser,
)


# =========================
# Flask mini tutorial
# =========================

# Flask(__name__)      -> יוצר את אפליקציית השרת
# app.secret_key      -> מפתח לחתימה על session (זיהוי משתמש)

# @app.route("שם הפונקציה שרוצים שתפעל")     -> מחבר כתובת לפונקציה - כול שורה כזאת יכולה לבצע קריאה לפונקציה אחת בלבד
# methods             -> GET = צפייה, POST = שליחת טופס

# request             -> נתוני הבקשה מהמשתמש
# request.form        -> שדות מטופס POST

# render_template()   -> החזרת HTML
# session             -> זיכרון זמני למשתמש מחובר

# redirect()          -> מעבר לכתובת אחרת
# url_for(func_name)  -> יצירת URL לפי שם פונקציה


app = Flask(__name__)  # יצירת האפליקציה
app.secret_key = os.urandom(32)  # מפתח סשן אקראי לשמירת משתמש מחובר


# הגדרות (מגיעות מהקונפיג / קבועים)
MAX_LOGIN_ATTEMPTS = get_max_login_attempts(default=3)
LOCK_MINUTES = 10
RESET_CODE_EXP_MINUTES = 10
RESET_MAX_ATTEMPTS = 5


# טיפול בהצגת דף התחברות - והתחברות
@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        pwd = request.form.get("password", "")

        if not email or not pwd:  # בדיקה שהשדות לא ריקים
            return render_template("login.html", error_msg="Please fill email and password")

        conn = Establish_DB_Connection()  # יצירת חיבור לבסיס נתונים
        if not conn:
            return render_template("login.html", error_msg="connection error")

        # בדיקה שהמשתמש קיים (לא לחשוף מידע לתוקף)
        if not CheckIfUserExists(conn, email):
            CloseDBConnection(conn)
            return render_template("login.html", error_msg="Invalid email or password")

        # בדיקה אם המשתמש נעול
        state = GetLoginState(conn, email)
        if state and state.get("lock_until"):
            try:
                if datetime.now() < state["lock_until"]:
                    CloseDBConnection(conn)
                    return render_template("login.html", error_msg="Account is temporarily locked. Try again later.")
            except Exception:
                pass

        db_pwd = GetUserPassword(conn, email)
        if db_pwd is None:
            CloseDBConnection(conn)
            return render_template("login.html", error_msg="Invalid email or password")

        if not verify_password(pwd, db_pwd):  # בדיקה שהסיסמא נכונה
            IncrementFailedLogin(conn, email)

            # אם עברנו את מספר הניסיונות - נועל ומחזיר הודעת נעילה כבר עכשיו
            state2 = GetLoginState(conn, email)
            failed = int((state2 or {}).get("failed_login_count", 0))
            if failed >= MAX_LOGIN_ATTEMPTS:
                LockUser(conn, email, LOCK_MINUTES)
                CloseDBConnection(conn)
                return render_template("login.html", error_msg="Account is temporarily locked. Try again later.")

            CloseDBConnection(conn)
            return render_template("login.html", error_msg="Invalid email or password")

        # הצלחה -> איפוס מונה ניסיונות
        ResetFailedLogin(conn, email)
        CloseDBConnection(conn)

        session.pop("reset_email", None)
        session["user_email"] = email
        return redirect(url_for("dashboard"))  # העברה למסך הראשי

    return render_template("login.html")



@app.route("/forgot_password", methods=["GET", "POST"])
# התחלת איפוס סיסמה: יצירת קוד ושמירה בבסיס הנתונים
def forgot_password():
    if request.method == "POST":  # בעת שליחת הטופס
        email = request.form.get("email", "").strip().lower()  # קריאת המייל מהטופס

        conn = Establish_DB_Connection()
        if not conn:
            return render_template("forgot_password.html", error_msg="connection error")

        if not CheckIfUserExists(conn, email):
            CloseDBConnection(conn)
            return render_template("forgot_password.html", error_msg="User not found")

        random_value = secrets.token_hex(16)  # יצירת ערך אקראי חזק (קריפטוגרפית)
        token_sha1 = hashlib.sha1(random_value.encode("utf-8")).hexdigest()  # יצירת קוד SHA-1 לפי הנחיות
        expires_at = datetime.now() + timedelta(minutes=RESET_CODE_EXP_MINUTES)  # תוקף לקוד

        SaveResetToken(conn, email, token_sha1, expires_at)
        CloseDBConnection(conn)

        # DEMO: כרגע לא שולחים מייל אמיתי - מציגים את הקוד בקונסול
        print("RESET CODE (SHA-1):", token_sha1)

        return redirect(url_for("verify_reset_code", email=email))

    return render_template("forgot_password.html")


@app.route("/verify_reset_code", methods=["GET", "POST"])
# אימות קוד איפוס לפני מעבר לשינוי סיסמה
def verify_reset_code():
    if request.method == "GET":
        email = request.args.get("email", "").strip().lower()
        return render_template("verify_reset_code.html", email=email)

    # POST: המשתמש שלח את הטופס עם email + code
    email = request.form.get("email", "").strip().lower()
    code = request.form.get("code", "").strip()

    conn = Establish_DB_Connection()
    if not conn:
        return render_template("verify_reset_code.html", email=email, error_msg="connection error")

    row = GetResetTokenRow(conn, email)
    if not row:
        CloseDBConnection(conn)
        return render_template("verify_reset_code.html", email=email, error_msg="No reset request found")

    # בדיקת תוקף
    if datetime.now() > row["expires_at"]:
        DeleteResetToken(conn, email)
        CloseDBConnection(conn)
        return render_template("verify_reset_code.html", email=email, error_msg="Code expired")

    # הגבלת ניסיונות הזנת קוד
    if int(row.get("attempts", 0)) >= RESET_MAX_ATTEMPTS:
        DeleteResetToken(conn, email)
        CloseDBConnection(conn)
        return render_template("verify_reset_code.html", email=email, error_msg="Too many attempts. Please reset again.")

    # בדיקת התאמה
    if code != row["token_sha1"]:
        IncrementResetAttempts(conn, email)
        CloseDBConnection(conn)
        return render_template("verify_reset_code.html", email=email, error_msg="Invalid code")

    CloseDBConnection(conn)

    session.pop("user_email", None)
    session["reset_email"] = email
    return redirect(url_for("change_password"))


@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    is_reset_flow = session.get("reset_email") is not None

    # GET: הצגת המסך
    if request.method == "GET":
        return render_template("change_password.html", is_reset_flow=is_reset_flow)

    # POST: קריאת שדות מהטופס
    current_pwd = request.form.get("currentPassword", "")
    new_pwd = request.form.get("newPassword", "")
    confirm_pwd = request.form.get("confirmPassword", "")

    email = session.get("reset_email") or session.get("user_email")
    if not email:
        return redirect(url_for("login"))

    # בדיקה שהסיסמאות החדשות תואמות
    if new_pwd != confirm_pwd:
        return render_template("change_password.html", error_msg="Passwords do not match", is_reset_flow=is_reset_flow)

    # בדיקת מדיניות סיסמה
    error = validate_password_security(new_pwd)
    if error:
        return render_template("change_password.html", error_msg=error, is_reset_flow=is_reset_flow)

    conn = Establish_DB_Connection()
    if not conn:
        return render_template("change_password.html", error_msg="connection error", is_reset_flow=is_reset_flow)

    db_pwd = GetUserPassword(conn, email)
    if db_pwd is None:
        CloseDBConnection(conn)
        return render_template("change_password.html", error_msg="User not found", is_reset_flow=is_reset_flow)

    # אם זה שינוי סיסמה רגיל -> חייבים לאמת סיסמה נוכחית
    if not is_reset_flow:
        if not verify_password(current_pwd, db_pwd):
            CloseDBConnection(conn)
            return render_template("change_password.html", error_msg="Current password is incorrect", is_reset_flow=is_reset_flow)

    hashed_new_pwd = hash_password(new_pwd)
    ok = UpdateUserPassword(conn, email, hashed_new_pwd)

    if ok and is_reset_flow:
        DeleteResetToken(conn, email)

    CloseDBConnection(conn)

    if not ok:
        return render_template("change_password.html", error_msg="Failed to update password", is_reset_flow=is_reset_flow)

    # ניקוי session
    session.pop("reset_email", None)
    session.pop("user_email", None)
    return redirect(url_for("login"))


@app.route("/dashboard", methods=["GET"])
# דף אחרי התחברות: הצגת לקוחות
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
# יצירת משתמש חדש במערכת
def register():
    if request.method == "POST":
        conn = Establish_DB_Connection()
        if not conn:
            return render_template("register.html", error_msg="Connection Error")

        # קריאת נתונים מהטופס
        fname = request.form.get("first_name", "")
        lname = request.form.get("last_name", "")
        email = request.form.get("email", "").strip().lower()
        pwd = request.form.get("password", "")
        dob = request.form.get("date_of_birth", "")

        # בדיקת תקינות אימייל
        error = validate_email_format(email)
        if error:
            CloseDBConnection(conn)
            return render_template("register.html", error_msg=error)

        # בדיקת חוזק סיסמא
        error = validate_password_security(pwd)
        if error:
            CloseDBConnection(conn)
            return render_template("register.html", error_msg=error)

        # בדיקה אם המשתמש קיים כבר
        if CheckIfUserExists(conn, email):
            CloseDBConnection(conn)
            return render_template("register.html", error_msg="User already exists")

        # יצירת משתמש בפועל
        hashed_pwd = hash_password(pwd)
        success = AddUserToDB(conn, fname, lname, email, hashed_pwd, dob)
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

        # בדיקת תקינות אימייל של הלקוח
        if email_cust:
            error = validate_email_format(email_cust)
            if error:
                return render_template(
                    "add_customer_form.html",
                    error_msg=error,
                    first_name=first_name,
                    last_name=last_name,
                    email=email_cust,
                    phone=phone
                )

        # בדיקת תקינות מספר טלפון
        error = validate_phone_number(phone)
        if error:
            return render_template(
                "add_customer_form.html",
                error_msg=error,
                first_name=first_name,
                last_name=last_name,
                email=email_cust,
                phone=phone
            )

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
