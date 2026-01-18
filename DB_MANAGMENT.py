import mysql.connector
from mysql.connector import Error
from dotenv import load_dotenv
import hashlib
import hmac
import secrets
import os

load_dotenv()
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD")
MYSQL_USER_ADMIN = os.getenv("MYSQL_USER_ADMIN")
MYSQL_DB_NAME = os.getenv("MYSQL_DB_NAME")


# =========================
# Password: HMAC + Salt
# =========================
def hash_password(password):
    salt = secrets.token_hex(16)
    digest = hmac.new(salt.encode("utf-8"), password.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{salt}${digest}"


def verify_password(password, stored):
    if not stored or "$" not in stored:
        return False

    salt, digest = stored.split("$", 1)
    calc = hmac.new(salt.encode("utf-8"), password.encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(calc, digest)


# יוצר חיבור למסד הנתונים לפי פרטי הסביבה ומחזיר חיבור פעיל אם הצליח
def Establish_DB_Connection():
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user=MYSQL_USER_ADMIN,
            password=MYSQL_PASSWORD,
            database=MYSQL_DB_NAME,
            port=3306,
            charset="utf8mb4",
            autocommit=False,
        )
        print("Connected to the database")
        return conn

    except Error as err:
        print(f"Error: {err}")
        return None


# סוגר חיבור למסד הנתונים אם הוא פתוח
def CloseDBConnection(conn):
    try:
        if conn:
            conn.close()
            print("Database connection closed successfully")
            return True
        else:
            print("Connection was already closed or never established")
            return False

    except Exception as err:
        print(f"Error closing connection: {err}")
        return False


# בודק האם קיים משתמש לפי כתובת דואר אלקטרוני ומחזיר אמת או שקר
def CheckIfUserExists(conn, email):
    try:
        cur = conn.cursor()
        query = "SELECT COUNT(*) FROM comunication_ltd.users WHERE email = %s"
        cur.execute(query, (email,))
        count = cur.fetchone()[0]
        cur.close()
        return count > 0

    except Error as err:
        print(f"Error: {err}")
        return False


# מחזיר את הסיסמה של משתמש לפי כתובת דואר אלקטרוני
def GetUserPassword(conn, email):
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT password FROM comunication_ltd.users WHERE email=%s LIMIT 1",
            (email,)
        )
        row = cur.fetchone()
        cur.close()
        return row[0] if row else None

    except Error as err:
        print(f"Error: {err}")
        return None


# מוסיף משתמש חדש למסד הנתונים עם הפרטים שנשלחו
def AddUserToDB(conn, fname, lname, email, pwd, dob):
    try:
        cur = conn.cursor()
        query = (
            "INSERT INTO comunication_ltd.users "
            "(first_name, last_name, email, password, date_of_birth) "
            "VALUES (%s, %s, %s, %s, %s)"
        )
        cur.execute(query, (fname, lname, email, pwd, dob))
        conn.commit()
        cur.close()
        return True

    except Error as err:
        print(f"Error: {err}")
        return False


# מעדכן סיסמה של משתמש במסד הנתונים לפי כתובת דואר אלקטרוני
def UpdateUserPassword(conn, email, new_password):
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE comunication_ltd.users SET password=%s WHERE email=%s",
            (new_password, email)
        )
        conn.commit()
        ok = cur.rowcount > 0
        cur.close()
        return ok

    except Error as err:
        print(f"Error: {err}")
        return False


# =========================
# Login attempts (Lockout)
# =========================

# מביא מצב ניסיונות התחברות של משתמש
def GetLoginState(conn, email):
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT failed_login_count, lock_until FROM comunication_ltd.users WHERE email=%s LIMIT 1",
            (email,)
        )
        row = cur.fetchone()
        cur.close()
        return row
    except Error as err:
        print(f"Error: {err}")
        return None


# מגדיל מונה ניסיונות התחברות כושלים
def IncrementFailedLogin(conn, email):
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE comunication_ltd.users SET failed_login_count = failed_login_count + 1, last_login_attempt = NOW() "
            "WHERE email=%s",
            (email,)
        )
        conn.commit()
        cur.close()
        return True
    except Error as err:
        print(f"Error: {err}")
        return False


# מאפס מונה ניסיונות התחברות כושלים
def ResetFailedLogin(conn, email):
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE comunication_ltd.users SET failed_login_count = 0, lock_until = NULL, last_login_attempt = NULL "
            "WHERE email=%s",
            (email,)
        )
        conn.commit()
        cur.close()
        return True
    except Error as err:
        print(f"Error: {err}")
        return False


# נועל משתמש לזמן מוגדר בדקות
def LockUser(conn, email, minutes):
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE comunication_ltd.users SET lock_until = DATE_ADD(NOW(), INTERVAL %s MINUTE) WHERE email=%s",
            (minutes, email)
        )
        conn.commit()
        cur.close()
        return True
    except Error as err:
        print(f"Error: {err}")
        return False


# =========================
# Reset password tokens
# =========================

# שומר קוד איפוס סיסמה עם זמן תפוגה, לאחר מחיקת קוד קודם אם קיים
def SaveResetToken(conn, email, token_sha1, expires_at):
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM password_resets WHERE email=%s", (email,))
        cur.execute(
            "INSERT INTO password_resets (email, token_sha1, expires_at, attempts) VALUES (%s, %s, %s, 0)",
            (email, token_sha1, expires_at)
        )
        conn.commit()
        cur.close()
        return True
    except Error as err:
        print(f"Error: {err}")
        return False


# מחזיר את קוד איפוס הסיסמה האחרון של משתמש או ריק אם לא קיים
def GetResetTokenRow(conn, email):
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT * FROM password_resets WHERE email=%s ORDER BY created_at DESC LIMIT 1",
            (email,)
        )
        row = cur.fetchone()
        cur.close()
        return row
    except Error as err:
        print(f"Error: {err}")
        return None


# מגדיל ניסיונות הזנת קוד איפוס
def IncrementResetAttempts(conn, email):
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE password_resets SET attempts = attempts + 1 WHERE email=%s",
            (email,)
        )
        conn.commit()
        cur.close()
        return True
    except Error as err:
        print(f"Error: {err}")
        return False


# מוחק קוד איפוס סיסמה של משתמש
def DeleteResetToken(conn, email):
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM password_resets WHERE email=%s", (email,))
        conn.commit()
        cur.close()
        return True
    except Error as err:
        print(f"Error: {err}")
        return False


# =========================
# Customers
# =========================

# הוספת לקוח חדש לטבלת customers
def AddCustomer(conn, first_name, last_name, email=None, phone=None):
    try:
        cur = conn.cursor()
        query = (
            "INSERT INTO comunication_ltd.customers "
            "(first_name, last_name, email, phone) "
            "VALUES (%s, %s, %s, %s)"
        )
        cur.execute(query, (first_name, last_name, email, phone))
        conn.commit()
        cur.close()
        return True
    except Error as err:
        print(f"Error: {err}")
        return False


# מחזיר רשימת כל הלקוחות ממסד הנתונים
def ListCustomers(conn):
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM comunication_ltd.customers ORDER BY created_at DESC")
        rows = cur.fetchall()
        cur.close()
        return rows
    except Error as err:
        print(f"Error: {err}")
        return []
