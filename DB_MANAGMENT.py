import mysql.connector
from mysql.connector import Error
from dotenv import load_dotenv
import os

load_dotenv()
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD")
MYSQL_USER_ADMIN = os.getenv("MYSQL_USER_ADMIN")
MYSQL_DB_NAME = os.getenv("MYSQL_DB_NAME")


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


# מדפיס את כל הרשומות מטבלת המשתמשים (מיועד לבדיקה בלבד)
def printTopRows(conn):
    try:
        cur = conn.cursor()
        query = "SELECT * FROM comunication_ltd.users"
        cur.execute(query)
        print(cur.fetchall())
        cur.close()

    except Error as err:
        print(f"Error: {err}")


# בודק האם קיים משתמש לפי כתובת דואר אלקטרוני ומחזיר אמת או שקר
def CheckIfUserExists(conn, email):
    try:
        cur = conn.cursor()
        # Vulnerable: Direct string formatting
        query = f"SELECT COUNT(*) FROM comunication_ltd.users WHERE email = '{email}'"
        cur.execute(query)
        count = cur.fetchone()[0]
        cur.close()

        if count > 0:
            print(f"User with email {email} exists")
            return True
        else:
            print(f"User with email {email} does not exist")
            return False

    except Error as err:
        print(f"Error: {err}")
        return False

# פונקציה חדשה שמאפשרת SQL Injection להתחברות
def VulnerableLogin(conn, email, password):
    try:
        cur = conn.cursor(dictionary=True)
        # כאן נמצאת החולשה: בדיקת הסיסמה נעשית בתוך השאילתה הפריצה
        query = f"SELECT * FROM comunication_ltd.users WHERE email='{email}' AND password='{password}'"
        cur.execute(query)
        user = cur.fetchone()
        cur.close()
        return user
    except Error as err:
        print(f"Error: {err}")
        return None
    
# מחזיר את כל פרטי המשתמש לפי כתובת דואר אלקטרוני או ריק אם לא נמצא
def GetUserInfoByMail(conn, email):
    try:
        cur = conn.cursor(dictionary=True)
        # Vulnerable: Direct string formatting
        query = f"SELECT * FROM comunication_ltd.users WHERE email = '{email}'"
        cur.execute(query)
        user = cur.fetchone()
        cur.close()

        if user:
            print(f"User found: {user['first_name']} {user['last_name']}")
            return user
        else:
            print(f"No user found with email: {email}")
            return None

    except Error as err:
        print(f"Error: {err}")
        return None


# מוחק משתמש ממסד הנתונים לפי כתובת דואר אלקטרוני
def DeleteUser(conn, email):
    try:
        cur = conn.cursor()
        # Vulnerable: Direct string formatting
        query = f"DELETE FROM comunication_ltd.users WHERE email = '{email}'"
        cur.execute(query)
        conn.commit()

        ok = cur.rowcount > 0
        cur.close()
        return ok

    except Error as err:
        print(f"Error: {err}")
        return False


# מוסיף משתמש חדש למסד הנתונים עם הפרטים שנשלחו
def AddUserToDB(conn, fname, lname, email, pwd, dob):
    try:
        cur = conn.cursor()
        # Vulnerable: Direct string formatting
        query = (
            f"INSERT INTO comunication_ltd.users "
            f"(first_name, last_name, email, password, date_of_birth) "
            f"VALUES ('{fname}', '{lname}', '{email}', '{pwd}', '{dob}')"
        )
        cur.execute(query)
        conn.commit()
        cur.close()
        return True

    except Error as err:
        print(f"Error: {err}")
        return False


# מחזיר את הסיסמה של משתמש לפי כתובת דואר אלקטרוני
def GetUserPassword(conn, email):
    try:
        cur = conn.cursor()
        # Vulnerable: Direct string formatting
        query = f"SELECT password FROM comunication_ltd.users WHERE email='{email}' LIMIT 1"
        cur.execute(query)
        row = cur.fetchone()
        cur.close()
        return row[0] if row else None

    except Error as err:
        print(f"Error: {err}")
        return None


# מעדכן סיסמה של משתמש במסד הנתונים לפי כתובת דואר אלקטרוני
def UpdateUserPassword(conn, email, new_password):
    try:
        cur = conn.cursor()
        # Vulnerable: Direct string formatting
        query = f"UPDATE comunication_ltd.users SET password='{new_password}' WHERE email='{email}'"
        cur.execute(query)
        conn.commit()
        ok = cur.rowcount > 0
        cur.close()
        return ok

    except Error as err:
        print(f"Error: {err}")
        return False


# שומר קוד איפוס סיסמה עם זמן תפוגה, לאחר מחיקת קוד קודם אם קיים
def SaveResetToken(conn, email, token_sha1, expires_at):
    try:
        cur = conn.cursor()
        # Vulnerable: Direct string formatting
        cur.execute(f"DELETE FROM password_resets WHERE email='{email}'")
        
        query = (
            f"INSERT INTO password_resets (email, token_sha1, expires_at) "
            f"VALUES ('{email}', '{token_sha1}', '{expires_at}')"
        )
        cur.execute(query)
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
        # Vulnerable: Direct string formatting
        query = f"SELECT * FROM password_resets WHERE email='{email}' ORDER BY created_at DESC LIMIT 1"
        cur.execute(query)
        row = cur.fetchone()
        cur.close()
        return row
    except Error as err:
        print(f"Error: {err}")
        return None


# מוחק קוד איפוס סיסמה של משתמש
def DeleteResetToken(conn, email):
    try:
        cur = conn.cursor()
        # Vulnerable: Direct string formatting
        cur.execute(f"DELETE FROM password_resets WHERE email='{email}'")
        conn.commit()
        cur.close()
        return True
    except Error as err:
        print(f"Error: {err}")
        return False


# מוסיף חבילת שירות חדשה למסד הנתונים
def AddPackage(conn, name, speed, price, description=None):
    try:
        cur = conn.cursor()
        # Vulnerable: Direct string formatting
        query = (
            f"INSERT INTO comunication_ltd.packages (name, speed, price, description) "
            f"VALUES ('{name}', '{speed}', '{price}', '{description}')"
        )
        cur.execute(query)
        conn.commit()
        cur.close()
        return True
    except Error as err:
        print(f"Error: {err}")
        return False


# מחזיר את כל חבילות השירות הקיימות
def GetPackages(conn):
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM comunication_ltd.packages ORDER BY name")
        rows = cur.fetchall()
        cur.close()
        return rows
    except Error as err:
        print(f"Error: {err}")
        return []


# הוספת לקוח חדש לטבלת customers
def AddCustomer(conn, first_name, last_name, email=None, phone=None):
    try:
        cur = conn.cursor()
        # Vulnerable: Direct string formatting
        query = (
            f"INSERT INTO comunication_ltd.customers (first_name, last_name, email, phone) "
            f"VALUES ('{first_name}', '{last_name}', '{email}', '{phone}')"
        )
        cur.execute(query)
        conn.commit()
        cur.close()
        return True
    except Error as err:
        print(f"Error: {err}")
        return False


# מחזיר לקוח לפי כתובת דואר אלקטרוני
def GetCustomerByEmail(conn, email):
    try:
        cur = conn.cursor(dictionary=True)
        # Vulnerable: Direct string formatting
        cur.execute(f"SELECT * FROM comunication_ltd.customers WHERE email='{email}'")
        row = cur.fetchone()
        cur.close()
        return row
    except Error as err:
        print(f"Error: {err}")
        return None


# מחזיר לקוח לפי מזהה
def GetCustomerById(conn, customer_id):
    try:
        cur = conn.cursor(dictionary=True)
        # Vulnerable: Direct string formatting
        cur.execute(f"SELECT * FROM comunication_ltd.customers WHERE id='{customer_id}'")
        row = cur.fetchone()
        cur.close()
        return row
    except Error as err:
        print(f"Error: {err}")
        return None


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


# עדכון מונה ניסיונות התחברות כושלים
def IncrementFailedLogin(conn, email):
    try:
        cur = conn.cursor()
        # Vulnerable: Direct string formatting
        query = (
            f"UPDATE comunication_ltd.users "
            f"SET failed_login_count = failed_login_count + 1, last_login_attempt = NOW() "
            f"WHERE email = '{email}'"
        )
        cur.execute(query)
        conn.commit()
        cur.close()
        return True
    except Error as err:
        print(f"Error: {err}")
        return False


# מאפס מונה ניסיונות התחברות כושלים של משתמש
def ResetFailedLogin(conn, email):
    try:
        cur = conn.cursor()
        # Vulnerable: Direct string formatting
        query = (
            f"UPDATE comunication_ltd.users "
            f"SET failed_login_count = 0, last_login_attempt = NULL "
            f"WHERE email = '{email}'"
        )
        cur.execute(query)
        conn.commit()
        cur.close()
        return True
    except Error as err:
        print(f"Error: {err}")
        return False