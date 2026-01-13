import mysql.connector
from mysql.connector import Error
from dotenv import load_dotenv
import os

load_dotenv()
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD")
MYSQL_USER_ADMIN = os.getenv("MYSQL_USER_ADMIN")
MYSQL_DB_NAME = os.getenv("MYSQL_DB_NAME")

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
        return conn
    except Error as err:
        print(f"Error: {err}")
        return None

def CloseDBConnection(conn):
    try:
        if conn:
            conn.close()
            return True
        return False
    except Exception as err:
        print(f"Error closing connection: {err}")
        return False

# --- Vulnerable Functions below ---

def CheckIfUserExists(conn, email):
    try:
        cur = conn.cursor()
        # Vulnerable
        query = f"SELECT COUNT(*) FROM users WHERE email = '{email}'"
        cur.execute(query)
        count = cur.fetchone()[0]
        cur.close()
        return count > 0
    except Error as err:
        print(f"Error: {err}")
        return False

# פונקציה שמאפשרת פריצה כי היא בודקת סיסמה בתוך השאילת# פונקציה חדשה שמאפשרת SQL Injection להתחברות
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
    

def GetUserPassword(conn, email):
    try:
        cur = conn.cursor()
        query = f"SELECT password FROM users WHERE email='{email}' LIMIT 1"
        cur.execute(query)
        row = cur.fetchone()
        cur.close()
        return row[0] if row else None
    except Error as err:
        print(f"Error: {err}")
        return None

def AddUserToDB(conn, fname, lname, email, pwd, dob):
    try:
        cur = conn.cursor()
        # Vulnerable
        query = f"INSERT INTO users (first_name, last_name, email, password, date_of_birth) VALUES ('{fname}', '{lname}', '{email}', '{pwd}', '{dob}')"
        cur.execute(query)
        conn.commit()
        cur.close()
        return True
    except Error as err:
        print(f"Error: {err}")
        return False

def AddCustomer(conn, first_name, last_name, email=None, phone=None):
    try:
        cur = conn.cursor()
        # Vulnerable - קריטי ל-XSS
        # משתמשים בגרש בודד (') כדי לעטוף ערכים
        query = f"INSERT INTO customers (first_name, last_name, email, phone) VALUES ('{first_name}', '{last_name}', '{email}', '{phone}')"
        cur.execute(query)
        conn.commit()
        cur.close()
        return True
    except Error as err:
        print(f"Error: {err}")
        return False

def ListCustomers(conn):
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM customers ORDER BY created_at DESC")
        rows = cur.fetchall()
        cur.close()
        return rows
    except Error as err:
        print(f"Error: {err}")
        return []

# פונקציות עזר נוספות (אם היו לך בשימוש) יכולות להישאר כפי שהן
def UpdateUserPassword(conn, email, new_password):
    try:
        cur = conn.cursor()
        query = f"UPDATE users SET password='{new_password}' WHERE email='{email}'"
        cur.execute(query)
        conn.commit()
        cur.close()
        return True
    except Error as err:
        return False

def SaveResetToken(conn, email, token_sha1, expires_at):
    try:
        cur = conn.cursor()
        cur.execute(f"DELETE FROM password_resets WHERE email='{email}'")
        query = f"INSERT INTO password_resets (email, token_sha1, expires_at) VALUES ('{email}', '{token_sha1}', '{expires_at}')"
        cur.execute(query)
        conn.commit()
        cur.close()
        return True
    except: return False

def GetResetTokenRow(conn, email):
    try:
        cur = conn.cursor(dictionary=True)
        query = f"SELECT * FROM password_resets WHERE email='{email}' ORDER BY created_at DESC LIMIT 1"
        cur.execute(query)
        row = cur.fetchone()
        cur.close()
        return row
    except: return None

def DeleteResetToken(conn, email):
    try:
        cur = conn.cursor()
        cur.execute(f"DELETE FROM password_resets WHERE email='{email}'")
        conn.commit()
        cur.close()
        return True
    except: return False