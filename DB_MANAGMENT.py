import mysql.connector
from dotenv import load_dotenv
from datetime import datetime
import os

load_dotenv()
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD")
MYSQL_USER_ADMIN = os.getenv("MYSQL_USER_ADMIN")
MYSQL_DB_NAME = os.getenv("MYSQL_DB_NAME")




def Establish_DB_Connection():
    try:
        MYSQL_CONNECTION = mysql.connector.connect(
            host="localhost",
            user= MYSQL_USER_ADMIN,
            password=MYSQL_PASSWORD,
            database=MYSQL_DB_NAME
        )

        if MYSQL_CONNECTION.is_connected():
           print("Connected to the database")
           return MYSQL_CONNECTION
        else:
            print("Failed to connect to the database")

    except mysql.connector.Error as err:
             print(f"Error: {err}")


def CloseDBConnection(MYSQL_CONNECTION):
    
    try:
        if MYSQL_CONNECTION and MYSQL_CONNECTION.is_connected():
            MYSQL_CONNECTION.close()
            print("Database connection closed successfully")
            return True
        else:
            print("Connection was already closed or never established")
            return False
            
    except mysql.connector.Error as err:
        print(f"Error closing connection: {err}")
        return False

def printTopRows(MYSQL_CONNECTION):
     try:
          MY_Current_Sesion = MYSQL_CONNECTION.cursor()
          query = f"SELECT * FROM comunication_ltd.users"

          MY_Current_Sesion.execute(query)
          print(MY_Current_Sesion.fetchall())

     except mysql.connector.Error as err:
             print(f"Error: {err}")



def CheckIfUserExists(MYSQL_CONNECTION, email):
    try:
        MY_Current_Session = MYSQL_CONNECTION.cursor()
        query = "SELECT COUNT(*) FROM comunication_ltd.users WHERE email = %s"
        
        MY_Current_Session.execute(query, (email,))
        count = MY_Current_Session.fetchone()[0]
        MY_Current_Session.close()
        
        if count > 0:
            print(f"User with email {email} exists")
            return True
        else:
            print(f"User with email {email} does not exist")
            return False
            
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return False



def GetUserInfoByMail(MYSQL_CONNECTION, email):
    try:
        MY_Current_Session = MYSQL_CONNECTION.cursor(dictionary=True)
        query = "SELECT * FROM comunication_ltd.users WHERE email = %s"
        
        MY_Current_Session.execute(query, (email,))
        user = MY_Current_Session.fetchone()
        MY_Current_Session.close()
        
        if user:
            print(f"User found: {user['first_name']} {user['last_name']}")
            return user
        else:
            print(f"No user found with email: {email}")
            return None
            
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return None



def DeleteUser(MYSQL_CONNECTION, email):
    try:
        MY_Current_Session = MYSQL_CONNECTION.cursor()
        query = "DELETE FROM comunication_ltd.users WHERE email = %s"
        
        MY_Current_Session.execute(query, (email,))
        MYSQL_CONNECTION.commit()
        
        if MY_Current_Session.rowcount > 0:
            print(f"User with email {email} deleted successfully.")
            MY_Current_Session.close()
            return True
        else:
            print(f"No user found with email: {email}")
            MY_Current_Session.close()
            return False
            
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return False
    
    

def AddUserToDB(MYSQL_CONNECTION, fname, lname, email, pwd, dob):
    try:
         cursor = MYSQL_CONNECTION.cursor()
         query = "INSERT INTO comunication_ltd.users (first_name, last_name, email, password, date_of_birth) VALUES (%s, %s, %s, %s, %s)"

         cursor.execute(query, (fname, lname, email, pwd, dob))
         MYSQL_CONNECTION.commit()
         cursor.close()
         return True

    except mysql.connector.Error as err:
         print(f"Error: {err}")
         return False

     
def GetUserPassword(MYSQL_CONNECTION, email):
    try:
        cursor = MYSQL_CONNECTION.cursor()
        cursor.execute(
            "SELECT password FROM comunication_ltd.users WHERE email=%s LIMIT 1",
            (email,),
        )
        row = cursor.fetchone()
        cursor.close()
        return row[0] if row else None
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return None


def UpdateUserPassword(MYSQL_CONNECTION, email, new_password):
    try:
        cursor = MYSQL_CONNECTION.cursor()
        cursor.execute(
            "UPDATE comunication_ltd.users SET password=%s WHERE email=%s",
            (new_password, email),
        )
        MYSQL_CONNECTION.commit()
        ok = cursor.rowcount > 0
        cursor.close()
        return ok
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return False


def SaveResetToken(MYSQL_CONNECTION, email, token_sha1, expires_at):
    cursor = MYSQL_CONNECTION.cursor()
    cursor.execute("DELETE FROM password_resets WHERE email=%s", (email,))
    cursor.execute(
        "INSERT INTO password_resets (email, token_sha1, expires_at) VALUES (%s, %s, %s)",
        (email, token_sha1, expires_at)
    )
    MYSQL_CONNECTION.commit()
    cursor.close()
    return True

def GetResetTokenRow(MYSQL_CONNECTION, email):
    cursor = MYSQL_CONNECTION.cursor(dictionary=True)
    cursor.execute(
        "SELECT * FROM password_resets WHERE email=%s ORDER BY created_at DESC LIMIT 1",
        (email,)
    )
    row = cursor.fetchone()
    cursor.close()
    return row

def DeleteResetToken(MYSQL_CONNECTION, email):
    cursor = MYSQL_CONNECTION.cursor()
    cursor.execute("DELETE FROM password_resets WHERE email=%s", (email,))
    MYSQL_CONNECTION.commit()
    cursor.close()
    return True


def AddPackage(MYSQL_CONNECTION, name, speed, price, description=None):
    try:
        cursor = MYSQL_CONNECTION.cursor()
        query = (
            "INSERT INTO comunication_ltd.packages (name, speed, price, description) "
            "VALUES (%s, %s, %s, %s)"
        )
        cursor.execute(query, (name, speed, price, description))
        MYSQL_CONNECTION.commit()
        cursor.close()
        return True
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return False


def GetPackages(MYSQL_CONNECTION):
    try:
        cursor = MYSQL_CONNECTION.cursor(dictionary=True)
        cursor.execute("SELECT * FROM comunication_ltd.packages ORDER BY name")
        rows = cursor.fetchall()
        cursor.close()
        return rows
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return []


def AddCustomer(MYSQL_CONNECTION, first_name, last_name, email=None, phone=None):
    try:
        cursor = MYSQL_CONNECTION.cursor()
        query = (
            "INSERT INTO comunication_ltd.customers "
            "(first_name, last_name, email, phone) "
            "VALUES (%s, %s, %s, %s)"
        )
        cursor.execute(query, (first_name, last_name, email, phone))
        MYSQL_CONNECTION.commit()
        cursor.close()
        return True
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return False


def GetCustomerByEmail(MYSQL_CONNECTION, email):
    try:
        cursor = MYSQL_CONNECTION.cursor(dictionary=True)
        cursor.execute("SELECT * FROM comunication_ltd.customers WHERE email=%s", (email,))
        row = cursor.fetchone()
        cursor.close()
        return row
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return None


def GetCustomerById(MYSQL_CONNECTION, customer_id):
    try:
        cursor = MYSQL_CONNECTION.cursor(dictionary=True)
        cursor.execute("SELECT * FROM comunication_ltd.customers WHERE id=%s", (customer_id,))
        row = cursor.fetchone()
        cursor.close()
        return row
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return None


def ListCustomers(MYSQL_CONNECTION):
    try:
        cursor = MYSQL_CONNECTION.cursor(dictionary=True)
        cursor.execute("SELECT * FROM comunication_ltd.customers ORDER BY created_at DESC")
        rows = cursor.fetchall()
        cursor.close()
        return rows
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return []


def IncrementFailedLogin(MYSQL_CONNECTION, email):
    try:
        cursor = MYSQL_CONNECTION.cursor()
        query = (
            "UPDATE comunication_ltd.users "
            "SET failed_login_count = failed_login_count + 1, last_login_attempt = NOW() "
            "WHERE email = %s"
        )
        cursor.execute(query, (email,))
        MYSQL_CONNECTION.commit()
        cursor.close()
        return True
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return False


def ResetFailedLogin(MYSQL_CONNECTION, email):
    try:
        cursor = MYSQL_CONNECTION.cursor()
        query = (
            "UPDATE comunication_ltd.users "
            "SET failed_login_count = 0, last_login_attempt = NULL "
            "WHERE email = %s"
        )
        cursor.execute(query, (email,))
        MYSQL_CONNECTION.commit()
        cursor.close()
        return True
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return False
