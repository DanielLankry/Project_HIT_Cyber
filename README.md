# Project_HIT_Cyber

#TODO

Visual:
[X] Change Background Colors
[] Same Button Size and style
[] Fields and buttens CSS style

Pages To Add:
[] Main Screen after login
[X] Signup page
[X] Forget password
[] System page - Customer managment
[x] Login

Security:
[] Integration With Database for user storage with HMAC + Salt
[] Forgot password Mail approvel
[X] password requirements in signup page
[X] config Page for password requirements
[X] User Check to avoid duplicates

[X] Password Config page requirements: 1. length = 10 2. Must have: Capital and small letters 3. special char 4. Dictionary Words to avoid 5. Limited attempts for login = 3

[]ליצור מסך “מערכת” (System) ולהוסיף ממנו טופס “הכנסת לקוח חדש” + להציג על המסך את שם הלקוח החדש שהוזן.

[] Add a post‑login Main Screen and redirect to it after successful login.
[] Add a System page with “Add Customer” form and show the new customer name.
[] Add consistent navigation links across all pages.
[] Protect Main/System/Change Password with session checks.
[] Complete “Forgot Password”: send SHA‑1 code by email and verify it.
[] Store passwords with HMAC + Salt (not plain text).
[] Enforce password policy from config + limit login attempts.
[] Prepare two versions: vulnerable and fixed (XSS/SQLi).
