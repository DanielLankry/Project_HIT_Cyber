import configparser
import os
import re

# קורא את קובץ הקונפיגורציה לפי נתיב נכון
def _load_config():
    config = configparser.ConfigParser()
    base_dir = os.path.dirname(os.path.abspath(__file__))
    config.read(os.path.join(base_dir, "password_config.ini"))
    return config

# מחזיר את מספר ניסיונות ההתחברות המקסימלי מהקונפיג
def get_max_login_attempts(default=3):
    config = _load_config()
    try:
        return int(config["PASSWORD"].get("MAX_LOGIN_ATTEMPTS", str(default)))
    except Exception:
        return default

# Validate password according to password_config.ini rules.
def validate_password_security(password):
    config = _load_config()
    settings = config["PASSWORD"]

    min_len = int(settings.get("MIN_LENGTH", 10))
    if len(password) < min_len:
        return f"Password must have at least {min_len} characters."

    # Lower & upper
    if settings.getboolean("REQUIRE_LOWER"):
        if not any(c.islower() for c in password) or not any(c.isupper() for c in password):
            return "Password must contain both lowercase and uppercase letters."

    # Digit
    if settings.getboolean("REQUIRE_DIGIT"):
        if not any(c.isdigit() for c in password):
            return "Password must contain at least one number."

    # Special char
    if settings.getboolean("REQUIRE_SPECIAL"):
        special_chars = {"@", "!"}
        if not any(c in special_chars for c in password):
            return "Password must contain at least one special character (@ or !)."

    # Blacklist dictionary
    # 1. בדיקת קיימות של הקובץ
    # 2. בניית נתיב מלא לקובץ
    # 3. בדיקה שיש קובץ בנתיב ותחילת בדיקה
    # 4. קריאת הקובץ והכנת רשימת סיסמאות אסורות מהקובץ
    # 5. בדיקת סיסמא שנשלחה מול רשימת סיסמאות מסעיף 4
    dict_file = settings.get("DICTIONARY_FILE") # קבלת נתיב הקובץ והשם שלו
    if dict_file:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        dict_path = os.path.join(base_dir, dict_file)

        if os.path.exists(dict_path): # קריאה של הקובץ לאחר בדיקה
            try:
                with open(dict_path, "r", encoding="utf-8") as f:
                    bad = {line.strip().lower() for line in f} # בניית רשימת סיסמאות אסורות
                if password.lower() in bad: # בדיקת הסיסמא שנשלחה לפונקציה
                    return "Password is too common."
            except Exception as e:
                print(f"Warning: could not read dictionary file: {e}")

    return None  # valid

#Validate that email follows a basic correct format.
def validate_email_format(email):
    if not email:
        return "Email is required."
    pattern = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$" # ביטוי רגולרי שמגדיר את מבנה של כתובת מייל חוקית
    if not re.match(pattern, email):
        return "Invalid email format (example: name@example.com)."
    return None

#Phone is optional. If provided: exactly 10 digits, digits only.
def validate_phone_number(phone):
    if not phone or not phone.strip():
        return None

    phone = phone.strip()

    if not phone.isdigit():
        return "Phone must contain digits only."
    if len(phone) != 10:
        return "Phone must be exactly 10 digits."
    return None
