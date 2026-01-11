import configparser
import os
import re

#Validate password according to password_config.ini rules.
def validate_password_security(password):
    config = configparser.ConfigParser()
    config.read("password_config.ini")

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
    dict_file = settings.get("DICTIONARY_FILE")
    if dict_file and os.path.exists(dict_file):
        try:
            with open(dict_file, "r", encoding="utf-8") as f:
                bad = {line.strip().lower() for line in f}
            if password.lower() in bad:
                return "Password is too common."
        except Exception as e:
            print(f"Warning: could not read dictionary file: {e}")

    return None  # valid

#Validate that email follows a basic correct format.
def validate_email_format(email):
    if not email:
        return "Email is required."
    pattern = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
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
