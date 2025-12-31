import configparser
import os

def validate_password_security (password):

    # Load the password policy on each call to pick up config changes.
    config = configparser.ConfigParser()
    config.read('password_config.ini')

    settings = config['PASSWORD']

    # Enforce minimum length first to fail fast.
    min_len = int(settings.get('MIN_LENGTH', 8))
    if len(password) < min_len:
        return f"must have at least {min_len} char"

    #  lowercase requirement.
    if settings.getboolean('REQUIRE_LOWER'):
        if not any(char.islower() for char in password):
            return "Must have at least one lower case and one upper case"

    #  digit requirement.
    if settings.getboolean('REQUIRE_DIGIT'):
        if not any(char.isdigit() for char in password):
            return "Must have a number"

    #  special-character requirement using a small allowed set.
    if settings.getboolean('REQUIRE_SPECIAL'):
        special_chars = {'@','!'}
        if not any(char in special_chars for char in password):
            return "Must contain special char"

    #  dictionary blacklist check; skip if file missing.
    dict_file = settings.get('DICTIONARY_FILE')
    if dict_file and os.path.exists(dict_file):
        try:
            with open(dict_file, 'r', encoding='utf-8') as f:
                forbidden_passwords = {line.strip().lower() for line in f}

            if password.lower() in forbidden_passwords:
                return "password is no good"
        except Exception as e:
            print(f"Warning: Could not read dictionary file: {e}")

    return None
