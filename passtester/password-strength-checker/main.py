import re


PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 64

FILE_PATH = "common_passwords.txt"

def read_password_blacklist(file_path):
    blacklist = []
    with open("common_passwords.txt", "r") as file:
        for line in file:
            password = line.strip()
            blacklist.append(password)

    return blacklist

def check_password_strength(password):
    password_length = len(password)

    if password_length < PASSWORD_MIN_LENGTH:
        return f"[WEAK] password length should be at least {PASSWORD_MIN_LENGTH} characters."
 
    if password_length > PASSWORD_MAX_LENGTH:
        return f"[WEAK] password length exceeds the maximum limit of {PASSWORD_MAX_LENGTH} characters."

    blacklist = read_password_blacklist(FILE_PATH)
    if password.lower() in blacklist:
        return "[WEAK] password is easily guessable and part of the blacklist."

    if not re.search(r"\d", password):
        return "[WEAK] password should include at least one digit."

    if not re.search(r"[A-Z]", password):
        return "[WEAK] password should include at least one uppercase letter."

    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "[WEAK] password should include at least one special character."

    unique_chars_length = len(set(password))
    if unique_chars_length <= password_length / 2:
        return "[WEAK] password appears to have low entropy."

    return "[STRONG] password meets recommended security guidelines."


password = input("Enter your password: ")
result = check_password_strength(password)

print(result)
