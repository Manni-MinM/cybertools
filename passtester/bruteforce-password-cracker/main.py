import argparse

from password_cracker import PasswordCracker


parser = argparse.ArgumentParser(description="Bruteforce password checker")

parser.add_argument("-mode", help="Select mode {std, kchar}")
parser.add_argument("-charset", help="Select charset {d: digit, a: ascii_lowercase, A:ascii_uppercase, p: punctuation}")
parser.add_argument("-password", help="The password that needs to be cracked")
parser.add_argument("-kchar_regex", help="Regex pattern to search againts for kchar mode")

args = parser.parse_args()

if not args.mode:
    print("[ERROR] Mode not specified in command.")
    exit(0)

if not args.charset:
    print("[ERROR] Charset not specified in command.")
    exit(0)

if not args.password:
    print("[ERROR] Password not specified in command.")
    exit(0)

if args.mode == "kchar" and not args.kchar_regex:
    print("[ERROR] Kchar_regex not specified in command.")
    exit(0)

pc = PasswordCracker(args.mode, args.charset)
result = pc.execute(args.password, kchar_regex=args.kchar_regex)

print(result)
