import base64
import argparse

from file_encryptor import FileEncryptor


parser = argparse.ArgumentParser(description="File Encryptor")

parser.add_argument("-keygen", action="store_true", help="Generate key for encryption")
parser.add_argument("-mode", help="mode: {encrypt, decrypt} file using key")
parser.add_argument("-key", help="Key used for encrypting or decrypting file")
parser.add_argument("-filepath", help="Path of the file that should be encrypted or decrypted")

args = parser.parse_args()

if args.keygen:
    key = FileEncryptor.generate_key()
    encoded_key = base64.b64encode(key).decode("utf-8")
    print(f"[SUCESS] Your key is: {encoded_key}")

elif args.mode:
    if not args.key:
        print("[ERROR] Key not specified")

    elif not args.filepath:
        print("[ERROR] Filepath not specified")

    else:
        encoded_key = args.key
        key = base64.b64decode(encoded_key)

        if args.mode == "encrypt":
            FileEncryptor.encrypt_file(args.filepath, f"{args.filepath}.enc", key)
            print("[SUCCESS] file successfully encrypted")

        elif args.mode == "decrypt":
            FileEncryptor.decrypt_file(args.filepath, f"{args.filepath}.dec", key)
            print("[SUCCESS] file successfully decrypted")

        else:
            print("[ERROR] Mode not specified")
