#!/usr/bin/env python3

import os
import argparse

from storage import Storage

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class PasswordManager:
    def __init__(self, master_key, filepath):
        self.master_key = master_key
        self.storage = Storage(master_key, filepath)
        self._initiate_key()

    def _initiate_key(self):
        if self.storage.find("master_password"):
            return

        password_bytes = self.master_key.encode("utf-8")

        hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hasher.update(password_bytes)

        master_dict = {
            "key_name": "master_password",
            "comment": "this is the master password",
            "password": hasher.finalize().hex(),
        }

        self.storage.save(master_dict)

    @staticmethod
    def _derive_key(master_key, length):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            iterations=100000,
            salt=os.urandom(16),
            length=32,
            backend=default_backend()
        )

        hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hasher.update(kdf.derive(master_key.encode()))

        return hasher.finalize().hex()[:length]

    def new_pass(self, key_name, comment, length):
        if key_name == "master_password":
            return

        password_dict = {
            "key_name": key_name,
            "comment": comment,
            "password": self._derive_key(self.master_key, length)
        }

        self.storage.save(password_dict)
        print("successfully stored new password")

    def show_pass(self):
        dicts = self.storage.show_all()
        for password_dict in dicts:
            print(password_dict)

    def select(self, key_name):
        if key_name == "master_password":
            return

        password_dict = self.storage.find(key_name)
        print(password_dict)

    def delete(self, key_name):
        if key_name == "master_password":
            return

        self.storage.delete(key_name)
        print("successfully deleted password")

    def update(self, key_name, length):
        if key_name == "master_password":
            return

        self.storage.update(key_name, self._derive_key(self.master_key, length))
        print("successfully updated password")

    def gen_10k(self, seed):
        passwords = [self._derive_key(seed, index) for index in range(10000)]
        with open("test.txt", "w") as file:
            for password in passwords:
                file.write(f"{password}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Password Manager CLI")

    parser.add_argument('--init', action='store_true', help="Initialize a keystore")
    parser.add_argument('--newpass', type=str, help="Add a new password")
    parser.add_argument('-c', type=str, help="Comment for the key")
    parser.add_argument('-l', type=int, help="Length of the key")
    parser.add_argument('--showpass', action='store_true', help="Show all passwords")
    parser.add_argument('--select', type=str, help="Select a password")
    parser.add_argument('--update', type=str, help="Update a password")
    parser.add_argument('--delete', type=str, help="Delete a password")
    parser.add_argument('--gen-10k', type=str, help="Generate 10k passwords and store in file")

    args = parser.parse_args()

    if args.init:
        with open("keystore.txt", "w"):
            pass

        master_password = input("Enter master password: ")
        password_manager = PasswordManager(master_password, "keystore.txt")
        exit(0)

    try:
        master_password = input("Enter master password: ")
        password_manager = PasswordManager(master_password, "keystore.txt")

    except:
        print("wrong master_key or key_store file")
        exit(0)

    if args.newpass and args.c:
        length = args.l if args.l else 16
        password_manager.new_pass(args.newpass, args.c, length)

    elif args.showpass:
        password_manager.show_pass()

    elif args.select:
        password_manager.select(args.select)

    elif args.update:
        length = args.l if args.l else 16
        password_manager.update(args.update, length)

    elif args.delete:
        password_manager.delete(args.delete)

    elif args.gen_10k:
        password_manager.gen_10k(args.gen_10k)

    else:
        print("No valid command provided. Use --help for usage information.")
