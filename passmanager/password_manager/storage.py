import os
import json

from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class Storage:
    def __init__(self, key, filepath):
        self.key = key.encode("utf-8").ljust(32, b"\x00")
        self.filepath = filepath

    def _encrypt(self, data):
        data_json = json.dumps(data)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data_json.encode()) + encryptor.finalize()
        encrypted_data = b64encode(iv + ciphertext).decode()

        return encrypted_data

    def _decrypt(self, encrypted_data):
        encrypted_data = b64decode(encrypted_data.encode())
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        decrypted_dict = json.loads(decrypted_data.decode())

        return decrypted_dict

    def show_all(self):
        dicts = []
        with open(self.filepath, "r") as file:
            for line in file.readlines():
                if line.strip() == "":
                    continue

                decrypted_dict = self._decrypt(line)
                if decrypted_dict["key_name"] != "master_password":
                    dicts.append(decrypted_dict)

        return dicts

    def save(self, password_dict):
        encrypted_dict = self._encrypt(password_dict)
        with open(self.filepath, "a") as file:
            file.write(f"{encrypted_dict}\n")

    def find(self, key_name):
        with open(self.filepath, "r") as file:
            for line in file.readlines():
                if line.strip() == "":
                    continue

                decrypted_dict = self._decrypt(line)
                if decrypted_dict["key_name"] == key_name:
                    return decrypted_dict

        return None

    def delete(self, key_name):
        newlines = []
        with open(self.filepath, "r") as file:
            for line in file.readlines():
                encrypted_dict = line.strip()
                if encrypted_dict == "":
                    continue

                decrypted_dict = self._decrypt(encrypted_dict)
                if decrypted_dict["key_name"] != key_name:
                    newlines.append(encrypted_dict)

        with open(self.filepath, "w") as file:
            for line in newlines:
                file.write(f"{line}\n")

    def update(self, key_name, new_password):
        decrypted_dict = self.find(key_name)
        self.delete(decrypted_dict["key_name"])

        decrypted_dict["password"] = new_password
        self.save(decrypted_dict)
