from Crypto.Cipher import Blowfish
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


class FileEncryptor:
    @staticmethod
    def generate_key():
        return get_random_bytes(16)

    @staticmethod
    def _encrypt_text(key, plaintext):
        cipher = Blowfish.new(key, Blowfish.MODE_ECB)
        ciphertext = cipher.encrypt(pad(plaintext.encode(), Blowfish.block_size))
        return ciphertext

    @staticmethod
    def _decrypt_text(key, ciphertext):
        cipher = Blowfish.new(key, Blowfish.MODE_ECB)
        plaintext = unpad(cipher.decrypt(ciphertext), Blowfish.block_size)
        return plaintext.decode()

    @staticmethod
    def encrypt_file(input_filename, output_filename, key):
        with open(input_filename, "r") as file:
            plaintext = file.read()

        ciphertext = FileEncryptor._encrypt_text(key, plaintext)

        with open(output_filename, "wb") as file:
            file.write(ciphertext)

    @staticmethod
    def decrypt_file(input_filename, output_filename, key):
        with open(input_filename, "rb") as file:
            ciphertext = file.read()

        plaintext = FileEncryptor._decrypt_text(key, ciphertext)

        with open(output_filename, "w") as file:
            file.write(plaintext)
