import re
import string

from tqdm import tqdm
from itertools import product


class PasswordCracker:
    def __init__(self, exec_mode, charset_mode):
        self.exec_mode = exec_mode
        self.charset = self.find_charset(charset_mode)
        self.charset_mode = charset_mode

    @staticmethod
    def find_charset(charset_mode):
        charset = ""
        if 'd' in charset_mode:
            charset += string.digits
        if 'a' in charset_mode:
            charset += string.ascii_lowercase
        if 'A' in charset_mode:
            charset += string.ascii_uppercase
        if 'p' in charset_mode:
            charset += string.punctuation

        return charset

    @staticmethod
    def validate_kchar(password, kchar_regex):
        if len(password) != len(kchar_regex):
            return False

        return re.search(kchar_regex, password)

    @staticmethod
    def remove_kchar(password, kchar_regex):
        result = ""
        for p, r in zip(password, kchar_regex):
            if r == '.':
                result += p

        return result

    def generate_password(self, length):
        total_combinations = len(self.charset) ** length
        for combination in tqdm(product(self.charset, repeat=length), total=total_combinations):
            yield ''.join(combination)

    def execute(self, password, **kwargs):
        # validate charset
        if re.search(r'[^daAp]', self.charset_mode):
            return "[ERROR] Please enter a valid charset expression."

        if self.exec_mode == "std":
            pass

        elif self.exec_mode == "kchar":
            kchar_regex = kwargs["kchar_regex"]
            if not kchar_regex:
                return "[ERROR] Please enter kchar_regex string."

            if not self.validate_kchar(password, kchar_regex):
                return "[ERROR] The kchar_regex string doesn't match the entered password."

            password = self.remove_kchar(password, kchar_regex)

        else:
            return "[ERROR] Please choose one of two modes: 'std' or 'kchar'."

        attempts = 0
        password_length = len(password)
        for candidate in self.generate_password(password_length):
            attempts += 1
            if candidate == password:
                break

        return f"[SUCCESS] Password found after {attempts} attempts."
