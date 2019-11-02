import hashlib
import string
import codecs
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Util.number import bytes_to_long

class PWE():

    MIN_PASS_WORDS = 6
    PBKDF2_ITERATIONS = 100000
    PBKDF2_HASH = 'sha256'

    def __init__(self, cipher="aes", bits=256, iterations=200, charset=string.ascii_letters+string.digits, prefixed=b"hehsomehoworks", salt=b"_lotfua!", **kwargs):
        self._bits = bits
        self._cipher = cipher
        self._iterations = iterations
        self._charset = charset
        self._prefixed = prefixed
        self._salt = salt

        self.__dict__.update(**kwargs)

    def list_allowed_check_access(self, password):
        pass

    def _hash_to_prefixed(self, hashed, count, prefix, output_password_len):
        
        for x in range(count):
            m = hashlib.sha256()
            m.update(hashed + codecs.encode("{}{}".format(self._prefixed, x)))
            hashed = m.digest()
            self._add_bytes_stream(hashed, output_password_len)

        return hashed

    def _is_bytestream_sufficient(self, output_password_len):
        if len(self._bytes_msg) == output_password_len:
            return True
        
        return False

    def _add_bytes_stream(self, hashedmsg, output_password_len):
        if not hasattr(self, "_bytes_msg"):
            self._bytes_msg = b""
        if len(self._bytes_msg) < output_password_len:
            self._bytes_msg += hashedmsg[:min(output_password_len-len(self._bytes_msg), len(hashedmsg))]

    def _pwe_seed(self, passwords, output_password_len):
        """
        Arguments:
            passwords - list of passwords
            output length - encoded into allowed charset
        """
        if len(passwords) < self.MIN_PASS_WORDS:
            raise ValueError("This is not safe, declined")
        key = b""
        lowered_pwds = [pw.lower() for pw in passwords]
        sorted_passwords = sorted(lowered_pwds)
        hashedmsg = b""
        for pwd in sorted_passwords:
            m = hashlib.sha256()
            m.update(hashedmsg + codecs.encode(pwd))
            hashedmsg = m.digest()
            if len(key) < (self._bits//8):
                if len(key)+len(hashedmsg) < (self._bits//8):
                    key += hashedmsg
                elif len(key)+len(hashedmsg) > (self._bits//8):
                    key += hashedmsg[:(self._bits//8-(len(hashedmsg)))]
            else:
                self._add_bytes_stream(hashedmsg, output_password_len)

        hashedmsg = self._hash_to_prefixed(hashedmsg, self._iterations - len(sorted_passwords), self._prefixed, output_password_len)
        self._iv_seed = hashlib.pbkdf2_hmac(self.PBKDF2_HASH, hashedmsg, self._salt, self.PBKDF2_ITERATIONS)
        return self._iv_seed, key

    def _pwe(self, passwords, output_password_len):
        iv, key = self._pwe_seed(passwords, output_password_len)
        counter = Counter.new(256, initial_value = bytes_to_long(iv))
        cipher = AES.new(key, AES.MODE_CTR, counter = counter)
        encrypted = cipher.encrypt(self._bytes_msg)
        return encrypted

    def pwe(self, passwords, output_password_len):
        return self._pwe(passwords, output_password_len)