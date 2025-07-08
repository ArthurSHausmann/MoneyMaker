# database.py
import sqlite3
import hashlib
import os

class Database:
    def __init__(self, db_file="user_data.db"):
        self.db_file = db_file
        self.create_user_table()

    def create_user_table(self):
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        salt TEXT NOT NULL
                    );
                """)
                conn.commit()
        except sqlite3.Error as e:
            print(f"Erro ao criar a tabela: {e}")

    def _hash_password(self, password, salt):
        password_bytes = password.encode('utf-8')
        hashed_password = hashlib.pbkdf2_hmac('sha256', password_bytes, salt, 100000)
        return hashed_password.hex()

    def add_user(self, username, password):
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
                if cursor.fetchone():
                    return False, "Nome de usuário já existe."

                salt = os.urandom(16)
                password_hash = self._hash_password(password, salt)

                cursor.execute(
                    "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                    (username, password_hash, salt.hex())
                )
                conn.commit()
                return True, "Usuário registrado com sucesso!"
        except sqlite3.Error as e:
            return False, f"Erro ao adicionar usuário: {e}"

    def check_user(self, username, password):
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
                result = cursor.fetchone()

                if result:
                    stored_hash, salt_hex = result
                    salt = bytes.fromhex(salt_hex)
                    input_hash = self._hash_password(password, salt)
                    return input_hash == stored_hash
        except sqlite3.Error as e:
            print(f"Erro ao verificar usuário: {e}")
        return False
