# database.py
import sqlite3
import hashlib
import os

    
class Database:
    def __init__(self, db_file="user_data.db"):
        """Inicializa a conexão com o banco de dados e cria a tabela de usuários se não existir."""
        self.db_file = db_file
        try:
            self.conn = sqlite3.connect(self.db_file, check_same_thread=False)
            self.cursor = self.conn.cursor()
            self.create_user_table()
        except sqlite3.Error as e:
            print(f"Erro ao conectar ao banco de dados: {e}")
            self.conn = None

    def create_user_table(self):
        """Cria a tabela 'users' se ela não existir."""
        if not self.conn: return
        try:
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL
                );
            """)
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"Erro ao criar a tabela: {e}")

    def _hash_password(self, password, salt):
        """Gera o hash de uma senha usando um salt."""
        # Usamos PBKDF2HMAC para maior segurança. É o recomendado para senhas.
        password_bytes = password.encode('utf-8')
        hashed_password = hashlib.pbkdf2_hmac('sha256', password_bytes, salt, 100000)
        return hashed_password.hex()

    def add_user(self, username, password):
        """Adiciona um novo usuário ao banco de dados com senha hasheada e salt."""
        if not self.conn: return False, "Sem conexão com o banco de dados."
        
        # Verifica se o usuário já existe
        self.cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
        if self.cursor.fetchone():
            return False, "Nome de usuário já existe."

        # Cria um salt aleatório e seguro
        salt = os.urandom(16)
        
        # Gera o hash da senha
        password_hash = self._hash_password(password, salt)

        try:
            self.cursor.execute(
                "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                (username, password_hash, salt.hex())
            )
            self.conn.commit()
            return True, "Usuário registrado com sucesso!"
        except sqlite3.Error as e:
            return False, f"Erro ao adicionar usuário: {e}"

    def check_user(self, username, password):
        """Verifica se o nome de usuário e a senha correspondem aos registros."""
        if not self.conn: return False
        
        self.cursor.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
        result = self.cursor.fetchone()

        if result:
            stored_hash, salt_hex = result
            salt = bytes.fromhex(salt_hex)
            
            # Gera o hash da senha fornecida com o salt armazenado
            input_hash = self._hash_password(password, salt)
            
            # Compara os hashes
            return input_hash == stored_hash
        
        return False

    def close(self):
        """Fecha a conexão com o banco de dados."""
        if self.conn:
            self.conn.close()
            