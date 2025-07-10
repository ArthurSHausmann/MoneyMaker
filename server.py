from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import sqlite3
import hashlib

app = FastAPI()

class Database:
    def __init__(self, db_file="user_data.db"):
        self.db_file = db_file
        
    def _hash_password(self, password, salt):
        password_bytes = password.encode('utf-8')
        hashed_password = hashlib.pbkdf2_hmac('sha256', password_bytes, salt, 100000)
        return hashed_password.hex()
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
    
db = Database("user_data.db")

class LoginData(BaseModel):
    username: str
    password: str

@app.post("/login")
def login(data: LoginData):
    if db.check_user(data.username, data.password):
        return {"status": "success"}
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.get("/ping")
def ping():
    return {"status": "ok"}