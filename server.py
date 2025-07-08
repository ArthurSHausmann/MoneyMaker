from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from database import Database

app = FastAPI()
db = Database("user_data.db")  # Já é o seu banco atual

class LoginData(BaseModel):
    username: str
    password: str

@app.post("/login")
def login(data: LoginData):
    if db.check_user(data.username, data.password):
        return {"status": "success"}
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.on_event("shutdown")
def shutdown_event():
    db.close()

