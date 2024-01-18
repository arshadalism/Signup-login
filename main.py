import uvicorn
from fastapi import FastAPI, HTTPException
import Schema
import db
from passlib.context import CryptContext
from jose import JWTError, jwt
import secrets

from Oauth2_JWT import pwd_context

secret_key = secrets.token_hex(32)


app = FastAPI()


@app.post("/signup")
async def signup(user: Schema.User):
    if await db.signup_and_login_collection.find_one({"username": user.username}):
        raise HTTPException(status_code=400, detail="User is already registered")
    user_data = {
        "username": user.username,
        "password": pwd_context.hash(user.password)
    }
    await db.signup_and_login_collection.insert_one(user_data)
    return {"User registered successfully"}


@app.post("/login")
async def login(user: Schema.User):
    stored_user = await db.signup_and_login_collection.find_one({"username": user.username})
    if not stored_user or not pwd_context.verify(user.password, stored_user["password"]):
        raise HTTPException(status_code=404, detail="Username or password is incorrect")

    username = {
        "username": stored_user["username"]
    }

    encode = jwt.encode(username, secret_key)

    return {"message": "Login successfully", "token": encode}


@app.get("/get_username")
async def get_username(token: str):
    username = jwt.decode(token, secret_key)
    return username


if __name__ == '__main__':
    uvicorn.run("main:app")

