from datetime import datetime, timedelta
from typing import Optional
from jose import jwt, JWTError
import bcrypt
from dotenv import load_dotenv
import os
import re


load_dotenv()
ACCESS_TOKEN_EXPIRE_SECONDS = int(os.getenv('ACCESS_TOKEN_EXPIRE_SECONDS'))
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")

def verify_password(plain_password: str, hashed_password: str):
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))


def verify_email(email: str):
    return True if re.search(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email) else False


def get_password_hash(password: str):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    expire = datetime.now() + (expires_delta or timedelta(seconds=ACCESS_TOKEN_EXPIRE_SECONDS))
    data.update({'exp': expire})
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None
