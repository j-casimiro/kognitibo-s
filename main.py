from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from sqlmodel import Session, select, SQLModel
from typing import List
from contextlib import asynccontextmanager

from database import engine, init_db
from models import User, UserCreate, UserRead
from auth import get_password_hash, verify_password, create_access_token, decode_access_token

oauth2 = OAuth2PasswordBearer(tokenUrl='/login')

# startup DB
@asynccontextmanager
async def lifespan(app: SQLModel):
    print('Startup')
    init_db()
    yield
    print('Shutdown')
    pass

# start fastapi app
app = FastAPI(lifespan=lifespan)

# start session
def get_session():
    with Session(engine) as session:
        yield session

# register user
@app.post('/register', response_model=UserRead)
def register(user: UserCreate, session: Session = Depends(get_session)):
    user_exists = session.exec(select(User).where(User.email == user.email)).first()
    if user_exists:
        raise HTTPException(status_code=400, detail='email already exist')
    db_user = User(name=user.name, email=user.email, hashed_password=get_password_hash(user.password))
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user


# login user
@app.post('/login')
def login(form_data: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.email == form_data.email)).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail='Invalid Credentials')
    token = create_access_token(data={'sub': str(user.id)})
    return {'access_token': token, 'token_type': 'bearer'}


# get current user
def get_current_user(token: str = Depends(oauth2), session: Session = Depends(get_session)):
    payload = decode_access_token(token)
    if payload is None:
        raise HTTPException(status_code=401, detail='Invalid Token')
    user_id = int(payload.get('sub'))
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail='User Not Found')
    return user


# protected route
@app.get('/current_user', response_model=UserRead)
def read_current_user(current_user: User = Depends(get_current_user)):
    return current_user


# get all users
@app.get('/users', response_model=List[UserRead])
def list_users(session: Session = Depends(get_session)):
    return session.exec(select(User)).all()