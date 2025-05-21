from fastapi import FastAPI, HTTPException, Depends, Cookie, Response
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from sqlmodel import Session, select, SQLModel
from typing import List, Optional
from contextlib import asynccontextmanager

from database import engine, init_db
from models import User, UserCreate, UserRead
from auth import (get_password_hash, 
                  verify_password, 
                  verify_email,
                  create_access_token, 
                  create_refresh_token,
                  decode_access_token, 
                  decode_refresh_token,
                  is_refresh_token_expired,
                  blacklist_token,
                  validate_access_token)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/login')

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
    
    if not verify_email(user.email):
        raise HTTPException(status_code=400, detail='email is invalid')
    
    db_user = User(name=user.name, email=user.email, hashed_password=get_password_hash(user.password))
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return {'id': db_user.id, 'email': db_user.email}


# login user
@app.post('/login')
def login(
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: Session = Depends(get_session)
):
    user = session.exec(select(User).where(User.email == form_data.username)).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail='Invalid Credentials')
    
    access_token = create_access_token(data={'sub': str(user.id)})
    refresh_token = create_refresh_token(data={'sub': str(user.id)})
    
    # Set refresh token in HTTP-only cookie
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=60 * 60 * 24 * 7  # 7 days
    )
    
    return {
        'access_token': access_token,
        'refresh_token': refresh_token,
        'token_type': 'bearer'
    }


# get current user
def get_current_user(token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)):
    validate_access_token(token, session)
    payload = decode_access_token(token)
    user_id = int(payload.get('sub'))
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail='User not found')
    return user


# protected route
@app.get('/current_user', response_model=UserRead)
def read_current_user(current_user: User = Depends(get_current_user)):
    return current_user


# get all users
@app.get('/users', response_model=List[UserRead])
def list_users(token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)):
    validate_access_token(token, session)
    return session.exec(select(User)).all()


@app.post('/refresh')
def refresh_token(
    response: Response,
    token: str = Depends(oauth2_scheme),
    refresh_token: Optional[str] = Cookie(None),
    session: Session = Depends(get_session)
):
    validate_access_token(token, session)
    if not refresh_token:
        raise HTTPException(status_code=401, detail='Refresh token not found')
    
    payload = decode_refresh_token(refresh_token)
    if payload is None:
        raise HTTPException(status_code=401, detail='Invalid refresh token')

    if is_refresh_token_expired(refresh_token):
        raise HTTPException(status_code=401, detail='Refresh token expired')
    
    user_id = int(payload.get('sub'))
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail='User not found')
    
    # Create new tokens
    new_access_token = create_access_token(data={'sub': str(user.id)})
    new_refresh_token = create_refresh_token(data={'sub': str(user.id)})
    
    # Set new refresh token in HTTP-only cookie
    response.set_cookie(
        key="refresh_token",
        value=new_refresh_token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=60 * 60 * 24 * 7  # 7 days
    )
    
    return {
        'new_access_token': new_access_token,
        'token_type': 'bearer'
    }


@app.post('/logout')
def logout(
    response: Response, 
    access_token: str = Depends(oauth2_scheme),
    session: Session = Depends(get_session)
):
    # Blacklist the access token
    if not blacklist_token(access_token, session):
        raise HTTPException(status_code=400, detail='Failed to invalidate token')
    
    # Delete the refresh token cookie
    response.delete_cookie(
        key="refresh_token",
        httponly=True,
        secure=True,
        samesite="strict"
    )
    return {"message": "Successfully logged out"}