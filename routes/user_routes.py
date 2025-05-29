from fastapi import APIRouter, HTTPException, Depends
from sqlmodel import Session, select
from typing import List
from fastapi.security import OAuth2PasswordBearer

from database import get_session
from models import User, UserCreate, UserRead, UserUpdate
from .auth_routes import get_current_user, get_password_hash
from auth import validate_access_token

router = APIRouter(prefix="/users", tags=["users"])

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/auth/login')

def get_admin_user(
    token: str = Depends(oauth2_scheme),
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user)
):
    # Validate the access token
    validate_access_token(token, session)
    
    if current_user.role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Not enough permissions. Admin role required."
        )
    return current_user

@router.get("/", response_model=List[UserRead])
def list_users(
    token: str = Depends(oauth2_scheme),
    session: Session = Depends(get_session),
    _: User = Depends(get_admin_user)
):
    """Get all users. Admin only."""
    validate_access_token(token, session)
    users = session.exec(select(User)).all()
    return users

@router.post("/", response_model=UserRead)
def create_user(
    user: UserCreate,
    token: str = Depends(oauth2_scheme),
    session: Session = Depends(get_session),
    _: User = Depends(get_admin_user)
):
    """Create a new user. Admin only."""
    validate_access_token(token, session)
    
    # Check if user with email already exists
    existing_user = session.exec(
        select(User).where(User.email == user.email)
    ).first()
    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="User with this email already exists"
        )
    
    # Create new user
    db_user = User(
        name=user.name,
        email=user.email,
        role=user.role,
        hashed_password=get_password_hash(user.password)
    )
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user

@router.get("/{user_id}", response_model=UserRead)
def get_user(
    user_id: int,
    token: str = Depends(oauth2_scheme),
    session: Session = Depends(get_session),
    _: User = Depends(get_admin_user)
):
    """Get a specific user by ID. Admin only."""
    validate_access_token(token, session)
    
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )
    return user

@router.patch("/{user_id}", response_model=UserRead)
def update_user(
    user_id: int,
    user_update: UserUpdate,
    token: str = Depends(oauth2_scheme),
    session: Session = Depends(get_session),
    _: User = Depends(get_admin_user)
):
    """Update a user. Admin only."""
    validate_access_token(token, session)
    
    db_user = session.get(User, user_id)
    if not db_user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )
    
    # Update user fields
    user_data = user_update.model_dump(exclude_unset=True)
    if "password" in user_data:
        user_data["hashed_password"] = get_password_hash(user_data.pop("password"))
    
    for key, value in user_data.items():
        setattr(db_user, key, value)
    
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user

@router.delete("/{user_id}")
def delete_user(
    user_id: int,
    token: str = Depends(oauth2_scheme),
    session: Session = Depends(get_session),
    _: User = Depends(get_admin_user)
):
    """Delete a user. Admin only."""
    validate_access_token(token, session)
    
    db_user = session.get(User, user_id)
    if not db_user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )
    
    session.delete(db_user)
    session.commit()
    return {"message": "User deleted successfully"} 