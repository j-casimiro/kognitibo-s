from typing import Optional
from sqlmodel import SQLModel, Field


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    email: str
    hashed_password: str


class UserCreate(SQLModel):
    name: str
    email: str
    password: str


class UserRead(SQLModel):
    id: int
    email: str