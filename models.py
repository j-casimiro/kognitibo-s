from typing import Optional, List
from sqlmodel import SQLModel, Field, Enum, Relationship
from datetime import datetime

# CLASS DEFINITIONS
class RoleEnum(str, Enum):
    STUDENT = "student"
    ADMIN = "admin"
    INSTRUCTOR = "instructor"


class QuestionType(str, SQLModel):
    MULTIPLE_CHOICE = 'multiple_choice'
    ANSWER_INPUT = 'answer_input'


class UserCreate(SQLModel):
    name: str
    email: str
    password: str


class UserRead(SQLModel):
    id: int
    email: str


# Base model with timestamps
class TimestampModel(SQLModel):
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)


# DATABASE TABLES
class User(TimestampModel, table=True):
    __tablename__ = 'users'
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    email: str = Field(unique=True, index=True)
    role: RoleEnum = Field(default=RoleEnum.STUDENT)
    hashed_password: str
    
    # Relationships
    quizzes: List["Quiz"] = Relationship(back_populates="created_by_user")
    user_answers: List["UserAnswer"] = Relationship(back_populates="user")


class Course(TimestampModel, table=True):
    __tablename__ = 'courses'
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    
    # Relationships
    quizzes: List["Quiz"] = Relationship(back_populates="course")


class Quiz(TimestampModel, table=True):
    __tablename__ = 'quizzes'
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    course_id: int = Field(foreign_key="courses.id")
    created_by: int = Field(foreign_key="users.id")
    is_active: bool = Field(default=True)
    
    # Relationships
    course: Course = Relationship(back_populates="quizzes")
    created_by_user: User = Relationship(back_populates="quizzes")
    questions: List["Question"] = Relationship(back_populates="quiz")


class Question(TimestampModel, table=True):
    __tablename__ = 'questions'
    id: Optional[int] = Field(default=None, primary_key=True)
    quiz_id: int = Field(foreign_key="quizzes.id")
    question_text: str
    question_type: QuestionType = Field(default=QuestionType.MULTIPLE_CHOICE)
    points: int = Field(default=0)
    
    # Relationships
    quiz: Quiz = Relationship(back_populates="questions")
    answers: List["Answer"] = Relationship(back_populates="question")
    user_answers: List["UserAnswer"] = Relationship(back_populates="question")


class Answer(TimestampModel, table=True):
    __tablename__ = 'answers'
    id: Optional[int] = Field(default=None, primary_key=True)
    question_id: int = Field(foreign_key="questions.id")
    answer: str
    is_correct: bool = Field(default=False)
    
    # Relationships
    question: Question = Relationship(back_populates="answers")
    user_answers: List["UserAnswer"] = Relationship(back_populates="answer")


class UserAnswer(TimestampModel, table=True):
    __tablename__ = 'user_answers'
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users.id")
    question_id: int = Field(foreign_key="questions.id")
    answer_id: Optional[int] = Field(default=None, foreign_key="answers.id")
    text_answer: Optional[str] = Field(default=None)
    
    # Relationships
    user: User = Relationship(back_populates="user_answers")
    question: Question = Relationship(back_populates="user_answers")
    answer: Optional[Answer] = Relationship(back_populates="user_answers")


class BlacklistedToken(TimestampModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    token_id: str = Field(index=True)  # JTI (JWT ID) from the token
    expires_at: datetime