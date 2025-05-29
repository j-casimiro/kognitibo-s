from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from sqlmodel import SQLModel

from database import init_db
from routes import auth_router, user_router

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

origins = [
    "http://localhost:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth_router)
app.include_router(user_router)