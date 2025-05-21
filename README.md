# FastAPI JWT Authentication

A secure authentication system built with FastAPI, featuring JWT tokens, refresh tokens, and token blacklisting.

## Features

- User registration and login
- JWT-based authentication with access and refresh tokens
- Secure password hashing with bcrypt
- Refresh token rotation
- Token blacklisting for logout
- Email validation
- Protected routes
- SQLite database with SQLModel ORM

## Prerequisites

- Python 3.7+
- pip (Python package installer)

## Installation

1. Clone the repository:

```bash
git clone <repository-url>
cd fastapi-jwt-auth
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Create a `.env` file in the root directory with the following variables:

```env
SECRET_KEY=your-secret-key
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7
```

## Usage

1. Start the server:

```bash
fastapi dev main.py
```

2. Access the API documentation at `http://localhost:8000/docs`

## API Endpoints

- `POST /register` - Register a new user
- `POST /login` - Login and get access token
- `GET /current_user` - Get current user details
- `GET /users` - Get all users (protected)
- `POST /refresh` - Refresh access token
- `POST /logout` - Logout and invalidate tokens

## Security Features

- HTTP-only cookies for refresh tokens
- Secure password hashing
- Token blacklisting
- Email validation
- Access token expiration
- Refresh token rotation

## Database

The project uses SQLite with SQLModel ORM. The database file (`database.db`) will be created automatically when you first run the application.

## Testing

Run tests using pytest:

```bash
pytest test.py
```
