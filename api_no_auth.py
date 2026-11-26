import secrets

import uvicorn
from fastapi import FastAPI, status
from fastapi.exceptions import HTTPException
from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    username: str
    quote: str


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=50)
    email: EmailStr = Field(max_length=120)
    quote: str = Field(min_length=1, max_length=200)


class UserPrivate(UserPublic):
    id: int
    email: EmailStr


class UserDB(UserCreate):
    id: int


user_db: dict[str, UserDB] = {
    'rapha': UserDB(
        id=1,
        username='rapha',
        email='raphael@idalab.de',
        quote='Gallia est omnis divisa in partes tres',
    ),
}

app = FastAPI()


@app.post(
    '/user',
    response_model=UserPrivate,
    status_code=status.HTTP_201_CREATED,
    tags=['user'],
)
def create_user(user: UserCreate) -> UserDB:
    """Register a new user."""
    if user.username in user_db.keys():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Username already exists',
        )
    new_user = UserDB(id=secrets.randbelow(1_000_000), **user.model_dump())
    user_db[user.username] = new_user
    return new_user


@app.get('/list_users', response_model=list[str], tags=['user'])
def get_users() -> list[str]:
    """List the usernames of all registered users."""
    return list(user_db.keys())


@app.get('/users/{username}', response_model=UserPublic, tags=['user'])
def get_user(username: str) -> UserDB:
    """Show the public profile of a user."""
    if username not in user_db.keys():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='User not found')
    return user_db[username]


@app.delete('/users/{username}', status_code=status.HTTP_204_NO_CONTENT, tags=['user'])
def delete_user(username: str) -> None:
    """Delete a user."""
    if username not in user_db.keys():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='User not found')
    user_db.pop(username)


@app.get('/me', response_model=UserPrivate)
def get_current_user(username: str) -> UserDB:
    """Show the private profile of the user who claims to be the given username."""
    if username not in user_db.keys():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='User not found')
    return user_db[username]


if __name__ == '__main__':
    uvicorn.run(app=app, host='127.0.0.1', port=8001)
