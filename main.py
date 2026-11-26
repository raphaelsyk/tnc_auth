from datetime import UTC, datetime, timedelta
from typing import Annotated

import jwt
import pwdlib
import uvicorn
from fastapi import Depends, FastAPI, status
from fastapi.exceptions import HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel

from schemas import UserCreate, UserDB, UserPrivate, UserPublic

password_hasher = pwdlib.PasswordHash.recommended()

SECRET_KEY = '72163rtfugysdhk78t236qyafguwhjksu78q3t4wfgyaukdjshk'
ALGORITHM = 'HS256'
TOKEN_VALIDITY_MINUTES = 2

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl='token'
)  # this is specifying the endpoint to which the frontend needs to submit username and password to get the Bearer token


class Token(BaseModel):
    access_token: str
    token_type: str


def hash_password(password: str):
    return password_hasher.hash(password)


def verify_password(password_to_verify: str, ground_truth_password_hash: str):
    return password_hasher.verify(password_to_verify, ground_truth_password_hash)


def authenticate_user(username: str, password: str):
    credentials_incorrect_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Username or password incorrect.',
        headers={'WWW-Authenticate': 'Bearer'},
    )

    try:
        user = user_db[username]
    except KeyError:
        raise credentials_incorrect_exception
    if not verify_password(password, user.hashed_password):
        raise credentials_incorrect_exception
    return user


def create_jwt(data: dict):
    expiration_time = datetime.now(UTC) + timedelta(minutes=TOKEN_VALIDITY_MINUTES)

    data.update({'exp': expiration_time})
    token = jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)
    return token


def validate_jwt_and_get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> UserDB:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Could not validate credentials',
        headers={'WWW-Authenticate': 'Bearer'},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.InvalidTokenError:
        raise credentials_exception
    else:
        user = user_db[payload['sub']]
        return user


user_db = {
    'rapha': UserDB.model_validate(
        {
            'id': 1,
            'username': 'rapha',
            'hashed_password': hash_password('idalab'),
            'email': 'raphael@idalab.de',
            'quote': 'Gallia est omnis divisa in partes tres',
        }
    ),
    'max_id': 1,
}

app = FastAPI()


@app.post(
    '/user',
    response_model=UserPrivate,
    status_code=status.HTTP_201_CREATED,
)
def create_user(user: UserCreate):
    if user.username in user_db.keys():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Username already exists',
        )
    else:
        new_user = UserDB(
            id=user_db['max_id'] + 1,
            hashed_password=hash_password(user.password),
            quote=user.quote,
            username=user.username,
            email=user.email,
        )
        user_db[user.username] = new_user
        return new_user


@app.get('/users/{username}', response_model=UserPublic)
def get_user(username: str):
    "Show the public profile of a user."
    if username in user_db.keys():
        user = user_db[username]
        return user
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='User not found')


@app.delete('/users/{username}', status_code=status.HTTP_204_NO_CONTENT)
def delete_user(current_user: Annotated[UserDB, Depends(validate_jwt_and_get_current_user)], username: str):

    if (username != current_user.username) and not current_user.username == 'rapha':
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='No permission to delete this user')
    else:
        user_db.pop(username)


@app.get('/me', response_model=UserPrivate)
def get_current_user(
    user: Annotated[UserPrivate, Depends(validate_jwt_and_get_current_user)],
):
    return user


@app.post('/token')
def login_and_get_token(request_form: Annotated[OAuth2PasswordRequestForm, Depends(OAuth2PasswordRequestForm)]):

    # validate user
    user = authenticate_user(request_form.username, request_form.password)

    data = {'sub': user.username}
    jwt_token = create_jwt(data)

    token = {'access_token': jwt_token, 'token_type': 'Bearer'}
    return token


if __name__ == '__main__':
    uvicorn.run(app=app, host='127.0.0.1', port=8000)
