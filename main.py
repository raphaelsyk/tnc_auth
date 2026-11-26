import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

import jwt
import pwdlib
import uvicorn
from fastapi import Depends, FastAPI, status
from fastapi.exceptions import HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from schemas import Token, UserCreate, UserDB, UserPrivate, UserPublic

password_hasher = pwdlib.PasswordHash.recommended()

SECRET_KEY = '72163rtfugysdhk78t236qyafguwhjksu78q3t4wfgyaukdjshk'
ALGORITHM = 'HS256'
TOKEN_VALIDITY_MINUTES = 2

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl='token'
)  # this is specifying the endpoint to which the frontend needs to submit username and password to get the Bearer token


def hash_password(password: str) -> str:
    """Hash a plain-text password."""
    return password_hasher.hash(password)


def verify_password(password_to_verify: str, ground_truth_password_hash: str) -> bool:
    """Check a plain-text password against a stored hash."""
    return password_hasher.verify(password_to_verify, ground_truth_password_hash)


def authenticate_user(username: str, password: str) -> UserDB:
    """Return the user if username and password match, otherwise raise 401."""
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


def create_jwt(data: dict[str, Any]) -> str:
    """Create a signed JWT containing the given claims plus an expiration time."""
    expiration_time = datetime.now(UTC) + timedelta(minutes=TOKEN_VALIDITY_MINUTES)

    claims = {**data, 'exp': expiration_time}
    token = jwt.encode(claims, SECRET_KEY, algorithm=ALGORITHM)
    return token


def validate_jwt_and_get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> UserDB:
    """Decode the bearer token and return the user it belongs to."""
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
        username = payload.get('sub')
        if username is None or username not in user_db.keys():
            raise credentials_exception
        user = user_db[username]
        return user


user_db: dict[str, UserDB] = {
    'rapha': UserDB.model_validate(
        {
            'id': 1,
            'username': 'rapha',
            'hashed_password': hash_password('idalab'),
            'email': 'raphael@idalab.de',
            'quote': 'Gallia est omnis divisa in partes tres',
        }
    ),
}

app = FastAPI()


@app.post(
    '/user',
    response_model=UserPrivate,
    status_code=status.HTTP_201_CREATED,
)
def create_user(user: UserCreate) -> UserDB:
    """Register a new user."""
    if user.username in user_db.keys():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Username already exists',
        )
    else:
        new_user = UserDB(
            id=secrets.randbelow(1_000_000),
            hashed_password=hash_password(user.password),
            quote=user.quote,
            username=user.username,
            email=user.email,
        )
        user_db[user.username] = new_user
        return new_user


@app.get('/users/{username}', response_model=UserPublic)
def get_user(username: str) -> UserDB:
    """Show the public profile of a user."""
    if username in user_db.keys():
        user = user_db[username]
        return user
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='User not found')


@app.delete('/users/{username}', status_code=status.HTTP_204_NO_CONTENT)
def delete_user(current_user: Annotated[UserDB, Depends(validate_jwt_and_get_current_user)], username: str) -> None:
    """Delete a user. Users may delete themselves; the admin may delete anyone."""
    if (username != current_user.username) and not current_user.username == 'rapha':
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='No permission to delete this user')
    elif username not in user_db.keys():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='User not found')
    else:
        user_db.pop(username)


@app.get('/me', response_model=UserPrivate)
def get_current_user(
    user: Annotated[UserDB, Depends(validate_jwt_and_get_current_user)],
) -> UserDB:
    """Show the private profile of the logged-in user."""
    return user


@app.post('/token', response_model=Token)
def login_and_get_token(
    request_form: Annotated[OAuth2PasswordRequestForm, Depends(OAuth2PasswordRequestForm)],
) -> Token:
    """Exchange username and password for a bearer token."""
    # validate user
    user = authenticate_user(request_form.username, request_form.password)

    data = {'sub': user.username}
    jwt_token = create_jwt(data)

    token = Token(access_token=jwt_token, token_type='Bearer')  # noqa: S106
    return token


if __name__ == '__main__':
    uvicorn.run(app=app, host='127.0.0.1', port=8000)
