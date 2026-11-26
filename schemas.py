from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    username: str
    quote: str


class UserBase(BaseModel):
    username: str = Field(min_length=1, max_length=50)
    email: EmailStr = Field(max_length=120)
    quote: str = Field(min_length=1, max_length=200)


class UserCreate(UserBase):
    password: str = Field(min_length=8)


class UserPrivate(UserPublic):
    id: int
    email: EmailStr


class UserDB(UserBase):
    hashed_password: str
    id: int
    email: EmailStr


class Token(BaseModel):
    access_token: str
    token_type: str
