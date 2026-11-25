import uvicorn
from fastapi import FastAPI

from database import Base, engine
from routers import users

Base.metadata.create_all(bind=engine)

app = FastAPI()
app.include_router(users.router, prefix='/api/users', tags=['users'])

if __name__ == '__main__':
    uvicorn.run(app, host='127.0.0.1', port=8000)
