# tnc-auth

Minimal FastAPI example for a Tech and Croissant session on authentication (password hashing, JWT login) and authorization (protected endpoints, ownership checks).

## Structure

- `main.py` – FastAPI app, mounts the users router under `/api/users`
- `routers/users.py` – register, login (`/token`), `/me`, get and delete user
- `auth.py` – password hashing, JWT creation/verification, `CurrentUser` dependency
- `models.py` / `schemas.py` – SQLAlchemy model and Pydantic schemas
- `database.py` – SQLite engine and session
- `config.py` – settings loaded from `.env`

## Setup

```bash
uv sync
echo "SECRET_KEY=$(openssl rand -hex 32)" > .env
uv run fastapi dev main.py
```

Interactive API docs: http://127.0.0.1:8000/docs

## Dev tooling

```bash
uv run ruff check .
uv run ruff format .
uv run ty check
uv run pytest
```
