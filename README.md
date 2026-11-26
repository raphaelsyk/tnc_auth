# tnc-auth

Minimal FastAPI example for a Tech and Croissant session on authentication (password hashing, JWT login) and authorization (protected endpoints, ownership checks).

## Structure

- `main.py` – FastAPI app with an in-memory user store, JWT creation and validation: register, login (`/token`), `/me`, get and delete user
- `password_hashing.py` – password hashing and verification
- `schemas.py` – Pydantic schemas

## Setup

```bash
uv sync
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
