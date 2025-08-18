from fastapi import FastAPI
from infrastructure.database import create_db_and_tables
from api import user_routes

app = FastAPI(
    title="User Service with Hexagonal Architecture",
    description="A professional and structured example using FastAPI.",
    version="1.0.0",
)

@app.on_event("startup")
def on_startup():
    create_db_and_tables()

app.include_router(user_routes.router)

@app.get("/", tags=["Health Check"])
def read_root():
    return {"status": "ok"}