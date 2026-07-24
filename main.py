from fastapi import FastAPI
from infrastructure.database import create_db_and_tables
from api import user_routes
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="User Service with Hexagonal Architecture",
    description="A professional and structured example using FastAPI.",
    version="1.0.0",
)

import os

# Enable CORS
allowed_origins_env = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173,http://localhost:5174,http://localhost:3000")
origins = [origin.strip() for origin in allowed_origins_env.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins if origins else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def on_startup():
    create_db_and_tables()

app.include_router(user_routes.router)