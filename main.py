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
allowed_origins_env = os.getenv("ALLOWED_ORIGINS", "https://life-flow-fe-cyan.vercel.app,http://localhost:5173,http://localhost:5174,http://localhost:3000,http://127.0.0.1:5173,http://192.168.0.10:5173")
origins = [origin.strip() for origin in allowed_origins_env.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)(:\d+)?",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def on_startup():
    create_db_and_tables()

@app.api_route("/health", methods=["GET", "HEAD"])
def health():
    return {"status": "healthy"}

# Mount router at root (for Gateway proxied requests: /login, /, /refresh, /logout)
app.include_router(user_routes.router)

# Also mount with /api/users prefix (for direct service requests: /api/users/login, /api/users/)
app.include_router(user_routes.router, prefix="/api/users")