from fastapi import FastAPI
from infrastructure.database import create_db_and_tables
from api import user_routes
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="User Service with Hexagonal Architecture",
    description="A professional and structured example using FastAPI.",
    version="1.0.0",
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:5174", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def on_startup():
    create_db_and_tables()

app.include_router(user_routes.router)