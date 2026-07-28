from sqlalchemy import (
    create_engine,
    Column,
    String,
    Boolean,
    DateTime,
    ForeignKey,
    JSON,
    text
)
from sqlalchemy.orm import sessionmaker, DeclarativeBase, relationship
from sqlalchemy.dialects.postgresql import UUID
import uuid
import os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# --- Database Connection ---
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@localhost:5433/User")
if SQLALCHEMY_DATABASE_URL and SQLALCHEMY_DATABASE_URL.startswith("postgres://"):
    SQLALCHEMY_DATABASE_URL = SQLALCHEMY_DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(
    SQLALCHEMY_DATABASE_URL
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class Base(DeclarativeBase):
    pass

# --- Table Models ---

class UserTable(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=False)

    profile = relationship("ProfileTable", back_populates="user", uselist=False, cascade="all, delete-orphan")
    refresh_tokens = relationship("RefreshTokenTable", back_populates="user", cascade="all, delete-orphan")


class ProfileTable(Base):
    __tablename__ = "profiles"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    bio = Column(String, nullable=True)
    theme = Column(String, default="dark", nullable=True)
    accent_color = Column(String, default="#0ea5e9", nullable=True)
    navigation_preferences = Column(JSON, nullable=True)

    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    user = relationship("UserTable", back_populates="profile")


class RefreshTokenTable(Base):
    __tablename__ = "refresh_tokens"

    # token_id is a UUID Primary Key for O(1) indexed fast lookup
    token_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    session_id = Column(UUID(as_uuid=True), index=True, nullable=False, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    token_hash = Column(String, nullable=False) # Argon2id hash ($argon2id$)
    family = Column(String, index=True, nullable=False)
    device_name = Column(String, nullable=True, default="Unknown Device")
    ip_address = Column(String, nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    last_used = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)

    user = relationship("UserTable", back_populates="refresh_tokens")


def create_db_and_tables():
    Base.metadata.create_all(bind=engine)
    try:
        with engine.connect() as conn:
            conn.execute(text("ALTER TABLE profiles ADD COLUMN IF NOT EXISTS theme VARCHAR DEFAULT 'dark'"))
            conn.execute(text("ALTER TABLE profiles ADD COLUMN IF NOT EXISTS accent_color VARCHAR DEFAULT '#0ea5e9'"))
            conn.execute(text("ALTER TABLE profiles ADD COLUMN IF NOT EXISTS navigation_preferences JSON"))
            conn.commit()
    except Exception:
        pass