from sqlalchemy import (
    create_engine,
    Column,
    String,
    Boolean,
    Integer,
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
def format_supabase_url(url: str) -> str:
    if not url:
        return url
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    if "db.ckfgoifiwvvsbccgjnmn.supabase.co" in url:
        url = url.replace("postgres:", "postgres.ckfgoifiwvvsbccgjnmn:", 1)
        url = url.replace("db.ckfgoifiwvvsbccgjnmn.supabase.co:5432", "aws-0-ap-southeast-1.pooler.supabase.com:6543", 1)
        url = url.replace("db.ckfgoifiwvvsbccgjnmn.supabase.co", "aws-0-ap-southeast-1.pooler.supabase.com:6543", 1)
    if "supabase" in url and "sslmode" not in url:
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}sslmode=require"
    return url

SQLALCHEMY_DATABASE_URL = format_supabase_url(os.getenv("DATABASE_URL", "postgresql://postgres:postgres@localhost:5433/User"))

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    pool_pre_ping=True
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
    avatar_url = Column(String, nullable=True)
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


class UserTrustedDeviceTable(Base):
    __tablename__ = "user_trusted_devices"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    device_fingerprint = Column(String, nullable=False, index=True)
    device_name = Column(String, nullable=True, default="Unknown Device")
    verified_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)

    user = relationship("UserTable")


class DeviceOTPTable(Base):
    __tablename__ = "device_otps"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    device_fingerprint = Column(String, nullable=False, index=True)
    otp_code = Column(String, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    attempts = Column(Integer, default=0, nullable=False)
    verified = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)

    user = relationship("UserTable")


class PendingRegistrationOTPTable(Base):
    __tablename__ = "pending_registration_otps"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=False)
    bio = Column(String, nullable=True)
    otp_code = Column(String, nullable=False)
    device_fingerprint = Column(String, nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    attempts = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)


def create_db_and_tables():
    Base.metadata.create_all(bind=engine)
    try:
        with engine.connect() as conn:
            conn.execute(text("ALTER TABLE profiles ADD COLUMN IF NOT EXISTS theme VARCHAR DEFAULT 'dark'"))
            conn.execute(text("ALTER TABLE profiles ADD COLUMN IF NOT EXISTS accent_color VARCHAR DEFAULT '#0ea5e9'"))
            conn.execute(text("ALTER TABLE profiles ADD COLUMN IF NOT EXISTS avatar_url TEXT"))
            conn.execute(text("ALTER TABLE profiles ADD COLUMN IF NOT EXISTS navigation_preferences JSON"))
            conn.commit()
    except Exception:
        pass