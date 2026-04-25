# --- Imports ---
# We import the tools we need from sqlalchemy.
# - create_engine: Establishes the connection to the database.
# - Column, String, ForeignKey: Used to define the structure of our table columns.
# - sessionmaker: A factory for creating database session objects.
# - DeclarativeBase: A base class that our table models will inherit from.
# - relationship: Defines how two tables are linked together.
from sqlalchemy import (
    create_engine,
    Column,
    String,
    ForeignKey
)
from sqlalchemy.orm import sessionmaker, DeclarativeBase, relationship
# This specific UUID type helps SQLAlchemy work efficiently with UUIDs in databases like PostgreSQL.
from sqlalchemy.dialects.postgresql import UUID
import uuid
import os
from dotenv import load_dotenv

load_dotenv()

# --- Database Connection ---
# This is the connection string. It tells SQLAlchemy where our database is.
# For this tutorial, we're using SQLite, which is a simple file-based database.
# The database will be created in a file named 'test.db' in the same directory.
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@localhost:5433/User")

# The 'engine' is the core entry point for SQLAlchemy to communicate with the database.
# 'connect_args' is a special setting needed only for SQLite to ensure it works correctly in a multi-threaded
# environment like a web application.
engine = create_engine(
    SQLALCHEMY_DATABASE_URL
)

# A 'Session' is like an ongoing conversation with the database.
# We create a 'SessionLocal' class here. Later, we will create instances of this class
# to handle each individual request to our application.
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# --- Base Class for Table Models ---
# We create a 'Base' class by inheriting from DeclarativeBase.
# Any class that represents a database table will inherit from this 'Base'.
# This is how SQLAlchemy's "Object-Relational Mapping" (ORM) works.
class Base(DeclarativeBase):
    pass


# --- SQLAlchemy Table Models ---
# IMPORTANT: These classes define the DATABASE tables. They are related to, but SEPARATE from,
# our Pydantic DOMAIN models. This separation is key to our architecture.

class UserTable(Base):
    __tablename__ = "users" # This must be the actual table name in the database.

    # Define the columns of the 'users' table.
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=False)

    # This defines the 'one-to-one' relationship between a User and their Profile.
    # - "ProfileTable": The other class in the relationship.
    # - back_populates="user": Links this to the 'user' attribute in ProfileTable.
    # - uselist=False: Specifies this is a one-to-one (one user has one profile).
    # - cascade="all, delete-orphan": Important! This means if a user is deleted, their associated profile is automatically deleted too.
    profile = relationship("ProfileTable", back_populates="user", uselist=False, cascade="all, delete-orphan")


class ProfileTable(Base):
    __tablename__ = "profiles"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    bio = Column(String, nullable=True) # nullable=True means this field can be empty.

    # This is the foreign key that links a profile back to a specific user.
    # It says that the 'user_id' column in this table must match an 'id' in the 'users' table.
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)

    # This is the other side of the relationship defined in UserTable.
    user = relationship("UserTable", back_populates="profile")


# --- Helper Function ---
def create_db_and_tables():
    # This function tells SQLAlchemy to look at all the classes that inherit from 'Base'
    # and create the corresponding tables in the database if they don't already exist.
    Base.metadata.create_all(bind=engine)