from fastapi import APIRouter, Depends, HTTPException, status, Response
from pydantic import BaseModel, EmailStr
from typing import Optional, List
import uuid

from application.services import UserService
from dependencies import get_user_service

# --- API Schemas ---
class UserCreateRequest(BaseModel):
    email: EmailStr
    password: str
    first_name: str
    last_name: str
    bio: Optional[str] = None

class UserUpdateRequest(BaseModel):
    # For updates, all fields are optional.
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    bio: Optional[str] = None

class ProfileResponse(BaseModel):
    bio: Optional[str] = None
    
    # This Config class was missing. It tells this nested model
    # that it can also be created from database object attributes.
    class Config:
        from_attributes = True

class UserResponse(BaseModel):
    id: uuid.UUID
    email: EmailStr
    first_name: str
    last_name: str
    profile: ProfileResponse
    
    class Config:
        from_attributes = True

# --- API Router ---
router = APIRouter(prefix="/users", tags=["Users"])

# --- CREATE ---
@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user_endpoint(request: UserCreateRequest, service: UserService = Depends(get_user_service)):
    try:
        return service.create_user(
            email=request.email, password=request.password,
            first_name=request.first_name, last_name=request.last_name, bio=request.bio
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

# --- READ (ALL) ---
@router.get("/", response_model=List[UserResponse])
def get_all_users_endpoint(service: UserService = Depends(get_user_service)):
    return service.get_all_users()

# --- READ (ONE) ---
@router.get("/{user_id}", response_model=UserResponse)
def get_user_by_id_endpoint(user_id: uuid.UUID, service: UserService = Depends(get_user_service)):
    user = service.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user

# --- UPDATE ---
@router.put("/{user_id}", response_model=UserResponse)
def update_user_endpoint(user_id: uuid.UUID, request: UserUpdateRequest, service: UserService = Depends(get_user_service)):
    updated_user = service.update_user(
        user_id=user_id,
        first_name=request.first_name,
        last_name=request.last_name,
        bio=request.bio
    )
    if not updated_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return updated_user

# --- DELETE ---
@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user_endpoint(user_id: uuid.UUID, service: UserService = Depends(get_user_service)):
    success = service.delete_user(user_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    # Return a response with no body for 204 status code
    return Response(status_code=status.HTTP_204_NO_CONTENT)
