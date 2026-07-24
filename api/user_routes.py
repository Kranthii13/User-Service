from fastapi import APIRouter, Depends, HTTPException, status, Response, Cookie
from pydantic import BaseModel, EmailStr
from typing import Optional, List
import uuid

from application.services import UserService
from dependencies import get_user_service
from infrastructure.auth import create_access_token, create_refresh_token, verify_token

# --- API Schemas ---
class UserCreateRequest(BaseModel):
    email: EmailStr
    password: str
    first_name: str
    last_name: str
    bio: Optional[str] = None

class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str

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

class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse

# --- API Router ---
router = APIRouter(tags=["Users"])

# --- AUTHENTICATION ---
@router.post("/login", response_model=LoginResponse, status_code=status.HTTP_200_OK)
def login_user_endpoint(request: UserLoginRequest, response: Response, service: UserService = Depends(get_user_service)):
    try:
        user = service.authenticate_user(email=request.email, password=request.password)
        access_token = create_access_token(data={"sub": str(user.id), "email": user.email})
        refresh_token = create_refresh_token(data={"sub": str(user.id), "email": user.email})
        
        # Set HTTP-only cookie
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            samesite="lax",
            max_age=7 * 24 * 60 * 60, # 7 days
            secure=False # Set to True in production with HTTPS
        )

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": user
        }
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))

# --- CREATE ---
@router.post("/", response_model=LoginResponse, status_code=status.HTTP_201_CREATED)
def create_user_endpoint(request: UserCreateRequest, response: Response, service: UserService = Depends(get_user_service)):
    try:
        user = service.create_user(
            email=request.email, password=request.password,
            first_name=request.first_name, last_name=request.last_name, bio=request.bio
        )
        access_token = create_access_token(data={"sub": str(user.id), "email": user.email})
        refresh_token = create_refresh_token(data={"sub": str(user.id), "email": user.email})
        
        # Set HTTP-only cookie
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            samesite="lax",
            max_age=7 * 24 * 60 * 60, # 7 days
            secure=False # Set to True in production with HTTPS
        )

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": user
        }
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Registration error: {str(e)}")

# --- REFRESH TOKEN ---
class RefreshResponse(BaseModel):
    access_token: str
    token_type: str

@router.post("/refresh", response_model=RefreshResponse, status_code=status.HTTP_200_OK)
def refresh_token_endpoint(refresh_token: str = Cookie(None)):
    if not refresh_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token missing")

    payload = verify_token(refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token")
    
    user_id = payload.get("sub")
    email = payload.get("email")
    if not user_id or not email:
         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    new_access_token = create_access_token(data={"sub": user_id, "email": email})
    return {
        "access_token": new_access_token,
        "token_type": "bearer"
    }

# --- LOGOUT ---
@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout_endpoint(response: Response):
    response.delete_cookie("refresh_token")
    return Response(status_code=status.HTTP_204_NO_CONTENT)

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
