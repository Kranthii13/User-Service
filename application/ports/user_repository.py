from abc import ABC, abstractmethod
from typing import Optional, List
import uuid

from domain.user import User

class UserRepository(ABC):
    """
    This is the updated Output Port. It defines the contract for all CRUD operations.
    """

    @abstractmethod
    def add(self, user: User) -> None:
        """Saves a user object to the storage."""
        raise NotImplementedError

    @abstractmethod
    def get_by_id(self, user_id: uuid.UUID) -> Optional[User]:
        """Retrieves a user by their unique ID."""
        raise NotImplementedError

    @abstractmethod
    def get_by_email(self, email: str) -> Optional[User]:
        """Retrieves a user by their email address."""
        raise NotImplementedError
    
    @abstractmethod
    def get_all(self) -> List[User]:
        """Retrieves all users from storage."""
        raise NotImplementedError

    @abstractmethod
    def update(self, user: User) -> None:
        """Updates an existing user's details in storage."""
        raise NotImplementedError

    @abstractmethod
    def delete(self, user_id: uuid.UUID) -> None:
        """Deletes a user from storage by their unique ID."""
        raise NotImplementedError
