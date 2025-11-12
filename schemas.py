"""
Database Schemas for SheSecure

Each Pydantic model maps to a MongoDB collection (class name lowercased).
"""
from typing import List, Optional
from pydantic import BaseModel, Field, EmailStr

class User(BaseModel):
    """
    SheSecure user profile
    Collection: user
    """
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address")
    phone: str = Field(..., description="Phone number")
    address: Optional[str] = Field(None, description="Address")
    state: Optional[str] = Field(None, description="State/Region")
    photo_url: Optional[str] = Field(None, description="Profile photo URL")
    emergency_contacts: List[str] = Field(default_factory=list, description="Up to 4 emergency contact numbers")
    language: str = Field("en", description="Language preference: 'en' or 'hi'")

class Report(BaseModel):
    """
    Unsafe area reports submitted by users
    Collection: report
    """
    user_id: Optional[str] = Field(None, description="Reporter user id")
    lat: float
    lng: float
    description: Optional[str] = None
    photo_url: Optional[str] = None
    severity: int = Field(1, ge=1, le=5, description="1-5 where 5 is most severe")

class Session(BaseModel):
    """
    Simple session mapping for demo (email/phone -> user id)
    Collection: session
    """
    user_id: str
    token: str
