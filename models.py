from pydantic import BaseModel, Field
from datetime import date
from typing import Optional

from sqlalchemy import Column, String, Integer, Table
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class UVCCodeTable(Base):
    __tablename__ = 'uvc_code'
    UVC = Column(String, primary_key=True)
    used = Column(Integer)

class Voter(BaseModel):
    voter_id: str = Field(..., max_length=50)
    full_name: Optional[str] = Field(None, max_length=50)
    DOB: Optional[date] = None
    password: str
    UVC: Optional[str] = Field(None, max_length=45)
    constituency_id: Optional[int] = None

