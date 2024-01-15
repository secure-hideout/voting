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

class ConstituencyBase(BaseModel):
    constituency_name: str

class ConstituencyCreate(ConstituencyBase):
    pass

class Constituency(ConstituencyBase):
    constituency_id: int

    class Config:
        orm_mode = True

from pydantic import BaseModel

class PartyBase(BaseModel):
    party: str

class PartyCreate(PartyBase):
    pass

class Party(PartyBase):
    party_id: int

    class Config:
        orm_mode = True

class CandidateBase(BaseModel):
    party_id: Optional[int]
    constituency_id: Optional[int]
    candidate: Optional[str]
    vote_count: Optional[int]  # Make vote_count optional

class CandidateCreate(CandidateBase):
    pass

class CandidateUpdate(CandidateBase):
    pass

class Candidate(CandidateBase):
    pass

    class Config:
        orm_mode = True


