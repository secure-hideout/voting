from fastapi import FastAPI, HTTPException, status
from databases import Database
import models
DATABASE_URL = "mysql+aiomysql://admin:your_password@16.170.201.59:3306/voting"
import sqlalchemy as sqlalchemy
from sqlalchemy import select, update
from sqlalchemy import create_engine, text
import jwt
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from typing import List
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Depends, status, Security, Response
from jose import JWTError, jwt
from pydantic import BaseModel
import bcrypt

metadata = sqlalchemy.MetaData()

voters = sqlalchemy.Table(
    "voters",
    metadata,
    sqlalchemy.Column("voter_id", sqlalchemy.String(50), primary_key=True),
    sqlalchemy.Column("full_name", sqlalchemy.String(50)),
    sqlalchemy.Column("DOB", sqlalchemy.Date),
    sqlalchemy.Column("password", sqlalchemy.Text),
    sqlalchemy.Column("UVC", sqlalchemy.String(45)),
    sqlalchemy.Column("constituency_id", sqlalchemy.Integer),
)

constituency = sqlalchemy.Table(
    "constituency",
    metadata,
    sqlalchemy.Column("constituency_id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("constituency_name", sqlalchemy.String(50)),
)


database = Database(DATABASE_URL)
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Passlib Context for password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)
def create_access_token(data: dict, role: str, expires_delta: timedelta = None):
    to_encode = data.copy()
    to_encode.update({"role": role})  # Add role to the payload
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def verify_voter(voter_id: str, password: str):
    query = "SELECT * FROM voters WHERE voter_id = :voter_id"
    voter = await database.fetch_one(query, values={"voter_id": voter_id})

    if voter and verify_password(password, voter["password"]):
        return voter
    return None

class TokenData(BaseModel):
    role: str = None

async def get_current_user(token: str = Security(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        role: str = payload.get("role")
        if role is None or role != "ec":
            raise credentials_exception
        token_data = TokenData(role=role)
    except JWTError:
        raise credentials_exception
    return token_data

@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    voter_id = form_data.username
    password = form_data.password

    # Check for special credentials
    if voter_id == "election@shangrila.gov.sr" and password == "shangrila2024$":
        access_token = create_access_token(
            data={"sub": voter_id},
            role="ec",
            expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        return {"access_token": access_token, "token_type": "bearer"}

    # For regular voters
    voter = await verify_voter(voter_id, password)
    if not voter:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect voter ID or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(
        data={"sub": voter["voter_id"]},
        role="voter",
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}



@app.on_event("startup")
async def startup():
    await database.connect()
    print("Database Connection Successfull")

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

@app.get("/")
async def root():
    return {"message": "Hello World"}


@app.get("/hello/{name}")
async def say_hello(name: str):
    return {"message": f"Hello {name}"}

@app.post("/voters/", response_model=models.Voter, status_code=status.HTTP_201_CREATED)
async def create_voter(voter: models.Voter):
    # Check if the UVC code exists and is not used
    check_uvc_query = "SELECT * FROM uvc_code WHERE UVC = :UVC AND used = 0"
    uvc_result = await database.fetch_one(check_uvc_query, values={"UVC": voter.UVC})

    if uvc_result is None:
        detail = {"status": "failure", "detail": "Invalid or already used UVC code."}
        raise HTTPException(status_code=400, detail=detail)

    transaction = await database.transaction()
    try:
        hashed_password = pwd_context.hash(voter.password)

        # Insert the new voter with the hashed password
        insert_voter_query = """
            INSERT INTO voters (voter_id, full_name, DOB, password, UVC, constituency_id)
            VALUES (:voter_id, :full_name, :DOB, :password, :UVC, :constituency_id)
        """
        await database.execute(insert_voter_query, values={**voter.dict(), "password": hashed_password})

        # Update the uvc_code table
        update_uvc_query = "UPDATE uvc_code SET used = 1 WHERE UVC = :UVC"
        await database.execute(update_uvc_query, values={"UVC": voter.UVC})

        await transaction.commit()
        return {**voter.dict(), "status": "success"}
    except Exception as e:
        await transaction.rollback()
        detail = {"status": "failure", "detail": str(e)}
        raise HTTPException(status_code=500, detail=detail)

@app.get("/constituencies")
async def get_constituencies():
    query = "SELECT * FROM constituency"
    constituencies = await database.fetch_all(query)
    return constituencies

@app.post("/constituency/", response_model=models.Constituency)
async def create_constituency(constituency: models.ConstituencyCreate, current_user: TokenData = Depends(get_current_user)):
    insert_query = f"INSERT INTO constituency (constituency_name) VALUES ('{constituency.constituency_name}')"
    last_record_id = await database.execute(insert_query)
    return {**constituency.dict(), "constituency_id": last_record_id}

@app.put("/constituency/{constituency_id}", response_model=models.Constituency)
async def update_constituency(constituency_id: int, constituency: models.ConstituencyCreate, current_user: TokenData = Depends(get_current_user)):
    update_query = f"UPDATE constituency SET constituency_name = '{constituency.constituency_name}' WHERE consitituency_id = {constituency_id}"
    await database.execute(update_query)
    return {**constituency.dict(), "constituency_id": constituency_id}

@app.delete("/constituency/{constituency_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_constituency(constituency_id: int, current_user: TokenData = Depends(get_current_user)):
    delete_query = f"DELETE FROM constituency WHERE consitituency_id = {constituency_id}"
    await database.execute(delete_query)
    return Response(status_code=status.HTTP_204_NO_CONTENT)

@app.get("/party/{party_id}", response_model=models.Party)
async def get_party_by_id(party_id: int):
    query = "SELECT * FROM party WHERE party_id = :party_id"
    party = await database.fetch_one(query, values={"party_id": party_id})
    if party is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Party not found")
    return party

@app.post("/party/", response_model=models.Party)
async def create_party(party: models.PartyCreate, current_user: TokenData = Depends(get_current_user)):
    insert_query = "INSERT INTO party (party) VALUES (:party_name)"
    values = {"party_name": party.party_name}
    party_id = await database.execute(insert_query, values=values)
    return {**party.dict(), "party_id": party_id}

@app.put("/party/{party_id}", response_model=models.Party)
async def update_party(party_id: int, party: models.PartyCreate, current_user: TokenData = Depends(get_current_user)):
    update_query = "UPDATE party SET party = :party_name WHERE party_id = :party_id"
    values = {"party_name": party.party_name, "party_id": party_id}
    await database.execute(update_query, values=values)
    return {**party.dict(), "party_id": party_id}

@app.delete("/party/{party_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_party(party_id: int, current_user: TokenData = Depends(get_current_user)):
    delete_query = "DELETE FROM party WHERE party_id = :party_id"
    values = {"party_id": party_id}
    await database.execute(delete_query, values=values)
    return Response(status_code=status.HTTP_204_NO_CONTENT)

@app.get("/parties")
async def get_all_parties():
    query = "SELECT * FROM party"
    parties = await database.fetch_all(query)
    return parties

@app.post("/candidate/", response_model=models.Candidate)
async def create_candidate(candidate: models.CandidateCreate, current_user: TokenData = Depends(get_current_user)):
    insert_query = (
        "INSERT INTO candidate (party_id, consitituency_id, vote_count, candidate) "
        "VALUES (:party_id, :constituency_id, :vote_count, :candidate)"
    )
    values = {
        "party_id": candidate.party_id,
        "constituency_id": candidate.constituency_id,
        "vote_count": candidate.vote_count,  # Allow vote_count to be None
        "candidate": candidate.candidate
    }
    candidate_id = await database.execute(insert_query, values)
    return {**candidate.dict(), "candidate_id": candidate_id}



@app.put("/candidate/{candidate_id}", response_model=models.Candidate)
async def update_candidate(candidate_id: int, candidate: models.CandidateUpdate, current_user: TokenData = Depends(get_current_user)):
    update_query = (
        "UPDATE candidate "
        "SET party_id = :party_id, consitituency_id = :constituency_id, vote_count = :vote_count "
        "WHERE consitituency_id = :candidate_id"
    )
    values = {
        "party_id": candidate.party_id,
        "constituency_id": candidate.constituency_id,
        "vote_count": candidate.vote_count,  # Allow vote_count to be None
        "candidate_id": candidate_id,
    }
    await database.execute(update_query, values)
    return {**candidate.dict(), "candidate_id": candidate_id}

@app.get("/candidates")
async def get_all_candidates():
    query = "SELECT * FROM candidate"
    candidates = await database.fetch_all(query)
    return candidates

@app.delete("/candidate/{canid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_candidate_by_id(canid: int, current_user: TokenData = Depends(get_current_user)):
    delete_query = "DELETE FROM candidate WHERE canid = :canid"
    values = {"canid": canid}
    await database.execute(delete_query, values=values)
    return None




