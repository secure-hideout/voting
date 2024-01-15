from fastapi import FastAPI, HTTPException, status
from databases import Database
import models
DATABASE_URL = "mysql+aiomysql://admin:your_password@16.170.201.59:3306/voting"
import sqlalchemy as sqlalchemy
from sqlalchemy import select, update
import jwt
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware

from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Depends, status
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
        raise HTTPException(status_code=400, detail="Invalid or already used UVC code.")

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
        return voter
    except Exception as e:
        await transaction.rollback()
        raise HTTPException(status_code=500, detail=str(e))


