from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os
from schemas import UserCreate,TokenData
from database import SessionLocal
from sqlalchemy.orm import Session
from models import User
from auth import create_access_token,create_refresh_token,get_user,authenticate_user

load_dotenv()

app = FastAPI()

origins = [
    "http://localhost:3000",  # Example: Frontend app running on localhost:3000
    "http://localhost:8001",  # Example: Other services that might call this API
    # Add more origins as needed
]

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/user/login")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.post("/user/register", tags=["Auth Service"])
async def register(user:UserCreate,db:Session = Depends(get_db)):
    existing_user = get_user(db, user.username)
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")
    hashed_password = pwd_context.hash(user.password)
    db_user = User(
        name=user.name,
        username=user.username,
        email=user.email,
        hashed_password=hashed_password,
        phone=user.phone,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    return {"msg": "User registered successfully", "user_id": db_user.id}

@app.post("/user/login" ,tags=["Auth Service"])
async def login(form_data: OAuth2PasswordRequestForm = Depends(),db:Session = Depends(get_db)):
    user = authenticate_user(db,form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Invalid credentials")
    
    access_token = create_access_token(data={"sub": user.username})
    refresh_token = create_refresh_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer","refresh_token": refresh_token, }

@app.get("/user/me",tags=["Auth Service"])
async def read_users_me(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, os.getenv("SECRET_KEY"), algorithms=os.getenv("ALGORITHM"))
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(db,username=username)
    if user is None:
        raise credentials_exception
    return user

@app.post("/token/refresh",tags=["Auth Service"])
async def refresh_token(refresh_token: str, db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(refresh_token, os.getenv("SECRET_KEY"), algorithms=os.getenv("ALGORITHM"))
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = get_user(db, username)
    if not user:
        raise credentials_exception

    new_access_token = create_access_token(data={"sub": username})
    return {"access_token": new_access_token, "token_type": "bearer"}

@app.post("/token/verify" ,tags=["Auth Service"])
async def verify_token(token_data:TokenData):
    token = token_data.token
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )        
    try:
        payload = jwt.decode(token, os.getenv("SECRET_KEY"), algorithms=os.getenv("ALGORITHM"))
        if payload is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return payload

@app.get("/data/demo")
def demo_function():
    print("consoling from demo function")
    return {"msg":"Message from authservice application"}