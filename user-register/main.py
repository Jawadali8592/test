
# from fastapi import FastAPI, HTTPException, Depends
# from pydantic import BaseModel, EmailStr, constr
# from passlib.context import CryptContext
# from sqlmodel import SQLModel, Field, create_engine, Session, select

# app = FastAPI()

# # Database configuration
# connection_string = 'postgresql://postgres.reryfynzrybzthmgvefq:FCUovkXqEjT8E9pr@aws-0-ap-southeast-1.pooler.supabase.com:6543/postgres'
# engine = create_engine(connection_string)

# # Password hashing context
# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# # SQLModel for User
# class User(SQLModel, table=True):
#     id: int = Field(default=None, primary_key=True)
#     email: str
#     hashed_password: str

# class UserCreate(BaseModel):
#     email: EmailStr
#     password: constr(min_length=8)

# # Create the database tables
# SQLModel.metadata.create_all(engine)

# def get_password_hash(password):
#     return pwd_context.hash(password)

# def verify_password(plain_password, hashed_password):
#     return pwd_context.verify(plain_password, hashed_password)

# def get_user(email: str, session: Session):
#     statement = select(User).where(User.email == email)
#     return session.exec(statement).first()

# def create_user(user: UserCreate, session: Session):
#     if get_user(user.email, session):
#         raise HTTPException(status_code=400, detail="Email already registered")
#     hashed_password = get_password_hash(user.password)
#     db_user = User(email=user.email, hashed_password=hashed_password)
#     session.add(db_user)
#     session.commit()
#     session.refresh(db_user)
#     return db_user

# @app.post("/register/")
# def register(user: UserCreate):
#     with Session(engine) as session:
#         db_user = create_user(user, session)
#         return {"email": db_user.email}

from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, constr
from passlib.context import CryptContext
from sqlmodel import SQLModel, Field, create_engine, Session, select
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional

# Initialize FastAPI app
app = FastAPI()

# Database configuration
connection_string = 'postgresql://postgres.reryfynzrybzthmgvefq:FCUovkXqEjT8E9pr@aws-0-ap-southeast-1.pooler.supabase.com:6543/postgres'
engine = create_engine(connection_string)

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT configuration
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# SQLModel for User
class User(SQLModel, table=True):
    id: int = Field(default=None, primary_key=True)
    email: str
    hashed_password: str

class UserCreate(BaseModel):
    email: EmailStr
    password: constr(min_length=8)

class UserLogin(BaseModel):
    email: EmailStr
    password: constr(min_length=8)

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

# Create the database tables
SQLModel.metadata.create_all(engine)

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_user(email: str, session: Session):
    statement = select(User).where(User.email == email)
    return session.exec(statement).first()

def create_user(user: UserCreate, session: Session):
    if get_user(user.email, session):
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(user.password)
    db_user = User(email=user.email, hashed_password=hashed_password)
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user

def authenticate_user(email: str, password: str, session: Session):
    user = get_user(email, session)
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    with Session(engine) as session:
        user = get_user(token_data.email, session)
        if user is None:
            raise credentials_exception
        return user

@app.post("/register/")
def register(user: UserCreate):
    with Session(engine) as session:
        db_user = create_user(user, session)
        return {"email": db_user.email}

@app.post("/login/", response_model=Token)
def login(user: UserLogin):
    with Session(engine) as session:
        db_user = authenticate_user(user.email, user.password, session)
        if not db_user:
            raise HTTPException(status_code=400, detail="Invalid credentials")
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": db_user.email}, expires_delta=access_token_expires
        )
        return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user


