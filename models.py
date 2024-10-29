from sqlalchemy import Column,Integer,String
from database import Base

class User(Base):
    __tablename__ = "users"  
    id = Column(Integer, primary_key=True, index=True)  
    name = Column(String, nullable=False)  
    username = Column(String, unique=True, index=True, nullable=False)  
    email = Column(String, unique=True, index=True, nullable=False)  
    hashed_password = Column(String, nullable=False)  
    phone = Column(String, nullable=True)
