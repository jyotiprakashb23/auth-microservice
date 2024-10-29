from pydantic import BaseModel
class UserCreate(BaseModel):
    name:str
    username:str
    email:str
    password:str
    phone:str