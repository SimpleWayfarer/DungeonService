from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

from pydantic import BaseModel
import grpc
import auth_pb2
import auth_pb2_grpc


app = FastAPI()

auth_service_address = 'auth-service:50051'
auth_channel = grpc.insecure_channel(auth_service_address)
auth_stub = auth_pb2_grpc.AuthServiceStub(auth_channel)

origins = [
    "http://localhost",
    "http://127.0.0.1",
    "http://localhost:80",
    "http://127.0.0.1:80" 
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins, 
    allow_credentials=True,
    allow_methods=["*"], 
    allow_headers=["*"]
)

class UserSchema(BaseModel):
    username: str
    password: str

@app.post("/api/register")
async def register(user: UserSchema):
    response = auth_stub.Register(auth_pb2.RegisterRequest(username=user.username, password=user.password))
    if not response.success:
        raise HTTPException(status_code=400, detail=response.message)
    return {"token": response.token, "username": response.username}

@app.post("/api/login")
async def login(user: UserSchema):
    response = auth_stub.Login(auth_pb2.LoginRequest(username=user.username, password=user.password))
    if not response.success:
        raise HTTPException(status_code=401, detail=response.message)
    return {"token": response.token, "username": response.username}

@app.get("/api/validate")
async def validate(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    
    token = authorization.split(" ")[1]
    
    response = auth_stub.ValidateToken(auth_pb2.ValidateRequest(token=token))
    
    if not response.is_valid:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    
    return {"status": "ok", "username": response.username}
