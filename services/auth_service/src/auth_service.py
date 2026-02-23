import grpc
from concurrent import futures
import auth_pb2
import auth_pb2_grpc
from passlib.hash import bcrypt

import jwt
from datetime import datetime, timedelta

from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker

import redis

#Подключение к Postgres
DATABASE_URL = "postgresql://postgres:postgres@users-db:5432/dungeon_users"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
Base.metadata.create_all(bind=engine)

#Создание токена JWT
def create_access_token(data: dict):
    SECRET_KEY = "SECRET_KEY"
    ALGORITHM = "HS256"
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=30)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

#Подключение к Redis
cache = redis.Redis(host='users-cache', port=6379, db=0, decode_responses=True)


class AuthServicer(auth_pb2_grpc.AuthServiceServicer):
    def Register(self, request, context):
        db = SessionLocal()
        existing_user = db.query(User).filter(User.username == request.username).first()
        if existing_user:
            return auth_pb2.AuthResponse(success=False, message="User already exists")
        
        new_user = User(
            username=request.username, 
            hashed_password=bcrypt.hash(request.password)
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        
        token = create_access_token({"sub": new_user.username})
        return auth_pb2.AuthResponse(success=True, token=token, username=new_user.username)

    def Login(self, request, context):
        db = SessionLocal()
        user = db.query(User).filter(User.username == request.username).first()
        
        if user and bcrypt.verify(request.password, user.hashed_password):
            token = create_access_token({"sub": user.username})
            cache.setex(f"session:{token}", 1800, user.username)
            return auth_pb2.AuthResponse(success=True, token=token, username=user.username)
            
        return auth_pb2.AuthResponse(success=False, message="Invalid username or password")
    
    def ValidateToken(self, request, context):
        token = request.token
        SECRET_KEY = "SECRET_KEY"
        ALGORITHM = "HS256"
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username = payload.get("sub")
            
            if not username:
                return auth_pb2.ValidateResponse(is_valid=False, message="Invalid payload")

            session_user = cache.get(f"session:{token}")
            
            if not session_user:
                return auth_pb2.ValidateResponse(is_valid=False, message="Session expired or logged out")

            return auth_pb2.ValidateResponse(
                is_valid=True, 
                username=username, 
                message="Token is valid"
            )

        except jwt.ExpiredSignatureError:
            return auth_pb2.ValidateResponse(is_valid=False, message="Token has expired")
        except jwt.InvalidTokenError:
            return auth_pb2.ValidateResponse(is_valid=False, message="Invalid token")
        except Exception as e:
            return auth_pb2.ValidateResponse(is_valid=False, message=str(e))
    
def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    auth_pb2_grpc.add_AuthServiceServicer_to_server(AuthServicer(), server)
    server.add_insecure_port('[::]:50051')
    server.start()
    server.wait_for_termination()

if __name__ == "__main__":
    serve()