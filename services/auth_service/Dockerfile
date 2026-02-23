FROM python:3.11-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential && \
    rm -rf /var/lib/apt/lists/*

COPY ./services/auth_service/requirements.txt .
RUN pip install --no-cache-dir -r ./requirements.txt 

COPY ./proto/auth.proto .
RUN python -m grpc_tools.protoc -I./ --python_out=./ --grpc_python_out=./ ./auth.proto

COPY ./services/auth_service/src/auth_service.py .
CMD ["python", "auth_service.py"]