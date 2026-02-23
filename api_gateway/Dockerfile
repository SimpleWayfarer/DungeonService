FROM python:3.11-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential && \
    rm -rf /var/lib/apt/lists/*

COPY ./api_gateway/requirements.txt .
RUN pip install --no-cache-dir -r ./requirements.txt 

COPY ./proto/auth.proto .
RUN python -m grpc_tools.protoc -I./ --python_out=./ --grpc_python_out=./ ./auth.proto

COPY ./api_gateway/src/api_gateway.py .
CMD ["uvicorn", "api_gateway:app", "--host", "0.0.0.0", "--port", "8000"]