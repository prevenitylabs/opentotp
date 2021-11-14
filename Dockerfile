# syntax=docker/dockerfile:1
FROM python:alpine
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
ENTRYPOINT ["python3", "-m", "opentotp"]
