FROM python:3.12-alpine

WORKDIR /app

# Dependencias del sistema
RUN apk update && apk add --no-cache file libmagic

# Copiamos código
COPY . .

# Dependencias Python
RUN pip install --no-cache-dir -r requirements.txt

# Script inicial (se ejecuta en runtime igual que ahora)
CMD python create_user.py && \
    uvicorn main:app --host 0.0.0.0 --port 8001
