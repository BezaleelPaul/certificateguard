FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir fastapi uvicorn pydantic

COPY mock-issuer/ /app/

EXPOSE 8001

CMD ["python", "main.py"]
