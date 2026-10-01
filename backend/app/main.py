import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.database import engine, Base
from app.seed import seed_data
from app.api import auth, submissions, issuers, audit, stats


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: ensure tables and seed initial test records
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await seed_data()
    yield
    # Shutdown
    await engine.dispose()


app = FastAPI(
    title="CertificateGuard API",
    description="Evidence-Based Certificate Verification & Anomaly Detection Platform",
    version="1.0.0",
    lifespan=lifespan
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows local frontend on any port
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(auth.router)
app.include_router(submissions.router)
app.include_router(issuers.router)
app.include_router(audit.router)
app.include_router(stats.router)


@app.get("/health")
def health_check():
    return {"status": "ok", "platform": "CertificateGuard", "version": "1.0.0"}


@app.get("/")
def root():
    return {
        "message": "Welcome to CertificateGuard API",
        "docs": "/docs",
        "philosophy": "AI and automation provide evidence. The issuer and teacher provide trust."
    }
