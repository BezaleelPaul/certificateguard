import sys
from pathlib import Path

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

import pytest
import os
import asyncio
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from app.database import Base, get_db
import app.database as app_db
import app.api.submissions as app_subs
from app.main import app
from app.models import User, Student, Issuer, UserRole
from app.security.auth import get_password_hash, create_access_token

TEST_DB_PATH = Path("./test_certificateguard.db").resolve()
TEST_DB_URL = f"sqlite+aiosqlite:///{TEST_DB_PATH}"

test_engine = create_async_engine(TEST_DB_URL, echo=False)
TestSessionLocal = async_sessionmaker(bind=test_engine, class_=AsyncSession, expire_on_commit=False)

# Monkey-patch database session factories for background tasks
app_db.engine = test_engine
app_db.AsyncSessionLocal = TestSessionLocal
app_subs.AsyncSessionLocal = TestSessionLocal


async def override_get_db():
    async with TestSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session", autouse=True)
async def setup_test_db():
    if TEST_DB_PATH.exists():
        try:
            TEST_DB_PATH.unlink()
        except Exception:
            pass

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Seed test users
    async with TestSessionLocal() as session:
        student_prof = Student(
            id="test-student-1",
            student_identifier="STU-TEST-001",
            full_name="Bezaleel Paul",
            email="student@example.com"
        )
        student_prof_2 = Student(
            id="test-student-2",
            student_identifier="STU-TEST-002",
            full_name="Rahul Kumar",
            email="rahul.k@example.com"
        )
        session.add(student_prof)
        session.add(student_prof_2)
        await session.flush()

        pw = get_password_hash("password123")
        u_student = User(
            id="test-user-student-1",
            name="Bezaleel Paul",
            email="student@example.com",
            hashed_password=pw,
            role=UserRole.STUDENT.value,
            student_id=student_prof.id
        )
        u_student_2 = User(
            id="test-user-student-2",
            name="Rahul Kumar",
            email="rahul.k@example.com",
            hashed_password=pw,
            role=UserRole.STUDENT.value,
            student_id=student_prof_2.id
        )
        u_teacher = User(
            id="test-user-teacher-1",
            name="Dr. Alan Turing",
            email="teacher@example.com",
            hashed_password=pw,
            role=UserRole.TEACHER.value
        )
        session.add(u_student)
        session.add(u_student_2)
        session.add(u_teacher)

        # Seed Issuer
        iss = Issuer(
            id="test-issuer-1",
            name="Example University",
            official_domain="example.edu",
            verification_type="WEB",
            verification_url="http://localhost:8001/verify",
            active=True
        )
        session.add(iss)
        await session.commit()

    yield

    # Cleanup
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await test_engine.dispose()
    if TEST_DB_PATH.exists():
        try:
            TEST_DB_PATH.unlink()
        except Exception:
            pass


@pytest.fixture
async def db_session():
    async with TestSessionLocal() as session:
        yield session
        await session.rollback()


@pytest.fixture
def student_auth_headers():
    token = create_access_token(data={"sub": "test-user-student-1", "role": "STUDENT"})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def other_student_auth_headers():
    token = create_access_token(data={"sub": "test-user-student-2", "role": "STUDENT"})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def teacher_auth_headers():
    token = create_access_token(data={"sub": "test-user-teacher-1", "role": "TEACHER"})
    return {"Authorization": f"Bearer {token}"}
