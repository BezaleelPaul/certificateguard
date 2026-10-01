import asyncio
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.database import AsyncSessionLocal, Base, engine
from app.models import User, Student, Issuer, UserRole, IssuerVerificationType
from app.security.auth import get_password_hash


async def seed_data():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as session:
        # Check if users already seeded
        res = await session.execute(select(User).where(User.email == "student@example.com"))
        if res.scalar_one_or_none():
            print("Database already contains seed users.")
            return

        print("Seeding initial development users and issuers...")

        # 1. Seed Student Profile
        student_profile = Student(
            student_identifier="STU-2025-001",
            full_name="Bezaleel Paul",
            email="student@example.com",
            department="Computer Science & Engineering",
            section="A"
        )
        session.add(student_profile)
        await session.flush()

        student_profile_2 = Student(
            student_identifier="STU-2025-002",
            full_name="Rahul Kumar",
            email="rahul.k@example.com",
            department="Information Security",
            section="B"
        )
        session.add(student_profile_2)
        await session.flush()

        # 2. Seed Users
        hashed_pw = get_password_hash("password123")

        user_student = User(
            name="Bezaleel Paul",
            email="student@example.com",
            hashed_password=hashed_pw,
            role=UserRole.STUDENT.value,
            student_id=student_profile.id
        )
        session.add(user_student)

        user_teacher = User(
            name="Dr. Alan Turing",
            email="teacher@example.com",
            hashed_password=hashed_pw,
            role=UserRole.TEACHER.value
        )
        session.add(user_teacher)

        user_admin = User(
            name="System Administrator",
            email="admin@example.com",
            hashed_password=hashed_pw,
            role=UserRole.ADMIN.value
        )
        session.add(user_admin)

        # 3. Seed Issuers
        issuer_1 = Issuer(
            name="Example University",
            official_domain="example.edu",
            verification_type=IssuerVerificationType.WEB.value,
            verification_url="http://localhost:8001/verify",
            active=True,
            configuration_json='{"status_selector": "#cert-status", "recipient_selector": "#cert-recipient", "course_selector": "#cert-course", "cert_id_selector": "#cert-id"}'
        )
        session.add(issuer_1)

        issuer_2 = Issuer(
            name="Coursera Verification Service",
            official_domain="coursera.org",
            verification_type=IssuerVerificationType.WEB.value,
            verification_url="https://coursera.org/verify",
            active=True,
            configuration_json='{"status_selector": ".verification-status"}'
        )
        session.add(issuer_2)

        issuer_3 = Issuer(
            name="edX Credential Authority",
            official_domain="edx.org",
            verification_type=IssuerVerificationType.WEB.value,
            verification_url="https://courses.edx.org/certificates",
            active=True
        )
        session.add(issuer_3)

        await session.commit()
        print("Successfully seeded development data:")
        print("  - student@example.com (Password: password123)")
        print("  - teacher@example.com (Password: password123)")
        print("  - admin@example.com   (Password: password123)")


if __name__ == "__main__":
    asyncio.run(seed_data())
