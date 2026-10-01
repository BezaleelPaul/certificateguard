from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from app.database import get_db
from app.models import Issuer, User
from app.schemas import IssuerCreate, IssuerUpdate, IssuerResponse
from app.security.auth import get_current_user, require_admin, require_teacher

router = APIRouter(prefix="/api/issuers", tags=["Issuers"])


@router.get("", response_model=List[IssuerResponse])
async def list_issuers(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Issuer).order_by(desc(Issuer.created_at)))
    return result.scalars().all()


@router.post("", response_model=IssuerResponse)
async def create_issuer(
    issuer_in: IssuerCreate,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    # Check domain uniqueness
    existing = await db.execute(select(Issuer).where(Issuer.official_domain == issuer_in.official_domain.strip().lower()))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Issuer with domain '{issuer_in.official_domain}' already registered"
        )

    issuer = Issuer(
        name=issuer_in.name,
        official_domain=issuer_in.official_domain.strip().lower(),
        verification_type=issuer_in.verification_type.value,
        verification_url=issuer_in.verification_url,
        active=issuer_in.active,
        configuration_json=issuer_in.configuration_json
    )
    db.add(issuer)
    await db.commit()
    await db.refresh(issuer)
    return issuer


@router.patch("/{issuer_id}", response_model=IssuerResponse)
async def update_issuer(
    issuer_id: str,
    issuer_in: IssuerUpdate,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Issuer).where(Issuer.id == issuer_id))
    issuer = result.scalar_one_or_none()
    if not issuer:
        raise HTTPException(status_code=404, detail="Issuer not found")

    if issuer_in.name is not None:
        issuer.name = issuer_in.name
    if issuer_in.official_domain is not None:
        issuer.official_domain = issuer_in.official_domain.strip().lower()
    if issuer_in.verification_type is not None:
        issuer.verification_type = issuer_in.verification_type.value
    if issuer_in.verification_url is not None:
        issuer.verification_url = issuer_in.verification_url
    if issuer_in.active is not None:
        issuer.active = issuer_in.active
    if issuer_in.configuration_json is not None:
        issuer.configuration_json = issuer_in.configuration_json

    await db.commit()
    await db.refresh(issuer)
    return issuer
