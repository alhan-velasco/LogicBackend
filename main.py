"""
API RESTful de Logística - Envíos de Paquetes
FastAPI - Listo para desplegar con: uvicorn main:app --reload --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field

app = FastAPI(
    title="Logística API",
    description="API RESTful para gestión de envíos de paquetes",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer(auto_error=False)

# ---------------------------------------------------------------------------
# Almacenamiento en memoria
# ---------------------------------------------------------------------------

users_db: Dict[str, dict] = {}
tokens_db: Dict[str, str] = {}
shipments_db: Dict[str, dict] = {}


# ---------------------------------------------------------------------------
# Modelos
# ---------------------------------------------------------------------------


class ShipmentStatus(str, Enum):
    pending = "pending"
    in_transit = "in_transit"
    delivered = "delivered"


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6)
    full_name: str = Field(min_length=2)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class AuthResponse(BaseModel):
    token: str
    email: str
    full_name: str


class ShipmentCreate(BaseModel):
    trackingNumber: str = Field(min_length=3)
    sender: str = Field(min_length=2)
    receiver: str = Field(min_length=2)
    destination: str = Field(min_length=3)
    status: ShipmentStatus = ShipmentStatus.pending


class ShipmentUpdate(BaseModel):
    destination: Optional[str] = Field(default=None, min_length=3)
    status: Optional[ShipmentStatus] = None


class ShipmentResponse(BaseModel):
    id: str
    trackingNumber: str
    sender: str
    receiver: str
    destination: str
    status: ShipmentStatus
    created_at: str
    updated_at: str


# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------


def _hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _get_current_user_email(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> str:
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token de autenticación requerido",
        )
    email = tokens_db.get(credentials.credentials)
    if email is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido o expirado",
        )
    return email


def _to_shipment_response(data: dict) -> ShipmentResponse:
    return ShipmentResponse(**data)


# ---------------------------------------------------------------------------
# Autenticación
# ---------------------------------------------------------------------------


@app.post("/api/auth/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest) -> AuthResponse:
    if payload.email in users_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El correo electrónico ya está registrado",
        )

    users_db[payload.email] = {
        "email": payload.email,
        "password_hash": _hash_password(payload.password),
        "full_name": payload.full_name,
    }

    token = secrets.token_urlsafe(32)
    tokens_db[token] = payload.email

    return AuthResponse(
        token=token,
        email=payload.email,
        full_name=payload.full_name,
    )


@app.post("/api/auth/login", response_model=AuthResponse)
def login(payload: LoginRequest) -> AuthResponse:
    user = users_db.get(payload.email)
    if user is None or user["password_hash"] != _hash_password(payload.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas",
        )

    token = secrets.token_urlsafe(32)
    tokens_db[token] = payload.email

    return AuthResponse(
        token=token,
        email=user["email"],
        full_name=user["full_name"],
    )


# ---------------------------------------------------------------------------
# Envíos (Shipments)
# ---------------------------------------------------------------------------


@app.get("/api/shipments", response_model=List[ShipmentResponse])
def list_shipments(_: str = Depends(_get_current_user_email)) -> List[ShipmentResponse]:
    shipments = sorted(
        shipments_db.values(),
        key=lambda s: s["created_at"],
        reverse=True,
    )
    return [_to_shipment_response(s) for s in shipments]


@app.post("/api/shipments", response_model=ShipmentResponse, status_code=status.HTTP_201_CREATED)
def create_shipment(
    payload: ShipmentCreate,
    _: str = Depends(_get_current_user_email),
) -> ShipmentResponse:
    shipment_id = str(uuid.uuid4())
    now = _now_iso()

    shipment = {
        "id": shipment_id,
        "trackingNumber": payload.trackingNumber,
        "sender": payload.sender,
        "receiver": payload.receiver,
        "destination": payload.destination,
        "status": payload.status.value,
        "created_at": now,
        "updated_at": now,
    }
    shipments_db[shipment_id] = shipment
    return _to_shipment_response(shipment)


@app.put("/api/shipments/{shipment_id}", response_model=ShipmentResponse)
def update_shipment(
    shipment_id: str,
    payload: ShipmentUpdate,
    _: str = Depends(_get_current_user_email),
) -> ShipmentResponse:
    shipment = shipments_db.get(shipment_id)
    if shipment is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Envío no encontrado",
        )

    if payload.destination is not None:
        shipment["destination"] = payload.destination
    if payload.status is not None:
        shipment["status"] = payload.status.value

    shipment["updated_at"] = _now_iso()
    shipments_db[shipment_id] = shipment
    return _to_shipment_response(shipment)


@app.delete("/api/shipments/{shipment_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_shipment(
    shipment_id: str,
    _: str = Depends(_get_current_user_email),
) -> None:
    if shipment_id not in shipments_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Envío no encontrado",
        )
    del shipments_db[shipment_id]


@app.get("/")
def health_check() -> dict:
    return {"status": "ok", "service": "logistica-api"}
