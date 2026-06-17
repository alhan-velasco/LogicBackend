"""
API RESTful de Logística - Envíos de Paquetes
FastAPI + SQLite - Listo para desplegar con:
uvicorn main:app --reload --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Generator, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field

DATABASE_PATH = Path(__file__).resolve().parent / "logistica.db"

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
# Base de datos SQLite
# ---------------------------------------------------------------------------


def init_db() -> None:
    with get_db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                full_name TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tokens (
                token TEXT PRIMARY KEY,
                user_email TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_email) REFERENCES users(email) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS shipments (
                id TEXT PRIMARY KEY,
                tracking_number TEXT NOT NULL,
                sender TEXT NOT NULL,
                receiver TEXT NOT NULL,
                destination TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )


@contextmanager
def get_db() -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@app.on_event("startup")
def on_startup() -> None:
    init_db()


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


def _get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    with get_db() as conn:
        return conn.execute(
            "SELECT email, password_hash, full_name FROM users WHERE email = ?",
            (email,),
        ).fetchone()


def _create_user(email: str, password_hash: str, full_name: str) -> None:
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO users (email, password_hash, full_name, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (email, password_hash, full_name, _now_iso()),
        )


def _create_token(token: str, user_email: str) -> None:
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO tokens (token, user_email, created_at)
            VALUES (?, ?, ?)
            """,
            (token, user_email, _now_iso()),
        )


def _get_email_by_token(token: str) -> Optional[str]:
    with get_db() as conn:
        row = conn.execute(
            "SELECT user_email FROM tokens WHERE token = ?",
            (token,),
        ).fetchone()
        return row["user_email"] if row else None


def _row_to_shipment_dict(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "trackingNumber": row["tracking_number"],
        "sender": row["sender"],
        "receiver": row["receiver"],
        "destination": row["destination"],
        "status": row["status"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _get_shipment_by_id(shipment_id: str) -> Optional[dict]:
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM shipments WHERE id = ?",
            (shipment_id,),
        ).fetchone()
        return _row_to_shipment_dict(row) if row else None


def _list_shipments() -> List[dict]:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM shipments ORDER BY created_at DESC"
        ).fetchall()
        return [_row_to_shipment_dict(row) for row in rows]


def _create_shipment_record(
    shipment_id: str,
    tracking_number: str,
    sender: str,
    receiver: str,
    destination: str,
    shipment_status: str,
    created_at: str,
    updated_at: str,
) -> dict:
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO shipments (
                id, tracking_number, sender, receiver, destination,
                status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                shipment_id,
                tracking_number,
                sender,
                receiver,
                destination,
                shipment_status,
                created_at,
                updated_at,
            ),
        )

    return {
        "id": shipment_id,
        "trackingNumber": tracking_number,
        "sender": sender,
        "receiver": receiver,
        "destination": destination,
        "status": shipment_status,
        "created_at": created_at,
        "updated_at": updated_at,
    }


def _update_shipment_record(
    shipment_id: str,
    destination: Optional[str],
    shipment_status: Optional[str],
) -> Optional[dict]:
    shipment = _get_shipment_by_id(shipment_id)
    if shipment is None:
        return None

    new_destination = destination if destination is not None else shipment["destination"]
    new_status = shipment_status if shipment_status is not None else shipment["status"]
    updated_at = _now_iso()

    with get_db() as conn:
        conn.execute(
            """
            UPDATE shipments
            SET destination = ?, status = ?, updated_at = ?
            WHERE id = ?
            """,
            (new_destination, new_status, updated_at, shipment_id),
        )

    shipment["destination"] = new_destination
    shipment["status"] = new_status
    shipment["updated_at"] = updated_at
    return shipment


def _delete_shipment_record(shipment_id: str) -> bool:
    with get_db() as conn:
        cursor = conn.execute(
            "DELETE FROM shipments WHERE id = ?",
            (shipment_id,),
        )
        return cursor.rowcount > 0


def _get_current_user_email(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> str:
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token de autenticación requerido",
        )

    email = _get_email_by_token(credentials.credentials)
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
    if _get_user_by_email(payload.email) is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El correo electrónico ya está registrado",
        )

    _create_user(
        email=payload.email,
        password_hash=_hash_password(payload.password),
        full_name=payload.full_name,
    )

    token = secrets.token_urlsafe(32)
    _create_token(token, payload.email)

    return AuthResponse(
        token=token,
        email=payload.email,
        full_name=payload.full_name,
    )


@app.post("/api/auth/login", response_model=AuthResponse)
def login(payload: LoginRequest) -> AuthResponse:
    user = _get_user_by_email(payload.email)
    if user is None or user["password_hash"] != _hash_password(payload.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas",
        )

    token = secrets.token_urlsafe(32)
    _create_token(token, payload.email)

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
    shipments = _list_shipments()
    return [_to_shipment_response(shipment) for shipment in shipments]


@app.post("/api/shipments", response_model=ShipmentResponse, status_code=status.HTTP_201_CREATED)
def create_shipment(
    payload: ShipmentCreate,
    _: str = Depends(_get_current_user_email),
) -> ShipmentResponse:
    shipment_id = str(uuid.uuid4())
    now = _now_iso()

    shipment = _create_shipment_record(
        shipment_id=shipment_id,
        tracking_number=payload.trackingNumber,
        sender=payload.sender,
        receiver=payload.receiver,
        destination=payload.destination,
        shipment_status=payload.status.value,
        created_at=now,
        updated_at=now,
    )
    return _to_shipment_response(shipment)


@app.put("/api/shipments/{shipment_id}", response_model=ShipmentResponse)
def update_shipment(
    shipment_id: str,
    payload: ShipmentUpdate,
    _: str = Depends(_get_current_user_email),
) -> ShipmentResponse:
    shipment = _update_shipment_record(
        shipment_id=shipment_id,
        destination=payload.destination,
        shipment_status=payload.status.value if payload.status is not None else None,
    )
    if shipment is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Envío no encontrado",
        )

    return _to_shipment_response(shipment)


@app.delete(
    "/api/shipments/{shipment_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
)
def delete_shipment(
    shipment_id: str,
    _: str = Depends(_get_current_user_email),
) -> Response:
    if not _delete_shipment_record(shipment_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Envío no encontrado",
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.get("/")
def health_check() -> dict:
    return {
        "status": "ok",
        "service": "logistica-api",
        "database": str(DATABASE_PATH.name),
    }
