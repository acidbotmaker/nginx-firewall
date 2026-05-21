from typing import Optional

from pydantic import BaseModel, Field


class IPEntryCreate(BaseModel):
    value: str = Field(..., description="IPv4/IPv6 address or CIDR range")
    label: Optional[str] = None
    enabled: bool = True


class IPEntryUpdate(BaseModel):
    label: Optional[str] = None
    enabled: Optional[bool] = None


class IPEntryOut(BaseModel):
    id: int
    value: str
    label: Optional[str]
    enabled: bool
    created_at: str
    updated_at: str


class TokenCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)


class TokenOut(BaseModel):
    id: int
    name: str
    created_at: str
    last_used_at: Optional[str]


class TokenCreatedOut(TokenOut):
    token: str = Field(..., description="Plaintext token, shown only once")


class LoginRequest(BaseModel):
    password: str
