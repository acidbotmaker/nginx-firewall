from typing import Literal, Optional

from pydantic import BaseModel, Field


class ServiceCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    upstream_host: str = Field(..., min_length=1, description="Host nginx forwards to")
    protocol: Literal["tcp", "udp"]
    external_port: int = Field(..., ge=1, le=65535, description="Public port nginx listens on")
    target_port: int = Field(..., ge=1, le=65535, description="Upstream port to forward to")
    enabled: bool = True


class ServiceUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    upstream_host: Optional[str] = Field(None, min_length=1)
    protocol: Optional[Literal["tcp", "udp"]] = None
    external_port: Optional[int] = Field(None, ge=1, le=65535)
    target_port: Optional[int] = Field(None, ge=1, le=65535)
    enabled: Optional[bool] = None


class ServiceOut(BaseModel):
    id: int
    name: str
    upstream_host: str
    protocol: str
    external_port: int
    target_port: int
    enabled: bool
    created_at: str
    updated_at: str


class IPEntryCreate(BaseModel):
    service_id: int = Field(..., description="Service this rule applies to")
    value: str = Field(..., description="IPv4/IPv6 address or CIDR range")
    label: Optional[str] = None
    enabled: bool = True


class IPEntryUpdate(BaseModel):
    label: Optional[str] = None
    enabled: Optional[bool] = None


class IPEntryOut(BaseModel):
    id: int
    service_id: int
    service_name: str
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
