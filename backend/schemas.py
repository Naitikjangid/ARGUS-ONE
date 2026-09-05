from datetime import datetime
from pydantic import BaseModel, Field


class Flow(BaseModel):
    timestamp: datetime

    src_ip: str
    dst_ip: str

    src_port: int = Field(ge=0, le=65535)
    dst_port: int = Field(ge=0, le=65535)

    protocol: str

    bytes_out: int = Field(ge=0)
    bytes_in: int = Field(ge=0)

    packets_out: int = Field(ge=0)
    packets_in: int = Field(ge=0)

    tcp_flags: str = ""