from __future__ import annotations
import ipaddress
from pydantic import BaseModel, field_validator

ALLOWED_MASKING = ("STUN", "AUTO", "NONE")

class Config(BaseModel):
    public_host: str
    pub_port: int
    wg_port: int
    wg_subnet: str
    masking: str
    mtu: int | None = None
    # Whether to expose the WireGuard UDP port on the public interface.
    # Default False -> hide (secure) mode where direct WG traffic is blocked
    # except via the obfuscator. Set True to expose the WG port publicly.
    expose_wg_port: bool = False

    # Optional obfuscator key (plain text). If None/empty, no `key =` line
    # will be written and wg-obfuscator will rely on WireGuard's crypto.
    # If supplied, the exact text will be used as the obfuscation key.
    create_obf_key: str | None = None

    @field_validator('pub_port', 'wg_port')
    @classmethod
    def port_in_range(cls, v):
        if not (1 <= v <= 65535):
            raise ValueError('Port must be between 1 and 65535')
        return v

    @field_validator('wg_subnet')
    @classmethod
    def valid_subnet(cls, v):
        try:
            net = ipaddress.ip_network(v, strict=False)
            if net.version != 4:
                raise ValueError('IPv4 only')
            hosts = list(net.hosts())
            if len(hosts) < 2:
                raise ValueError('Subnet too small (need at least 2 hosts)')
        except ValueError as e:
            raise ValueError(f'Invalid IPv4 CIDR: {e}')
        return v

    @field_validator('masking')
    @classmethod
    def valid_masking(cls, v):
        if v not in ALLOWED_MASKING:
            raise ValueError(f'Invalid masking mode: {v}')
        return v

    @field_validator('mtu')
    @classmethod
    def mtu_in_range(cls, v):
        if v is not None and not (1200 <= v <= 9200):
            raise ValueError('MTU must be between 1200 and 9200')
        return v

def first_host_and_client(nets: str) -> tuple[str, str, int]:
    net = ipaddress.ip_network(nets, strict=False)
    hosts = list(net.hosts())
    if len(hosts) < 2:
        raise ValueError("Subnet too small for server+client")
    return str(hosts[0]), str(hosts[1]), net.prefixlen