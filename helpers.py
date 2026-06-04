import curses
import ipaddress
import math
import os
import socket
import struct
from typing import Optional


def is_root() -> bool:
    geteuid = getattr(os, "geteuid", None)
    return bool(geteuid and geteuid() == 0)


def clamp(value: float, lower: float, upper: float) -> float:
    return max(lower, min(value, upper))


def hash_ip_angle(ip: str) -> float:
    try:
        address = ipaddress.ip_address(ip)
        value = int.from_bytes(address.packed, "big", signed=False)
    except ValueError:
        return 0.0
    value = ((value >> 16) ^ value) * 0x45D9F3B
    value = ((value >> 16) ^ value) * 0x45D9F3B
    value = (value >> 16) ^ value
    return (value % 360) * (math.pi / 180.0)


def merge_proto(existing: str, new_proto: str) -> str:
    if not existing or existing == "UNK":
        return new_proto
    if existing == new_proto:
        return existing
    return "MIX"


def parse_ss_endpoint(endpoint: str) -> Optional[str]:
    endpoint = (endpoint or "").strip()
    if not endpoint or endpoint in {"*", "-"}:
        return None
    if endpoint.startswith("["):
        host = endpoint[1:].split("]", 1)[0]
    else:
        host = endpoint.rsplit(":", 1)[0] if ":" in endpoint else endpoint
    if "%" in host:
        host = host.split("%", 1)[0]
    if host.startswith("::ffff:"):
        host = host.split("::ffff:", 1)[1]
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return None
    if address.is_unspecified:
        return None
    return str(address)


def normalize_error_text(text: str | None) -> Optional[str]:
    if not text:
        return None
    cleaned = [part.strip() for part in str(text).splitlines() if part.strip()]
    return " | ".join(cleaned) or None


def get_iface_operstate(iface: str | None) -> Optional[str]:
    if not iface:
        return None
    try:
        with open(f"/sys/class/net/{iface}/operstate", "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return None


def simulated_proto_for_ip(ip: str) -> str:
    try:
        last_octet = int(str(ip).rsplit(".", 1)[-1])
    except ValueError:
        return "UNK"
    return "TCP" if last_octet % 2 else "UDP"


def color_name_to_const(name: Optional[str]) -> int:
    if not name:
        return -1
    normalized = str(name).strip().lower()
    mapping = {
        "black": curses.COLOR_BLACK,
        "red": curses.COLOR_RED,
        "green": curses.COLOR_GREEN,
        "yellow": curses.COLOR_YELLOW,
        "blue": curses.COLOR_BLUE,
        "magenta": curses.COLOR_MAGENTA,
        "purple": curses.COLOR_MAGENTA,
        "cyan": curses.COLOR_CYAN,
        "white": curses.COLOR_WHITE,
        "default": -1,
    }
    if normalized in mapping:
        return mapping[normalized]
    try:
        return int(normalized)
    except ValueError:
        return -1
