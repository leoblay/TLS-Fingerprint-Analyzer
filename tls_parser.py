"""Minimal, dependency-free TLS ClientHello parser and JA3 calculator."""

from __future__ import annotations

import hashlib
from typing import Any


class ClientHelloIncomplete(Exception):
    """Raised when more TLS bytes are needed before the hello can be parsed."""


class ClientHelloParseError(Exception):
    """Raised when received bytes are not a usable ClientHello."""


def _u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 2], "big")


def _u24(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 3], "big")


def is_grease(value: int) -> bool:
    """GREASE values have equal bytes ending in 0x0a (for example 0x3a3a)."""
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


def extract_client_hello(tls_records: bytes) -> bytes:
    """Reassemble the first handshake message from one or more TLS records."""
    offset = 0
    handshake = bytearray()
    expected_size: int | None = None

    while True:
        if len(tls_records) - offset < 5:
            raise ClientHelloIncomplete()
        content_type = tls_records[offset]
        record_length = _u16(tls_records, offset + 3)
        record_end = offset + 5 + record_length
        if len(tls_records) < record_end:
            raise ClientHelloIncomplete()
        if content_type != 22:  # TLS Handshake record
            raise ClientHelloParseError("first TLS record is not a handshake record")

        handshake.extend(tls_records[offset + 5:record_end])
        if expected_size is None and len(handshake) >= 4:
            if handshake[0] != 1:  # ClientHello handshake type
                raise ClientHelloParseError("first handshake is not ClientHello")
            expected_size = 4 + _u24(handshake, 1)
        if expected_size is not None and len(handshake) >= expected_size:
            return bytes(handshake[:expected_size])
        offset = record_end


def _read_vector(data: bytes, offset: int, length_size: int) -> tuple[bytes, int]:
    if len(data) < offset + length_size:
        raise ClientHelloParseError("truncated vector length")
    length = int.from_bytes(data[offset:offset + length_size], "big")
    start = offset + length_size
    end = start + length
    if end > len(data):
        raise ClientHelloParseError("truncated vector")
    return data[start:end], end


def parse_client_hello(handshake: bytes) -> dict[str, Any]:
    """Extract the ClientHello fields that make up JA3 and comparison data."""
    if len(handshake) < 4 or handshake[0] != 1:
        raise ClientHelloParseError("not a ClientHello handshake")
    if len(handshake) != 4 + _u24(handshake, 1):
        raise ClientHelloParseError("ClientHello length does not match header")

    body = handshake[4:]
    if len(body) < 35:
        raise ClientHelloParseError("ClientHello body is too short")
    offset = 0
    legacy_version = _u16(body, offset)
    offset += 2 + 32  # version and random
    _, offset = _read_vector(body, offset, 1)  # session ID
    cipher_bytes, offset = _read_vector(body, offset, 2)
    if len(cipher_bytes) % 2:
        raise ClientHelloParseError("odd cipher suite list")
    cipher_suites = [_u16(cipher_bytes, index) for index in range(0, len(cipher_bytes), 2)]
    _, offset = _read_vector(body, offset, 1)  # compression methods

    extensions: list[int] = []
    supported_groups: list[int] = []
    ec_point_formats: list[int] = []
    supported_versions: list[int] = []
    if offset < len(body):
        extension_bytes, offset = _read_vector(body, offset, 2)
        extension_offset = 0
        while extension_offset < len(extension_bytes):
            if len(extension_bytes) - extension_offset < 4:
                raise ClientHelloParseError("truncated extension header")
            extension_type = _u16(extension_bytes, extension_offset)
            extension_length = _u16(extension_bytes, extension_offset + 2)
            value_start = extension_offset + 4
            value_end = value_start + extension_length
            if value_end > len(extension_bytes):
                raise ClientHelloParseError("truncated extension data")
            value = extension_bytes[value_start:value_end]
            extensions.append(extension_type)

            if extension_type == 10 and len(value) >= 2:  # supported_groups
                group_bytes, _ = _read_vector(value, 0, 2)
                if len(group_bytes) % 2 == 0:
                    supported_groups = [_u16(group_bytes, i) for i in range(0, len(group_bytes), 2)]
            elif extension_type == 11 and value:  # ec_point_formats
                format_bytes, _ = _read_vector(value, 0, 1)
                ec_point_formats = list(format_bytes)
            elif extension_type == 43 and value:  # supported_versions (helpful display field)
                version_bytes, _ = _read_vector(value, 0, 1)
                if len(version_bytes) % 2 == 0:
                    supported_versions = [_u16(version_bytes, i) for i in range(0, len(version_bytes), 2)]
            extension_offset = value_end
        if extension_offset != len(extension_bytes):
            raise ClientHelloParseError("invalid extension list length")

    filtered_ciphers = [value for value in cipher_suites if not is_grease(value)]
    filtered_extensions = [value for value in extensions if not is_grease(value)]
    filtered_groups = [value for value in supported_groups if not is_grease(value)]
    ja3 = ",".join((
        str(legacy_version),
        "-".join(map(str, filtered_ciphers)),
        "-".join(map(str, filtered_extensions)),
        "-".join(map(str, filtered_groups)),
        "-".join(map(str, ec_point_formats)),
    ))
    # This companion value preserves cipher/group ordering but sorts extensions only.
    normalized = ",".join((
        str(legacy_version),
        "-".join(map(str, filtered_ciphers)),
        "-".join(map(str, sorted(filtered_extensions))),
        "-".join(map(str, filtered_groups)),
        "-".join(map(str, ec_point_formats)),
    ))
    return {
        "legacy_version": legacy_version,
        "cipher_suites": cipher_suites,
        "cipher_suites_without_grease": filtered_ciphers,
        "extensions": extensions,
        "extensions_without_grease": filtered_extensions,
        "normalized_extensions": sorted(filtered_extensions),
        "supported_groups": supported_groups,
        "supported_groups_without_grease": filtered_groups,
        "ec_point_formats": ec_point_formats,
        "supported_versions": supported_versions,
        "ja3_string": ja3,
        "ja3_md5": hashlib.md5(ja3.encode("ascii")).hexdigest(),  # nosec B324: JA3 defines MD5
        "normalized_comparison_string": normalized,
        "normalized_comparison_md5": hashlib.md5(normalized.encode("ascii")).hexdigest(),  # nosec B324
    }

