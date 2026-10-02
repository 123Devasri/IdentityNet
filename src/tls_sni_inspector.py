"""Minimal TLS ClientHello SNI parser; does not decrypt TLS."""

from typing import Optional


class TLSSNIInspector:
    """Extract server names from TLS records visible at the gateway."""

    def extract_sni(self, payload: bytes) -> Optional[str]:
        offset = 0
        while offset + 5 <= len(payload):
            if payload[offset] != 0x16:  # Handshake record
                return None
            record_length = int.from_bytes(payload[offset + 3:offset + 5], "big")
            record_end = offset + 5 + record_length
            if record_end > len(payload):
                return None
            handshake = payload[offset + 5:record_end]
            name = self._parse_client_hello(handshake)
            if name:
                return name
            offset = record_end
        return None

    def _parse_client_hello(self, data: bytes) -> Optional[str]:
        if len(data) < 4 or data[0] != 0x01:
            return None
        hello_length = int.from_bytes(data[1:4], "big")
        end = min(len(data), 4 + hello_length)
        offset = 4
        if offset + 2 + 32 + 1 > end:
            return None
        offset += 2 + 32
        session_length = data[offset]
        offset += 1 + session_length
        if offset + 2 > end:
            return None
        cipher_length = int.from_bytes(data[offset:offset + 2], "big")
        offset += 2 + cipher_length
        if offset + 1 > end:
            return None
        compression_length = data[offset]
        offset += 1 + compression_length
        if offset + 2 > end:
            return None
        extensions_length = int.from_bytes(data[offset:offset + 2], "big")
        offset += 2
        extensions_end = min(end, offset + extensions_length)

        while offset + 4 <= extensions_end:
            extension_type = int.from_bytes(data[offset:offset + 2], "big")
            extension_length = int.from_bytes(data[offset + 2:offset + 4], "big")
            offset += 4
            extension_end = offset + extension_length
            if extension_end > extensions_end:
                return None
            if extension_type == 0 and extension_length >= 5:
                server_name_list_length = int.from_bytes(data[offset:offset + 2], "big")
                name_offset = offset + 2
                name_end = min(extension_end, name_offset + server_name_list_length)
                while name_offset + 3 <= name_end:
                    name_type = data[name_offset]
                    name_length = int.from_bytes(data[name_offset + 1:name_offset + 3], "big")
                    name_offset += 3
                    if name_offset + name_length > name_end:
                        return None
                    if name_type == 0:
                        return data[name_offset:name_offset + name_length].decode("idna").lower().rstrip(".")
                    name_offset += name_length
            offset = extension_end
        return None
