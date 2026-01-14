# Hello Message Field Structures

This document describes the structure, types, initialization patterns, and valid values for each field in `ClientHello` and `ServerHello` messages that can be mutated via the mutator.

## Overview

The mutator allows modification of TLS handshake messages (`ClientHello` and `ServerHello`) before they are sent over the network. This document provides detailed information about each mutable field, including:

- Python type definitions
- How fields are initialized in normal flow
- Valid values and constraints
- JSON representation for mutations
- Examples

## Important Notes

- **Field Name Differences**: Some fields have different names or types between `ClientHello` and `ServerHello`:
  - `cipher_suites` (ClientHello, list) vs `cipher_suite` (ServerHello, int)
  - `legacy_compression_methods` (ClientHello, list) vs `compression_method` (ServerHello, int)
  - `key_share` (ClientHello, list) vs `key_share` (ServerHello, single entry)
  - `supported_versions` (ClientHello, list) vs `supported_version` (ServerHello, int)
  - `pre_shared_key` (ClientHello, OfferedPsks) vs `pre_shared_key` (ServerHello, int)

- **Note on ALLOWED_FIELD_NAMES**: The mutator's `ALLOWED_FIELD_NAMES` list includes field names that can be mutated. Some ServerHello-specific fields like `cipher_suite` and `compression_method` (singular) are documented here but use the plural names from ClientHello in the mutator API. When mutating ServerHello, use the singular field names directly.

- **Complex Types**: Some fields use complex nested types (tuples, dataclasses) that require special JSON representation.

---

## Field Documentation

### `random`

**Applies to**: ClientHello, ServerHello

**Python Type**: `bytes`

**Length**: Exactly 32 bytes

**Description**: Random value used in the TLS handshake. Must be exactly 32 bytes.

**Initialization**:
- **ClientHello**: `self.client_random = os.urandom(32)` (line 1343 in `tls.py`)
- **ServerHello**: `self.server_random = os.urandom(32)` (line 1911 in `tls.py`)

**Valid Values**: Any 32-byte sequence

**Example**:
```python
random = b'\x01' * 32  # 32 bytes of 0x01
```

**JSON Representation**: Base64-encoded string or hex string
```json
{
  "mutation": "modify_field",
  "target": "client",
  "fields": {
    "field_name": "random",
    "new_value": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
  }
}
```

**Constraints**: Must be exactly 32 bytes. Cannot be `None`.

---

### `legacy_session_id`

**Applies to**: ClientHello, ServerHello

**Python Type**: `bytes`

**Description**: Legacy TLS session ID (for compatibility with TLS 1.2 and earlier). Can be empty.

**Initialization**:
- **ClientHello**: `self.legacy_session_id = b""` (line 1344 in `tls.py`)
- **ServerHello**: Copied from ClientHello: `self.legacy_session_id = peer_hello.legacy_session_id` (line 1912 in `tls.py`)

**Valid Values**: Any byte sequence, typically empty (`b""`) for TLS 1.3

**Example**:
```python
legacy_session_id = b""  # Empty for TLS 1.3
legacy_session_id = b"\x01\x02\x03"  # Example session ID
```

**JSON Representation**: Base64-encoded string or hex string
```json
{
  "mutation": "modify_field",
  "target": "client",
  "fields": {
    "field_name": "legacy_session_id",
    "new_value": ""
  }
}
```

**Constraints**: None (can be empty or any byte sequence)

---

### `cipher_suites` (ClientHello)

**Applies to**: ClientHello only

**Python Type**: `list[int]`

**Description**: List of cipher suites supported by the client, in order of preference.

**Initialization**: `cipher_suites=[int(x) for x in self._cipher_suites]` (line 1559 in `tls.py`)

Default cipher suites (line 1291-1295):
```python
self._cipher_suites = [
    CipherSuite.AES_256_GCM_SHA384,      # 0x1302
    CipherSuite.AES_128_GCM_SHA256,      # 0x1301
    CipherSuite.CHACHA20_POLY1305_SHA256, # 0x1303
]
```

**Valid Values**: List of cipher suite integers. See [CipherSuite Enum Values](#ciphersuite-enum-values) below.

**Example**:
```python
cipher_suites = [0x1301, 0x1302, 0x1303]  # AES_128_GCM_SHA256, AES_256_GCM_SHA384, CHACHA20_POLY1305_SHA256
```

**JSON Representation**: Array of integers
```json
{
  "mutation": "modify_field",
  "target": "client",
  "fields": {
    "field_name": "cipher_suites",
    "new_value": [4865, 4866, 4867]
  }
}
```

**Constraints**: Must be a non-empty list. Values should be valid CipherSuite enum values.

---

### `cipher_suite` (ServerHello)

**Applies to**: ServerHello only

**Python Type**: `int`

**Description**: Single cipher suite selected by the server from the client's list.

**Initialization**: Negotiated from client's `cipher_suites` list (line 1872-1876 in `tls.py`)

**Valid Values**: Single cipher suite integer. See [CipherSuite Enum Values](#ciphersuite-enum-values) below.

**Example**:
```python
cipher_suite = 0x1302  # AES_256_GCM_SHA384
```

**JSON Representation**: Integer
```json
{
  "mutation": "modify_field",
  "target": "server",
  "fields": {
    "field_name": "cipher_suite",
    "new_value": 4866
  }
}
```

**Constraints**: Must be a valid CipherSuite enum value. Note: This is singular (`cipher_suite`), not plural like ClientHello.

---

### `legacy_compression_methods` (ClientHello)

**Applies to**: ClientHello only

**Python Type**: `list[int]`

**Description**: List of legacy compression methods. For TLS 1.3, this is always `[CompressionMethod.NULL]`.

**Initialization**: `self._legacy_compression_methods: list[int] = [CompressionMethod.NULL]` (line 1297 in `tls.py`)

**Valid Values**: 
- `[0]` for CompressionMethod.NULL (only valid value for TLS 1.3)

**Example**:
```python
legacy_compression_methods = [0]  # NULL compression only
```

**JSON Representation**: Array of integers
```json
{
  "mutation": "modify_field",
  "target": "client",
  "fields": {
    "field_name": "legacy_compression_methods",
    "new_value": [0]
  }
}
```

**Constraints**: For TLS 1.3, should only contain `[0]` (NULL compression).

---

### `compression_method` (ServerHello)

**Applies to**: ServerHello only

**Python Type**: `int`

**Description**: Compression method selected by the server. For TLS 1.3, always `CompressionMethod.NULL`.

**Initialization**: Negotiated from client's `legacy_compression_methods` (line 1877-1881 in `tls.py`)

**Valid Values**: `0` (CompressionMethod.NULL)

**Example**:
```python
compression_method = 0  # NULL compression
```

**JSON Representation**: Integer
```json
{
  "mutation": "modify_field",
  "target": "server",
  "fields": {
    "field_name": "compression_method",
    "new_value": 0
  }
}
```

**Constraints**: Must be `0` for TLS 1.3. Note: This is singular (`compression_method`), not plural like ClientHello.

---

### `alpn_protocols`

**Applies to**: ClientHello only

**Python Type**: `Optional[list[str]]`

**Description**: Application-Layer Protocol Negotiation (ALPN) protocols supported by the client.

**Initialization**: `alpn_protocols=self._alpn_protocols` (line 1561 in `tls.py`)

**Valid Values**: 
- `None` (if no ALPN)
- List of protocol name strings (e.g., `["h3", "h2"]`)

**Example**:
```python
alpn_protocols = ["h3", "h2"]  # HTTP/3 and HTTP/2
alpn_protocols = ["hq-interop"]  # QUIC interop
alpn_protocols = None  # No ALPN
```

**JSON Representation**: Array of strings or `null`
```json
{
  "mutation": "modify_field",
  "target": "client",
  "fields": {
    "field_name": "alpn_protocols",
    "new_value": ["h3", "h2"]
  }
}
```

**Constraints**: Protocol names should be valid ALPN protocol identifiers (typically ASCII strings).

---

### `early_data`

**Applies to**: ClientHello only

**Python Type**: `bool`

**Description**: Indicates whether the client supports 0-RTT (early data).

**Initialization**: Set to `True` if session ticket has `max_early_data_size` (line 1583-1584 in `tls.py`)

**Valid Values**: `true` or `false`

**Example**:
```python
early_data = True   # Supports 0-RTT
early_data = False  # No 0-RTT support
```

**JSON Representation**: Boolean
```json
{
  "mutation": "modify_field",
  "target": "client",
  "fields": {
    "field_name": "early_data",
    "new_value": true
  }
}
```

**Constraints**: None

---

### `key_share` (ClientHello)

**Applies to**: ClientHello only

**Python Type**: `Optional[list[KeyShareEntry]]`

**Description**: List of key share entries containing public keys for key exchange groups.

**Type Definition**: `KeyShareEntry = tuple[int, bytes]`
- First element: Group ID (int) - See [Group Enum Values](#group-enum-values)
- Second element: Public key bytes (bytes) - Format depends on group type

**Initialization**: Built in `_client_send_hello()` (lines 1522-1543 in `tls.py`):
```python
key_share: list[KeyShareEntry] = []
for group in self._supported_groups:
    if group == Group.X25519:
        # Generate X25519 key pair
        key_share.append(encode_public_key(...))
    elif group == Group.X448:
        # Generate X448 key pair
        key_share.append(encode_public_key(...))
    elif group in GROUP_TO_CURVE:
        # Generate EC key pair
        key_share.append(encode_public_key(...))
```

**Valid Values**: 
- `None` (not recommended, handshake will fail)
- List of `KeyShareEntry` tuples: `[(group_id, public_key_bytes), ...]`

**Key Share Entry Structure**:
- **X25519** (Group.X25519 = 0x001D): 32-byte public key (Raw format)
- **X448** (Group.X448 = 0x001E): 56-byte public key (Raw format)
- **EC Groups** (SECP256R1, SECP384R1, SECP521R1): Uncompressed point format
  - SECP256R1 (0x0017): 65 bytes (0x04 + 64 bytes)
  - SECP384R1 (0x0018): 97 bytes (0x04 + 96 bytes)
  - SECP521R1 (0x0019): 133 bytes (0x04 + 132 bytes)

**Example**:
```python
# X25519 key share entry
key_share = [(0x001D, b'\x01' * 32)]  # Group.X25519 with 32-byte key

# Multiple groups
key_share = [
    (0x0017, b'\x04' + b'\x00' * 64),  # SECP256R1
    (0x001D, b'\x01' * 32),            # X25519
]
```

**JSON Representation**: Array of arrays (tuples) or `null`
```json
{
  "mutation": "modify_field",
  "target": "client",
  "fields": {
    "field_name": "key_share",
    "new_value": [
      [29, "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="]
    ]
  }
}
```

**Constraints**: 
- Must have at least one entry for handshake to succeed
- Group IDs must be valid Group enum values
- Public key bytes must match the expected format for the group type
- Cannot be empty list (use `None` instead)

---

### `key_share` (ServerHello)

**Applies to**: ServerHello only

**Python Type**: `Optional[KeyShareEntry]`

**Description**: Single key share entry containing the server's public key for the selected group.

**Type Definition**: `KeyShareEntry = tuple[int, bytes]` (same as ClientHello, but single entry)

**Initialization**: `key_share=encode_public_key(public_key)` (line 2010 in `tls.py`)

**Valid Values**: 
- `None`
- Single `KeyShareEntry` tuple: `(group_id, public_key_bytes)`

**Example**:
```python
key_share = (0x001D, b'\x01' * 32)  # X25519 key share
key_share = None  # No key share (handshake will fail)
```

**JSON Representation**: Array of two elements (tuple) or `null`
```json
{
  "mutation": "modify_field",
  "target": "server",
  "fields": {
    "field_name": "key_share",
    "new_value": [29, "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="]
  }
}
```

**Constraints**: 
- Note: This is a single `KeyShareEntry` (tuple), not a list like ClientHello
- Group ID should match one from client's key_share list
- Public key format must match the group type

---

### `pre_shared_key` (ClientHello)

**Applies to**: ClientHello only

**Python Type**: `Optional[OfferedPsks]`

**Type Definition**: 
```python
@dataclass
class OfferedPsks:
    identities: list[PskIdentity]
    binders: list[bytes]

PskIdentity = tuple[bytes, int]  # (ticket, obfuscated_ticket_age)
```

**Description**: Pre-shared key information for session resumption (0-RTT).

**Initialization**: Created when session ticket is available (lines 1585-1590 in `tls.py`):
```python
hello.pre_shared_key = OfferedPsks(
    identities=[
        (self.session_ticket.ticket, self.session_ticket.obfuscated_age)
    ],
    binders=[bytes(binder_length)],
)
```

**Structure**:
- `identities`: List of `PskIdentity` tuples
  - Each tuple: `(ticket_bytes, obfuscated_ticket_age_int)`
  - `ticket`: Session ticket bytes (typically 64 bytes)
  - `obfuscated_ticket_age`: 32-bit integer (obfuscated age in milliseconds)
- `binders`: List of binder bytes
  - Length matches hash algorithm digest size (32 bytes for SHA256, 48 bytes for SHA384)
  - Binders are computed after serializing the hello message

**Valid Values**: 
- `None` (no PSK)
- `OfferedPsks` dataclass instance

**Example**:
```python
pre_shared_key = OfferedPsks(
    identities=[
        (b'\x01' * 64, 1234567890)  # 64-byte ticket, age
    ],
    binders=[
        b'\x02' * 32  # 32-byte binder (SHA256)
    ]
)
```

**JSON Representation**: Object with `identities` and `binders` arrays
```json
{
  "mutation": "modify_field",
  "target": "client",
  "fields": {
    "field_name": "pre_shared_key",
    "new_value": {
      "identities": [
        {
          "ticket": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
          "obfuscated_ticket_age": 1234567890
        }
      ],
      "binders": [
        "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC"
      ]
    }
  }
}
```

**Constraints**: 
- `identities` and `binders` lists must have the same length
- Binder length must match the hash algorithm digest size
- Pre-shared key extension MUST be the last extension in ClientHello

---

### `pre_shared_key` (ServerHello)

**Applies to**: ServerHello only

**Python Type**: `Optional[int]`

**Description**: Index into the client's PSK identities list (0-based). `None` if no PSK selected.

**Initialization**: Set to `0` if PSK is accepted, `None` otherwise (line 2011 in `tls.py`)

**Valid Values**: 
- `None` (no PSK selected)
- `0` (first identity selected, typically the only one)

**Example**:
```python
pre_shared_key = 0   # Selected first PSK identity
pre_shared_key = None  # No PSK selected
```

**JSON Representation**: Integer or `null`
```json
{
  "mutation": "modify_field",
  "target": "server",
  "fields": {
    "field_name": "pre_shared_key",
    "new_value": 0
  }
}
```

**Constraints**: 
- Must be a valid index into client's `pre_shared_key.identities` list
- Typically `0` if PSK is used
- Note: This is an integer index, not an `OfferedPsks` object like ClientHello

---

### `psk_key_exchange_modes`

**Applies to**: ClientHello only

**Python Type**: `Optional[list[int]]`

**Description**: PSK key exchange modes supported by the client.

**Initialization**: Set if session ticket or callback is available (lines 1563-1567 in `tls.py`)

Default value (line 1298):
```python
self._psk_key_exchange_modes: list[int] = [PskKeyExchangeMode.PSK_DHE_KE]  # [1]
```

**Valid Values**: 
- `None` (no PSK support)
- List of PskKeyExchangeMode enum values

**PskKeyExchangeMode Values**:
- `0` = PSK_KE (PSK key exchange only)
- `1` = PSK_DHE_KE (PSK with (EC)DHE key exchange)

**Example**:
```python
psk_key_exchange_modes = [1]  # PSK_DHE_KE
psk_key_exchange_modes = [0, 1]  # Both modes
psk_key_exchange_modes = None  # No PSK
```

**JSON Representation**: Array of integers or `null`
```json
{
  "mutation": "modify_field",
  "target": "client",
  "fields": {
    "field_name": "psk_key_exchange_modes",
    "new_value": [1]
  }
}
```

**Constraints**: Values must be valid PskKeyExchangeMode enum values (0 or 1).

---

### `server_name`

**Applies to**: ClientHello only

**Python Type**: `Optional[str]`

**Description**: Server Name Indication (SNI) - the hostname the client is connecting to.

**Initialization**: Set from `self._server_name` if not an IP address (lines 1547-1554 in `tls.py`):
```python
try:
    ipaddress.ip_address(self._server_name)
except ValueError:
    server_name = self._server_name  # Valid hostname
else:
    server_name = None  # IP address, cannot use SNI
```

**Valid Values**: 
- `None` (no SNI, e.g., when connecting to IP address)
- Valid hostname string (e.g., `"example.com"`, `"www.example.org"`)

**Example**:
```python
server_name = "example.com"
server_name = "www.example.org"
server_name = None  # No SNI (e.g., IP address)
```

**JSON Representation**: String or `null`
```json
{
  "mutation": "modify_field",
  "target": "client",
  "fields": {
    "field_name": "server_name",
    "new_value": "example.com"
  }
}
```

**Constraints**: 
- Cannot be an IP address (will be set to `None` automatically)
- Should be a valid DNS hostname
- ASCII string

---

### `signature_algorithms`

**Applies to**: ClientHello only

**Python Type**: `Optional[list[int]]`

**Description**: Signature algorithms supported by the client for certificate verification.

**Initialization**: `signature_algorithms=self._signature_algorithms` (line 1569 in `tls.py`)

Default algorithms (lines 1299-1307):
```python
self._signature_algorithms: list[int] = [
    SignatureAlgorithm.ECDSA_SECP256R1_SHA256,  # 0x0403
    SignatureAlgorithm.RSA_PSS_RSAE_SHA256,     # 0x0804
    SignatureAlgorithm.RSA_PKCS1_SHA256,        # 0x0401
    SignatureAlgorithm.ECDSA_SECP384R1_SHA384,  # 0x0503
    SignatureAlgorithm.RSA_PSS_RSAE_SHA384,     # 0x0805
    SignatureAlgorithm.RSA_PKCS1_SHA384,        # 0x0501
    SignatureAlgorithm.RSA_PKCS1_SHA1,          # 0x0201
]
# Plus ED25519/ED448 if supported
```

**Valid Values**: List of SignatureAlgorithm enum values. See [SignatureAlgorithm Enum Values](#signaturealgorithm-enum-values) below.

**Example**:
```python
signature_algorithms = [0x0403, 0x0804, 0x0401]  # ECDSA_SECP256R1_SHA256, RSA_PSS_RSAE_SHA256, RSA_PKCS1_SHA256
```

**JSON Representation**: Array of integers
```json
{
  "mutation": "modify_field",
  "target": "client",
  "fields": {
    "field_name": "signature_algorithms",
    "new_value": [1027, 2052, 1025]
  }
}
```

**Constraints**: Values must be valid SignatureAlgorithm enum values.

---

### `supported_groups`

**Applies to**: ClientHello only

**Python Type**: `Optional[list[int]]`

**Description**: Elliptic curve groups and finite field groups supported by the client for key exchange.

**Initialization**: Built from `self._supported_groups` (line 1570 in `tls.py`)

Default groups (lines 1312-1316):
```python
self._supported_groups = [Group.SECP256R1, Group.SECP384R1]  # [0x0017, 0x0018]
# Plus X25519/X448 if supported
```

**Valid Values**: List of Group enum values. See [Group Enum Values](#group-enum-values) below.

**Example**:
```python
supported_groups = [0x0017, 0x0018, 0x001D]  # SECP256R1, SECP384R1, X25519
```

**JSON Representation**: Array of integers
```json
{
  "mutation": "modify_field",
  "target": "client",
  "fields": {
    "field_name": "supported_groups",
    "new_value": [23, 24, 29]
  }
}
```

**Constraints**: Values must be valid Group enum values. Should match groups in `key_share`.

---

### `supported_versions` (ClientHello)

**Applies to**: ClientHello only

**Python Type**: `Optional[list[int]]`

**Description**: TLS versions supported by the client.

**Initialization**: `supported_versions=self._supported_versions` (line 1571 in `tls.py`)

Default (line 1317):
```python
self._supported_versions = [TLS_VERSION_1_3]  # [0x0304]
```

**TLS Version Constants**:
- `TLS_VERSION_1_2 = 0x0303`
- `TLS_VERSION_1_3 = 0x0304`
- `TLS_VERSION_1_3_DRAFT_28 = 0x7F1C`
- `TLS_VERSION_1_3_DRAFT_27 = 0x7F1B`
- `TLS_VERSION_1_3_DRAFT_26 = 0x7F1A`

**Valid Values**: List of TLS version integers

**Example**:
```python
supported_versions = [0x0304]  # TLS 1.3
supported_versions = [0x0304, 0x7F1C]  # TLS 1.3 and draft 28
```

**JSON Representation**: Array of integers
```json
{
  "mutation": "modify_field",
  "target": "client",
  "fields": {
    "field_name": "supported_versions",
    "new_value": [772]
  }
}
```

**Constraints**: Values should be valid TLS version numbers.

---

### `supported_version` (ServerHello)

**Applies to**: ServerHello only

**Python Type**: `Optional[int]`

**Description**: TLS version selected by the server.

**Initialization**: Negotiated from client's `supported_versions` list (line 2012 in `tls.py`)

**Valid Values**: Single TLS version integer (typically `0x0304` for TLS 1.3)

**Example**:
```python
supported_version = 0x0304  # TLS 1.3
```

**JSON Representation**: Integer
```json
{
  "mutation": "modify_field",
  "target": "server",
  "fields": {
    "field_name": "supported_version",
    "new_value": 772
  }
}
```

**Constraints**: 
- Must be a valid TLS version number
- Should match one from client's `supported_versions` list
- Note: This is singular (`supported_version`), not plural like ClientHello

---

### `other_extensions`

**Applies to**: ClientHello, ServerHello

**Python Type**: `list[Extension]`

**Type Definition**: `Extension = tuple[int, bytes]`
- First element: Extension type ID (int) - See [ExtensionType Enum Values](#extensiontype-enum-values)
- Second element: Extension data bytes (bytes)

**Description**: List of other extensions not explicitly handled as separate fields.

**Initialization**:
- **ClientHello**: `other_extensions=self.handshake_extensions` (line 1572 in `tls.py`)
- **ServerHello**: `other_extensions=[]` (default, line 726 in `tls.py`)

**Valid Values**: List of `Extension` tuples: `[(extension_type, extension_data), ...]`

**Common Extension Types**:
- `0x0039` = QUIC_TRANSPORT_PARAMETERS
- `0xFFA5` = QUIC_TRANSPORT_PARAMETERS_DRAFT
- `65486` = ENCRYPTED_SERVER_NAME

**Example**:
```python
other_extensions = [
    (0x0039, b'\x00\x11\x00\x05...'),  # QUIC transport parameters
    (0xFFA5, b'\x00\x11\x00\x05...'),  # QUIC transport parameters (draft)
]
```

**JSON Representation**: Array of arrays (tuples)
```json
{
  "mutation": "modify_field",
  "target": "client",
  "fields": {
    "field_name": "other_extensions",
    "new_value": [
      [57, "ABEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="]
    ]
  }
}
```

**Constraints**: Extension type IDs should be valid ExtensionType enum values or custom values.

---

## Complex Types Reference

### KeyShareEntry

**Type**: `tuple[int, bytes]`

**Structure**:
- Element 0: `int` - Group ID (see Group enum)
- Element 1: `bytes` - Public key bytes (format depends on group)

**Public Key Formats**:
- **X25519** (0x001D): 32 bytes, Raw format
- **X448** (0x001E): 56 bytes, Raw format
- **SECP256R1** (0x0017): 65 bytes, Uncompressed point (0x04 prefix + 64 bytes)
- **SECP384R1** (0x0018): 97 bytes, Uncompressed point (0x04 prefix + 96 bytes)
- **SECP521R1** (0x0019): 133 bytes, Uncompressed point (0x04 prefix + 132 bytes)

**Python Example**:
```python
key_share_entry = (0x001D, b'\x01' * 32)  # X25519
```

**JSON Example**:
```json
[29, "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="]
```

---

### OfferedPsks

**Type**: `@dataclass`

**Structure**:
```python
@dataclass
class OfferedPsks:
    identities: list[PskIdentity]
    binders: list[bytes]
```

**Fields**:
- `identities`: List of `PskIdentity` tuples
  - Each `PskIdentity = tuple[bytes, int]`
  - `(ticket_bytes, obfuscated_ticket_age)`
- `binders`: List of binder bytes
  - Length: 32 bytes (SHA256) or 48 bytes (SHA384)

**Python Example**:
```python
offered_psks = OfferedPsks(
    identities=[
        (b'\x01' * 64, 1234567890)
    ],
    binders=[
        b'\x02' * 32
    ]
)
```

**JSON Example**:
```json
{
  "identities": [
    {
      "ticket": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
      "obfuscated_ticket_age": 1234567890
    }
  ],
  "binders": [
    "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC"
  ]
}
```

---

### Extension

**Type**: `tuple[int, bytes]`

**Structure**:
- Element 0: `int` - Extension type ID
- Element 1: `bytes` - Extension-specific data

**Python Example**:
```python
extension = (0x0039, b'\x00\x11\x00\x05...')  # QUIC transport parameters
```

**JSON Example**:
```json
[57, "ABEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="]
```

---

### PskIdentity

**Type**: `tuple[bytes, int]`

**Structure**:
- Element 0: `bytes` - Session ticket (typically 64 bytes)
- Element 1: `int` - Obfuscated ticket age (32-bit integer, milliseconds)

**Python Example**:
```python
psk_identity = (b'\x01' * 64, 1234567890)
```

**JSON Example**:
```json
{
  "ticket": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
  "obfuscated_ticket_age": 1234567890
}
```

---

## Enum Values Reference

### CipherSuite Enum Values

| Name | Value (hex) | Value (decimal) | Description |
|------|-------------|-----------------|-------------|
| AES_128_GCM_SHA256 | 0x1301 | 4865 | AES-128-GCM with SHA-256 |
| AES_256_GCM_SHA384 | 0x1302 | 4866 | AES-256-GCM with SHA-384 |
| CHACHA20_POLY1305_SHA256 | 0x1303 | 4867 | ChaCha20-Poly1305 with SHA-256 |
| EMPTY_RENEGOTIATION_INFO_SCSV | 0x00FF | 255 | Legacy renegotiation indicator |

**Location**: `tls.py` lines 294-298

---

### Group Enum Values

| Name | Value (hex) | Value (decimal) | Key Size (bytes) |
|------|-------------|-----------------|------------------|
| SECP256R1 | 0x0017 | 23 | 65 (uncompressed point) |
| SECP384R1 | 0x0018 | 24 | 97 (uncompressed point) |
| SECP521R1 | 0x0019 | 25 | 133 (uncompressed point) |
| X25519 | 0x001D | 29 | 32 (raw) |
| X448 | 0x001E | 30 | 56 (raw) |
| GREASE | 0xAAAA | 43690 | Variable |

**Location**: `tls.py` lines 323-329

---

### SignatureAlgorithm Enum Values

| Name | Value (hex) | Value (decimal) | Description |
|------|-------------|-----------------|-------------|
| ECDSA_SECP256R1_SHA256 | 0x0403 | 1027 | ECDSA with secp256r1 and SHA-256 |
| ECDSA_SECP384R1_SHA384 | 0x0503 | 1283 | ECDSA with secp384r1 and SHA-384 |
| ECDSA_SECP521R1_SHA512 | 0x0603 | 1539 | ECDSA with secp521r1 and SHA-512 |
| RSA_PSS_RSAE_SHA256 | 0x0804 | 2052 | RSA-PSS with SHA-256 |
| RSA_PSS_RSAE_SHA384 | 0x0805 | 2053 | RSA-PSS with SHA-384 |
| RSA_PSS_RSAE_SHA512 | 0x0806 | 2054 | RSA-PSS with SHA-512 |
| RSA_PKCS1_SHA256 | 0x0401 | 1025 | RSA-PKCS1 with SHA-256 |
| RSA_PKCS1_SHA384 | 0x0501 | 1281 | RSA-PKCS1 with SHA-384 |
| RSA_PKCS1_SHA512 | 0x0601 | 1537 | RSA-PKCS1 with SHA-512 |
| ED25519 | 0x0807 | 2055 | Ed25519 |
| ED448 | 0x0808 | 2056 | Ed448 |
| RSA_PKCS1_SHA1 | 0x0201 | 513 | RSA-PKCS1 with SHA-1 (legacy) |

**Location**: `tls.py` lines 356-375

---

### PskKeyExchangeMode Enum Values

| Name | Value | Description |
|------|-------|-------------|
| PSK_KE | 0 | PSK key exchange only |
| PSK_DHE_KE | 1 | PSK with (EC)DHE key exchange |

**Location**: `tls.py` lines 351-353

---

### CompressionMethod Enum Values

| Name | Value | Description |
|------|-------|-------------|
| NULL | 0 | No compression (only valid value for TLS 1.3) |

**Location**: `tls.py` lines 301-302

---

### ExtensionType Enum Values (Common)

| Name | Value (hex) | Value (decimal) | Description |
|------|-------------|-----------------|-------------|
| SERVER_NAME | 0x0000 | 0 | Server Name Indication |
| SUPPORTED_GROUPS | 0x000A | 10 | Supported groups |
| SIGNATURE_ALGORITHMS | 0x000D | 13 | Signature algorithms |
| ALPN | 0x0010 | 16 | Application-Layer Protocol Negotiation |
| KEY_SHARE | 0x0033 | 51 | Key share |
| PRE_SHARED_KEY | 0x0029 | 41 | Pre-shared key |
| PSK_KEY_EXCHANGE_MODES | 0x002D | 45 | PSK key exchange modes |
| SUPPORTED_VERSIONS | 0x002B | 43 | Supported versions |
| EARLY_DATA | 0x002A | 42 | Early data |
| QUIC_TRANSPORT_PARAMETERS | 0x0039 | 57 | QUIC transport parameters |
| QUIC_TRANSPORT_PARAMETERS_DRAFT | 0xFFA5 | 65445 | QUIC transport parameters (draft) |
| ENCRYPTED_SERVER_NAME | 0xFFCE | 65486 | Encrypted server name |

**Location**: `tls.py` lines 305-320

---

### TLS Version Constants

| Constant | Value (hex) | Value (decimal) | Description |
|----------|-------------|-----------------|-------------|
| TLS_VERSION_1_2 | 0x0303 | 771 | TLS 1.2 |
| TLS_VERSION_1_3 | 0x0304 | 772 | TLS 1.3 |
| TLS_VERSION_1_3_DRAFT_28 | 0x7F1C | 32540 | TLS 1.3 Draft 28 |
| TLS_VERSION_1_3_DRAFT_27 | 0x7F1B | 32539 | TLS 1.3 Draft 27 |
| TLS_VERSION_1_3_DRAFT_26 | 0x7F1A | 32538 | TLS 1.3 Draft 26 |

**Location**: `tls.py` lines 48-52

---

## JSON Mutation Examples

### Example 1: Modify cipher_suites

```json
{
  "mutation": "modify_field",
  "target": "client",
  "fields": {
    "field_name": "cipher_suites",
    "new_value": [4865, 4866]
  }
}
```

### Example 2: Modify key_share (ClientHello)

```json
{
  "mutation": "modify_field",
  "target": "client",
  "fields": {
    "field_name": "key_share",
    "new_value": [
      [29, "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="]
    ]
  }
}
```

### Example 3: Modify pre_shared_key (ClientHello)

```json
{
  "mutation": "modify_field",
  "target": "client",
  "fields": {
    "field_name": "pre_shared_key",
    "new_value": {
      "identities": [
        {
          "ticket": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
          "obfuscated_ticket_age": 1234567890
        }
      ],
      "binders": [
        "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC"
      ]
    }
  }
}
```

### Example 4: Remove server_name

```json
{
  "mutation": "remove_field",
  "target": "client",
  "fields": {
    "field_name": "server_name"
  }
}
```

### Example 5: Modify cipher_suite (ServerHello)

```json
{
  "mutation": "modify_field",
  "target": "server",
  "fields": {
    "field_name": "cipher_suite",
    "new_value": 4866
  }
}
```

---

## Code References

### ClientHello Initialization
- **Location**: `src/aioquic/tls.py`, `_client_send_hello()` method (lines 1521-1621)
- **Key lines**:
  - Random: line 1557 (`self.client_random`)
  - Legacy session ID: line 1558 (`self.legacy_session_id`)
  - Cipher suites: line 1559 (`[int(x) for x in self._cipher_suites]`)
  - Key share: lines 1522-1543 (generated from supported groups)
  - ALPN: line 1561 (`self._alpn_protocols`)
  - Server name: lines 1547-1554 (filtered if IP address)
  - Pre-shared key: lines 1585-1590 (if session ticket available)

### ServerHello Initialization
- **Location**: `src/aioquic/tls.py`, `_server_handle_hello()` method (lines 1868-2090)
- **Key lines**:
  - Random: line 2006 (`self.server_random`)
  - Legacy session ID: line 2007 (`self.legacy_session_id`)
  - Cipher suite: line 2008 (negotiated from client)
  - Compression method: line 2009 (negotiated from client)
  - Key share: line 2010 (`encode_public_key(public_key)`)
  - Supported version: line 2012 (negotiated from client)

### Type Definitions
- **KeyShareEntry**: `tls.py` line 489 (`tuple[int, bytes]`)
- **OfferedPsks**: `tls.py` lines 525-528 (`@dataclass`)
- **PskIdentity**: `tls.py` line 522 (`tuple[bytes, int]`)
- **Extension**: `tls.py` line 574 (`tuple[int, bytes]`)

---

## Notes on JSON Representation

When using JSON for mutations, complex types need special representation:

1. **Tuples**: Represented as JSON arrays `[element1, element2]`
2. **Bytes**: Represented as base64-encoded strings or hex strings
3. **Dataclasses**: Represented as JSON objects with field names
4. **Nested structures**: Follow the same rules recursively

The mutator's `modify_field` mutation currently uses `setattr()` which directly assigns the Python value. For JSON-based mutations, you would need to:
1. Parse JSON into Python objects
2. Convert base64/hex strings to bytes
3. Construct tuples and dataclasses from JSON structures
4. Then apply the mutation

This documentation provides the structure needed to implement proper JSON parsing for complex types.
