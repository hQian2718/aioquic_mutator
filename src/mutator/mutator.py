import json
from dataclasses import dataclass
from typing import Any

from aioquic.tls import ClientHello, ServerHello

MUTATIONS_FORMAT = {
    "remove_field": ["field_name"],
    "modify_field": ["field_name", "new_value"],
    "send_additional_packet": ["packet_type", "packet_content"],
}

ALLOWED_PACKET_TYPES = [
    "ClientHello",
    "ServerHello",
]

# See ClientHello, ServerHello classes in aioquic/tls.py for field names
ALLOWED_FIELD_NAMES = [
    "random",
    "legacy_session_id",
    "cipher_suites",
    "legacy_compression_methods",
    "alpn_protocols",
    "early_data",
    "key_share",
    "pre_shared_key",
    "psk_key_exchange_modes",
    "server_name",
    "signature_algorithms",
    "supported_groups",
    "supported_versions",
    "other_extensions",
]


@dataclass
class Mutation:
    mutation_type: str
    target: str
    field_name: str
    new_value: Any = None


def _parse_bytes(value: Any) -> bytes:
    if not isinstance(value, str):
        raise ValueError(
            f"Expected hex string for bytes field, got {type(value).__name__}"
        )
    return bytes.fromhex(value)


def _parse_int(value: Any) -> int:
    """Parse an integer, accepting decimal ints or hex strings like '0xdeadbeef'."""
    if isinstance(value, str):
        return int(value, 0)
    return int(value)


def _parse_key_share_entry(value: Any) -> tuple[int, bytes]:
    if not (isinstance(value, list) and len(value) == 2):
        raise ValueError("key_share entry must be [int, hex_string]")
    return (_parse_int(value[0]), _parse_bytes(value[1]))


def _parse_new_value(field_name: str, target: str, raw_value: Any) -> Any:
    """Parse new_value from JSON into the correct Python type for the given field."""
    if field_name in ("random", "legacy_session_id"):
        return _parse_bytes(raw_value)

    if field_name in (
        "cipher_suites",
        "legacy_compression_methods",
        "psk_key_exchange_modes",
        "signature_algorithms",
        "supported_versions",
        "supported_groups",
    ):
        if not isinstance(raw_value, list):
            raise ValueError(f"Expected list for field '{field_name}'")
        return [_parse_int(v) for v in raw_value]

    if field_name == "alpn_protocols":
        if not isinstance(raw_value, list):
            raise ValueError("Expected list for field 'alpn_protocols'")
        return [str(v) for v in raw_value]

    if field_name == "early_data":
        if isinstance(raw_value, bool):
            return raw_value
        if isinstance(raw_value, str):
            if raw_value.lower() == "true":
                return True
            if raw_value.lower() == "false":
                return False
        raise ValueError(
            "Expected bool or 'true'/'false' string for field 'early_data'"
        )

    if field_name == "key_share":
        if target == "client":
            if not isinstance(raw_value, list):
                raise ValueError("Expected list for client 'key_share'")
            return [_parse_key_share_entry(e) for e in raw_value]
        else:  # server: single KeyShareEntry
            return _parse_key_share_entry(raw_value)

    if field_name == "other_extensions":
        if not isinstance(raw_value, list):
            raise ValueError("Expected list for field 'other_extensions'")
        return [_parse_key_share_entry(e) for e in raw_value]

    # server_name, pre_shared_key, etc.: pass through as-is
    return raw_value


class Mutator:
    """
    The Mutator class is responsible for mutating QUIC/TLS messages
    according to specified mutation parameters.

    :param mutation_params: A list of Mutation dataclass instances.
    Each mutation has the following fields:
        - mutation_type: str  ("remove_field", "modify_field", "send_additional_packet")
        - target: str         ("client" or "server")
        - field_name: str     Field to modify or remove
        - new_value: Any      New value for modify_field mutations

    For JSON input, use the static method `parse_mutation_params`.

    JSON format for bytes fields: hex string (e.g. "deadbeef")
    JSON format for key_share/other_extensions entry: [int, "hexstring"]
    """

    def __init__(self, mutation_params: list[Mutation]):
        self.mutation_params = mutation_params

    def mutate_client_hello(self, client_hello: ClientHello) -> ClientHello:
        """
        Mutate the ClientHello message based on mutation_params.
        """
        for mutation in self.mutation_params:
            if mutation.target != "client":
                continue

            mutation_type = mutation.mutation_type
            if mutation_type == "remove_field":
                if hasattr(client_hello, mutation.field_name):
                    setattr(client_hello, mutation.field_name, None)
            elif mutation_type == "modify_field":
                if hasattr(client_hello, mutation.field_name):
                    setattr(client_hello, mutation.field_name, mutation.new_value)
            # Additional mutation types can be implemented here

        return client_hello

    def mutate_server_hello(self, server_hello: ServerHello) -> ServerHello:
        """
        Mutate the ServerHello message based on mutation_params.
        """
        for mutation in self.mutation_params:
            if mutation.target != "server":
                continue

            mutation_type = mutation.mutation_type
            if mutation_type == "remove_field":
                if hasattr(server_hello, mutation.field_name):
                    setattr(server_hello, mutation.field_name, None)
            elif mutation_type == "modify_field":
                if hasattr(server_hello, mutation.field_name):
                    setattr(server_hello, mutation.field_name, mutation.new_value)
            # Additional mutation types can be implemented here

        return server_hello

    @staticmethod
    def parse_mutation_params(param_str: str) -> list[Mutation]:
        """
        Parse mutation parameters from a JSON string.
        :param param_str: JSON string representing mutation parameters.
        :return: List of Mutation dataclass instances.
        :raises ValueError: If the parameters are invalid.

        Each mutation has the following format:
        {
            "mutation": "<mutation_type>",
            "target": "<client / server>",
            "fields": {
                "field_name": "<field_name>",
                "new_value": <value>
            }
        }

        For bytes fields (random, legacy_session_id), new_value must be a hex string.
        For key_share/other_extensions entries, each entry is [int, "hexstring"].
        """
        param_json = json.loads(param_str)
        mutation_list = []

        for mutation in param_json:
            mutation_type = mutation.get("mutation")
            target = mutation.get("target")
            fields = mutation.get("fields", {})

            if mutation_type not in MUTATIONS_FORMAT.keys():
                raise ValueError(f"Invalid mutation type: {mutation_type}")
            if target not in ["client", "server"]:
                raise ValueError(f"Invalid target: {target}")

            # Check required fields per mutation type
            required_fields = MUTATIONS_FORMAT[mutation_type]
            for field in required_fields:
                if field not in fields:
                    raise ValueError(
                        f"Missing required field '{field}' "
                        f"for mutation type '{mutation_type}'"
                    )
                if field == "field_name" and fields[field] not in ALLOWED_FIELD_NAMES:
                    raise ValueError(f"Invalid field name: {fields[field]}")
                if field == "packet_type" and fields[field] not in ALLOWED_PACKET_TYPES:
                    raise ValueError(f"Invalid packet type: {fields[field]}")

            field_name = fields.get("field_name", "")
            new_value = None
            if mutation_type == "modify_field":
                new_value = _parse_new_value(field_name, target, fields["new_value"])

            mutation_entry = Mutation(
                mutation_type=mutation_type,
                target=target,
                field_name=field_name,
                new_value=new_value,
            )
            mutation_list.append(mutation_entry)

        return mutation_list


def main() -> None:
    # Test parsing function
    test_param_str = """
    [
        {
            "mutation": "remove_field",
            "target": "client",
            "fields": {
                "field_name": "server_name"
            }
        }
    ]
    """
    try:
        mutations = Mutator.parse_mutation_params(test_param_str)
        print("Parsed mutation parameters successfully:")
        for m in mutations:
            print(f"  {m}")
    except ValueError as e:
        print(f"Error parsing mutation parameters: {e}")


if __name__ == "__main__":
    main()
