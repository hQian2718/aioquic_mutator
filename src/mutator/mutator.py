from aioquic.tls import ClientHello, ServerHello
import json
MUTATIONS_FORMAT = {
    "identity": [],
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
    "other_extensions"
]

class Mutator:
    """
    The Mutator class is responsible for mutating QUIC/TLS messages
    according to specified mutation parameters.

    :param mutation_params: A list of lists containing mutation steps.
    Each mutation step is a dictionary with the following format:
        {
            "mutation": "<mutation_type>",
            "target": "<client / server>",
            "fields": {
                "<field_name1>": "<value1>",
                "<field_name2>": "<value2>",
                ...
            }
        }
    You can build this list with validation using the static method
        `parse_mutation_params`.

    TODO: Currently, there is no validation for the mutation parameter
    'new value'. The fields in QUIC HELLO messages are complex.
    """
    def __init__(self, mutation_params: list[dict[str, str | dict[str, str]]]):
        self.mutation_params = mutation_params
    
    def mutate_client_hello(self, client_hello: ClientHello) -> ClientHello:
        """
        Mutate the ClientHello message based on mutation_params.
        """
        for mutation in self.mutation_params:
            if mutation["target"] != "client":
                continue
            
            mutation_type = mutation["mutation_type"]
            fields = mutation["fields"]
            if mutation_type == "remove_field":
                field_name = fields["field_name"]
                if hasattr(client_hello, field_name):
                    setattr(client_hello, field_name, None)
            elif mutation_type == "modify_field":
                field_name = fields["field_name"]
                new_value = fields["new_value"]
                if hasattr(client_hello, field_name):
                    setattr(client_hello, field_name, new_value)
            if mutation_type == "identity":
                pass  # No changes
            # Additional mutation types can be implemented here

        return client_hello  # Return mutated ClientHello

    def mutate_server_hello(self, server_hello: ServerHello) -> ServerHello:
        """
        Mutate the ServerHello message based on mutation_params.
        """
        for mutation in self.mutation_params:
            if mutation["target"] != "server":
                continue
            
            mutation_type = mutation["mutation_type"]
            fields = mutation["fields"]
            if mutation_type == "remove_field":
                field_name = fields["field_name"]
                if hasattr(server_hello, field_name):
                    setattr(server_hello, field_name, None)
            elif mutation_type == "modify_field":
                field_name = fields["field_name"]
                new_value = fields["new_value"]
                if hasattr(server_hello, field_name):
                    setattr(server_hello, field_name, new_value)
            if mutation_type == "identity":
                pass  # No changes
            # Additional mutation types can be implemented here
        return server_hello  # Return mutated ServerHello
    
    @staticmethod
    def parse_mutation_params(param_str: str) -> list[dict[str, str | dict[str, str]]]:
        """
        Parse mutation parameters from a JSON string.
        :param param_str: JSON string representing mutation parameters.
        :return: List of tuples containing mutation type and fields.
        :raises ValueError: If the parameters are invalid.

        Each mutation has the following format:
        {
            "mutation": "<mutation_type>",
            "target": "<client / server>",
            "fields": {
                "<field_name1>": "<value1>",
                "<field_name2>": "<value2>",
                ...
            }
        } 
        """

        param_json = json.loads(param_str)
        mutation_list = []

        for mutation in param_json:
            mutation_params = {}
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
                    raise ValueError(f"Missing required field '{field}' for mutation type '{mutation_type}'")
                if field == "field_name" and fields[field] not in ALLOWED_FIELD_NAMES:
                    raise ValueError(f"Invalid field name: {fields[field]}")
                if field == "packet_type" and fields[field] not in ALLOWED_PACKET_TYPES:
                    raise ValueError(f"Invalid packet type: {fields[field]}")
            
            mutation_params["mutation_type"] = mutation_type
            mutation_params["target"] = target
            mutation_params["fields"] = fields
            mutation_list.append(mutation_params)
        
        return mutation_list
            
def main():
    # Test parsing function
    test_param_str = '''
    [
        {
            "mutation": "remove_field",
            "target": "client",
            "fields": {
                "field_name": "alpn_protocols"
            }
        },
        {
            "mutation": "modify_field",
            "target": "server", 
            "fields": {
                "field_name": "random",
                "new_value": "deadbeef"
            }
        }
    ]
    '''
    try:
        mutations = Mutator.parse_mutation_params(test_param_str)
        print("Parsed mutation parameters successfully:")
        mutator = Mutator(mutations)
    except ValueError as e:
        print(f"Error parsing mutation parameters: {e}")    

if __name__ == "__main__":
    main()