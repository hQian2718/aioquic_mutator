import json
from unittest import TestCase

from aioquic.tls import ClientHello, ServerHello
from mutator.mutator import Mutator


def create_mutator(mutation_type, target, fields):
    """Helper to create mutator for tests"""
    mutation_params = [
        {"mutation_type": mutation_type, "target": target, "fields": fields}
    ]
    return Mutator(mutation_params)


class MutatorTest(TestCase):
    def test_mutator_parse_mutation_params_valid(self):
        """Test parsing valid JSON mutation parameters"""
        param_str = json.dumps(
            [
                {
                    "mutation": "identity",
                    "target": "client",
                    "fields": {},
                }
            ]
        )
        result = Mutator.parse_mutation_params(param_str)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["mutation_type"], "identity")
        self.assertEqual(result[0]["target"], "client")

    def test_mutator_parse_mutation_params_invalid_mutation_type(self):
        """Test parsing with invalid mutation type"""
        param_str = json.dumps(
            [{"mutation": "invalid_type", "target": "client", "fields": {}}]
        )
        with self.assertRaises(ValueError) as cm:
            Mutator.parse_mutation_params(param_str)
        self.assertIn("Invalid mutation type", str(cm.exception))

    def test_mutator_parse_mutation_params_invalid_target(self):
        """Test parsing with invalid target"""
        param_str = json.dumps(
            [{"mutation": "identity", "target": "invalid", "fields": {}}]
        )
        with self.assertRaises(ValueError) as cm:
            Mutator.parse_mutation_params(param_str)
        self.assertIn("Invalid target", str(cm.exception))

    def test_mutator_parse_mutation_params_missing_required_field(self):
        """Test parsing with missing required field"""
        param_str = json.dumps(
            [{"mutation": "remove_field", "target": "client", "fields": {}}]
        )
        with self.assertRaises(ValueError) as cm:
            Mutator.parse_mutation_params(param_str)
        self.assertIn("Missing required field", str(cm.exception))

    def test_mutator_parse_mutation_params_invalid_field_name(self):
        """Test parsing with invalid field name"""
        param_str = json.dumps(
            [
                {
                    "mutation": "remove_field",
                    "target": "client",
                    "fields": {"field_name": "invalid_field"},
                }
            ]
        )
        with self.assertRaises(ValueError) as cm:
            Mutator.parse_mutation_params(param_str)
        self.assertIn("Invalid field name", str(cm.exception))

    def test_mutator_identity(self):
        """Test that identity mutation leaves hello messages unchanged"""
        mutator = create_mutator("identity", "client", {})
        hello = ClientHello(
            random=b"test" * 8,
            legacy_session_id=b"session",
            cipher_suites=[1, 2, 3],
            legacy_compression_methods=[0],
            server_name="example.com",
        )
        mutated = mutator.mutate_client_hello(hello)
        self.assertEqual(mutated.server_name, "example.com")
        self.assertEqual(mutated.cipher_suites, [1, 2, 3])

    def test_mutator_remove_field_client(self):
        """Test removing fields from ClientHello"""
        mutator = create_mutator("remove_field", "client", {"field_name": "server_name"})
        hello = ClientHello(
            random=b"test" * 8,
            legacy_session_id=b"session",
            cipher_suites=[1, 2, 3],
            legacy_compression_methods=[0],
            server_name="example.com",
        )
        mutated = mutator.mutate_client_hello(hello)
        self.assertIsNone(mutated.server_name)

    def test_mutator_remove_field_server(self):
        """Test removing fields from ServerHello"""
        mutator = create_mutator("remove_field", "server", {"field_name": "key_share"})
        hello = ServerHello(
            random=b"test" * 8,
            legacy_session_id=b"session",
            cipher_suite=1,
            compression_method=0,
            key_share=(1, b"key_data"),
        )
        mutated = mutator.mutate_server_hello(hello)
        self.assertIsNone(mutated.key_share)

    def test_mutator_modify_field_client(self):
        """Test modifying fields in ClientHello"""
        mutator = create_mutator(
            "modify_field", "client", {"field_name": "server_name", "new_value": "modified.com"}
        )
        hello = ClientHello(
            random=b"test" * 8,
            legacy_session_id=b"session",
            cipher_suites=[1, 2, 3],
            legacy_compression_methods=[0],
            server_name="example.com",
        )
        mutated = mutator.mutate_client_hello(hello)
        self.assertEqual(mutated.server_name, "modified.com")

    def test_mutator_modify_field_server(self):
        """Test modifying fields in ServerHello"""
        mutator = create_mutator(
            "modify_field", "server", {"field_name": "cipher_suite", "new_value": 999}
        )
        hello = ServerHello(
            random=b"test" * 8,
            legacy_session_id=b"session",
            cipher_suite=1,
            compression_method=0,
        )
        mutated = mutator.mutate_server_hello(hello)
        self.assertEqual(mutated.cipher_suite, 999)

    def test_mutator_target_filtering(self):
        """Test that client mutations only affect ClientHello and server mutations only affect ServerHello"""
        # Create mutator with client mutation
        client_mutator = create_mutator("remove_field", "client", {"field_name": "server_name"})
        server_mutator = create_mutator("remove_field", "server", {"field_name": "key_share"})

        client_hello = ClientHello(
            random=b"test" * 8,
            legacy_session_id=b"session",
            cipher_suites=[1, 2, 3],
            legacy_compression_methods=[0],
            server_name="example.com",
        )
        server_hello = ServerHello(
            random=b"test" * 8,
            legacy_session_id=b"session",
            cipher_suite=1,
            compression_method=0,
            key_share=(1, b"key_data"),
        )

        # Client mutator should not affect server hello
        mutated_server = client_mutator.mutate_server_hello(server_hello)
        self.assertIsNotNone(mutated_server.key_share)

        # Server mutator should not affect client hello
        mutated_client = server_mutator.mutate_client_hello(client_hello)
        self.assertIsNotNone(mutated_client.server_name)

    def test_mutator_multiple_mutations(self):
        """Test mutator with multiple mutation steps"""
        mutation_params = [
            {"mutation_type": "remove_field", "target": "client", "fields": {"field_name": "server_name"}},
            {"mutation_type": "modify_field", "target": "client", "fields": {"field_name": "alpn_protocols", "new_value": ["h3"]}},
        ]
        mutator = Mutator(mutation_params)
        hello = ClientHello(
            random=b"test" * 8,
            legacy_session_id=b"session",
            cipher_suites=[1, 2, 3],
            legacy_compression_methods=[0],
            server_name="example.com",
            alpn_protocols=["h2", "h3"],
        )
        mutated = mutator.mutate_client_hello(hello)
        self.assertIsNone(mutated.server_name)
        self.assertEqual(mutated.alpn_protocols, ["h3"])
