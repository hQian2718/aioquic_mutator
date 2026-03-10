import json
from unittest import TestCase

from aioquic.tls import ClientHello, ServerHello

from mutator.mutator import Mutation, Mutator


def create_mutator(mutation_type, target, field_name="", new_value=None):
    """Helper to create mutator for tests"""
    mutation = Mutation(
        mutation_type=mutation_type,
        target=target,
        field_name=field_name,
        new_value=new_value,
    )
    return Mutator([mutation])


def make_modify_json(field_name, new_value, target="client"):
    """Helper to build a modify_field JSON string for parse_mutation_params."""
    return json.dumps([{
        "mutation": "modify_field",
        "target": target,
        "fields": {"field_name": field_name, "new_value": new_value},
    }])


class MutatorTest(TestCase):
    def test_mutator_parse_mutation_params_valid(self):
        """Test parsing valid JSON mutation parameters"""
        param_str = json.dumps(
            [
                {
                    "mutation": "remove_field",
                    "target": "client",
                    "fields": {"field_name": "server_name"},
                }
            ]
        )
        result = Mutator.parse_mutation_params(param_str)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].mutation_type, "remove_field")
        self.assertEqual(result[0].target, "client")
        self.assertEqual(result[0].field_name, "server_name")

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
            [{"mutation": "remove_field", "target": "invalid",
              "fields": {"field_name": "server_name"}}]
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

    def test_mutator_remove_field_client(self):
        """Test removing fields from ClientHello"""
        mutator = create_mutator(
            "remove_field", "client", field_name="server_name"
        )
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
        mutator = create_mutator("remove_field", "server", field_name="key_share")
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
            "modify_field",
            "client",
            field_name="server_name",
            new_value="modified.com",
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
            "modify_field", "server", field_name="cipher_suite", new_value=999
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
        """Test that client mutations only affect ClientHello and
        server mutations only affect ServerHello"""
        client_mutator = create_mutator(
            "remove_field", "client", field_name="server_name"
        )
        server_mutator = create_mutator(
            "remove_field", "server", field_name="key_share"
        )

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
            Mutation(
                mutation_type="remove_field",
                target="client",
                field_name="server_name",
            ),
            Mutation(
                mutation_type="modify_field",
                target="client",
                field_name="alpn_protocols",
                new_value=["h3"],
            ),
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


# ---------------------------------------------------------------------------
# TDD tests for parse_mutation_params typed field parsing
# ---------------------------------------------------------------------------

class ParseModifyFieldTest(TestCase):
    """Tests for correct type parsing of modify_field new_value in
    parse_mutation_params. Each field also has a companion invalid-type test."""

    # --- cipher_suites ---
    def test_parse_cipher_suites_valid(self):
        result = Mutator.parse_mutation_params(
            make_modify_json("cipher_suites", [4865, 4866])
        )
        self.assertEqual(result[0].new_value, [4865, 4866])
        self.assertIsInstance(result[0].new_value[0], int)

    def test_parse_cipher_suites_invalid_non_list(self):
        with self.assertRaises((ValueError, TypeError)):
            Mutator.parse_mutation_params(make_modify_json("cipher_suites", "not_a_list"))

    # --- legacy_compression_methods ---
    def test_parse_legacy_compression_methods_valid(self):
        result = Mutator.parse_mutation_params(
            make_modify_json("legacy_compression_methods", [0])
        )
        self.assertEqual(result[0].new_value, [0])

    def test_parse_legacy_compression_methods_invalid_non_list(self):
        with self.assertRaises((ValueError, TypeError)):
            Mutator.parse_mutation_params(
                make_modify_json("legacy_compression_methods", 0)
            )

    # --- alpn_protocols ---
    def test_parse_alpn_protocols_valid(self):
        result = Mutator.parse_mutation_params(
            make_modify_json("alpn_protocols", ["h3", "http/1.1"])
        )
        self.assertEqual(result[0].new_value, ["h3", "http/1.1"])
        self.assertIsInstance(result[0].new_value[0], str)

    def test_parse_alpn_protocols_invalid_non_list(self):
        with self.assertRaises((ValueError, TypeError)):
            Mutator.parse_mutation_params(make_modify_json("alpn_protocols", "h3"))

    # --- early_data ---
    def test_parse_early_data_true(self):
        result = Mutator.parse_mutation_params(make_modify_json("early_data", True))
        self.assertIs(result[0].new_value, True)

    def test_parse_early_data_false(self):
        result = Mutator.parse_mutation_params(make_modify_json("early_data", False))
        self.assertIs(result[0].new_value, False)

    def test_parse_early_data_string_true(self):
        result = Mutator.parse_mutation_params(make_modify_json("early_data", "true"))
        self.assertIs(result[0].new_value, True)

    def test_parse_early_data_string_false(self):
        result = Mutator.parse_mutation_params(make_modify_json("early_data", "False"))
        self.assertIs(result[0].new_value, False)

    def test_parse_early_data_invalid_int(self):
        with self.assertRaises((ValueError, TypeError)):
            Mutator.parse_mutation_params(make_modify_json("early_data", 1))

    # --- key_share (client) ---
    def test_parse_key_share_client_valid(self):
        result = Mutator.parse_mutation_params(
            make_modify_json("key_share", [[23, "deadbeef"]], target="client")
        )
        self.assertEqual(result[0].new_value, [(23, bytes.fromhex("deadbeef"))])

    def test_parse_key_share_client_invalid_non_list(self):
        with self.assertRaises((ValueError, TypeError)):
            Mutator.parse_mutation_params(
                make_modify_json("key_share", "not_a_list", target="client")
            )

    def test_parse_key_share_client_invalid_bad_entry(self):
        # Entry is missing the bytes part
        with self.assertRaises((ValueError, TypeError)):
            Mutator.parse_mutation_params(
                make_modify_json("key_share", [[23]], target="client")
            )

    # --- key_share (server) ---
    def test_parse_key_share_server_valid(self):
        result = Mutator.parse_mutation_params(
            make_modify_json("key_share", [29, "cafebabe"], target="server")
        )
        self.assertEqual(result[0].new_value, (29, bytes.fromhex("cafebabe")))

    def test_parse_key_share_server_invalid_wrong_length(self):
        with self.assertRaises((ValueError, TypeError)):
            Mutator.parse_mutation_params(
                make_modify_json("key_share", [29], target="server")
            )

    # --- psk_key_exchange_modes ---
    def test_parse_psk_key_exchange_modes_valid(self):
        result = Mutator.parse_mutation_params(
            make_modify_json("psk_key_exchange_modes", [0, 1])
        )
        self.assertEqual(result[0].new_value, [0, 1])

    def test_parse_psk_key_exchange_modes_invalid_non_list(self):
        with self.assertRaises((ValueError, TypeError)):
            Mutator.parse_mutation_params(
                make_modify_json("psk_key_exchange_modes", 0)
            )

    # --- signature_algorithms ---
    def test_parse_signature_algorithms_valid(self):
        result = Mutator.parse_mutation_params(
            make_modify_json("signature_algorithms", [1027, 2052])
        )
        self.assertEqual(result[0].new_value, [1027, 2052])

    def test_parse_signature_algorithms_invalid_non_list(self):
        with self.assertRaises((ValueError, TypeError)):
            Mutator.parse_mutation_params(
                make_modify_json("signature_algorithms", 1027)
            )

    # --- supported_versions ---
    def test_parse_supported_versions_valid(self):
        result = Mutator.parse_mutation_params(
            make_modify_json("supported_versions", [772])  # 0x0304 = TLS 1.3
        )
        self.assertEqual(result[0].new_value, [772])

    def test_parse_supported_versions_invalid_non_list(self):
        with self.assertRaises((ValueError, TypeError)):
            Mutator.parse_mutation_params(
                make_modify_json("supported_versions", 772)
            )

    # --- supported_groups ---
    def test_parse_supported_groups_valid(self):
        result = Mutator.parse_mutation_params(
            make_modify_json("supported_groups", [29, 23])
        )
        self.assertEqual(result[0].new_value, [29, 23])

    def test_parse_supported_groups_invalid_non_list(self):
        with self.assertRaises((ValueError, TypeError)):
            Mutator.parse_mutation_params(make_modify_json("supported_groups", 29))

    # --- other_extensions ---
    def test_parse_other_extensions_valid(self):
        result = Mutator.parse_mutation_params(
            make_modify_json("other_extensions", [[42, "aabb"]])
        )
        self.assertEqual(result[0].new_value, [(42, b"\xaa\xbb")])

    def test_parse_other_extensions_invalid_bad_entry(self):
        with self.assertRaises((ValueError, TypeError)):
            Mutator.parse_mutation_params(
                make_modify_json("other_extensions", [[42]])
            )

    def test_parse_other_extensions_invalid_non_list(self):
        with self.assertRaises((ValueError, TypeError)):
            Mutator.parse_mutation_params(
                make_modify_json("other_extensions", "not_a_list")
            )

    # --- random ---
    def test_parse_random_valid(self):
        result = Mutator.parse_mutation_params(
            make_modify_json("random", "deadbeefcafe" + "00" * 26)
        )
        self.assertIsInstance(result[0].new_value, bytes)
        self.assertEqual(result[0].new_value, bytes.fromhex("deadbeefcafe" + "00" * 26))

    def test_parse_random_invalid_non_string(self):
        with self.assertRaises((ValueError, TypeError)):
            Mutator.parse_mutation_params(make_modify_json("random", 12345))

    def test_parse_random_invalid_hex_chars(self):
        with self.assertRaises(ValueError):
            Mutator.parse_mutation_params(make_modify_json("random", "not_hex_string!"))

    # --- legacy_session_id ---
    def test_parse_legacy_session_id_valid(self):
        result = Mutator.parse_mutation_params(
            make_modify_json("legacy_session_id", "aabb")
        )
        self.assertEqual(result[0].new_value, b"\xaa\xbb")

    def test_parse_legacy_session_id_invalid_non_string(self):
        with self.assertRaises((ValueError, TypeError)):
            Mutator.parse_mutation_params(make_modify_json("legacy_session_id", 42))

    def test_parse_legacy_session_id_invalid_hex_chars(self):
        with self.assertRaises(ValueError):
            Mutator.parse_mutation_params(
                make_modify_json("legacy_session_id", "xyz!")
            )

    # --- hex string integer parsing ---
    def test_parse_cipher_suites_hex_string(self):
        """Hex string values like '0xdeadbeef' are parsed as integers."""
        result = Mutator.parse_mutation_params(
            make_modify_json("cipher_suites", ["0x1301", "0x1302"])
        )
        self.assertEqual(result[0].new_value, [0x1301, 0x1302])

    def test_parse_supported_groups_hex_string(self):
        result = Mutator.parse_mutation_params(
            make_modify_json("supported_groups", ["0x001d", "0x0017"])
        )
        self.assertEqual(result[0].new_value, [0x001D, 0x0017])

    def test_parse_key_share_client_hex_group_id(self):
        result = Mutator.parse_mutation_params(
            make_modify_json("key_share", [["0x001d", "deadbeef"]], target="client")
        )
        self.assertEqual(result[0].new_value, [(0x001D, bytes.fromhex("deadbeef"))])

    def test_parse_key_share_server_hex_group_id(self):
        result = Mutator.parse_mutation_params(
            make_modify_json("key_share", ["0x001d", "cafebabe"], target="server")
        )
        self.assertEqual(result[0].new_value, (0x001D, bytes.fromhex("cafebabe")))

    def test_parse_other_extensions_hex_type_id(self):
        result = Mutator.parse_mutation_params(
            make_modify_json("other_extensions", [["0x002a", "aabb"]])
        )
        self.assertEqual(result[0].new_value, [(0x002A, b"\xaa\xbb")])

    # --- server_name (passthrough) ---
    def test_parse_server_name_passthrough(self):
        result = Mutator.parse_mutation_params(
            make_modify_json("server_name", "test.example.com")
        )
        self.assertEqual(result[0].new_value, "test.example.com")
