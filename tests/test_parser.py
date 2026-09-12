import unittest

from connstrlint.parser import parse, parse_keyvalue, parse_url


class ParseUrlTests(unittest.TestCase):
    def test_full_postgres_url(self):
        conn = parse_url(
            "postgres://app_user:changeme123@db.internal:5432/orders?sslmode=require"
        )
        self.assertEqual(conn.style, "url")
        self.assertEqual(conn.scheme, "postgres")
        self.assertEqual(conn.user, "app_user")
        self.assertEqual(conn.password, "changeme123")
        self.assertEqual(conn.host, "db.internal")
        self.assertEqual(conn.port, 5432)
        self.assertEqual(conn.database, "orders")
        self.assertEqual(conn.options, {"sslmode": "require"})

    def test_jdbc_prefix_is_kept_on_scheme(self):
        conn = parse_url("jdbc:mysql://user:pass@host:3306/db")
        self.assertEqual(conn.scheme, "jdbc:mysql")
        self.assertEqual(conn.host, "host")
        self.assertEqual(conn.port, 3306)

    def test_percent_encoded_credentials_are_unquoted(self):
        conn = parse_url("redis://u%40ser:p%40ss@host:6379/0")
        self.assertEqual(conn.user, "u@ser")
        self.assertEqual(conn.password, "p@ss")

    def test_missing_scheme_or_netloc_returns_none(self):
        self.assertIsNone(parse_url("not a url at all"))
        self.assertIsNone(parse_url("just-a-path/no-scheme"))

    def test_invalid_port_is_ignored_but_rest_still_parses(self):
        conn = parse_url("postgres://user@host:notaport/db")
        self.assertIsNone(conn.port)
        self.assertEqual(conn.host, "host")

    def test_missing_path_gives_none_database(self):
        conn = parse_url("mongodb://user:pass@host:27017")
        self.assertIsNone(conn.database)


class ParseKeyValueTests(unittest.TestCase):
    def test_typical_ado_string(self):
        raw = (
            "Server=sqlsrv01;Database=orders;User Id=sa;"
            "Password=changeme123;TrustServerCertificate=true;"
        )
        conn = parse_keyvalue(raw)
        self.assertEqual(conn.style, "kv")
        self.assertEqual(conn.host, "sqlsrv01")
        self.assertEqual(conn.database, "orders")
        self.assertEqual(conn.user, "sa")
        self.assertEqual(conn.password, "changeme123")
        self.assertEqual(conn.options, {"trustservercertificate": "true"})

    def test_single_pair_is_not_enough(self):
        self.assertIsNone(parse_keyvalue("Server=host"))

    def test_pairs_without_equals_sign_are_skipped(self):
        conn = parse_keyvalue("foo;Server=host;Database=db")
        self.assertEqual(conn.host, "host")
        self.assertEqual(conn.database, "db")

    def test_quotes_are_stripped_from_values(self):
        conn = parse_keyvalue('Server="host";Password=\'p@ss\'')
        self.assertEqual(conn.host, "host")
        self.assertEqual(conn.password, "p@ss")

    def test_invalid_port_is_dropped_not_kept_as_option(self):
        conn = parse_keyvalue("Server=host;Port=notanumber;Database=db")
        self.assertIsNone(conn.port)
        self.assertNotIn("port", conn.options)

    def test_valid_port_is_parsed_as_int(self):
        conn = parse_keyvalue("Server=host;Port=5432;Database=db")
        self.assertEqual(conn.port, 5432)
        self.assertNotIn("port", conn.options)

    def test_no_recognizable_identity_fields_returns_none(self):
        # Port alone isn't enough - without a user, host, or database
        # there's nothing worth reporting on.
        self.assertIsNone(parse_keyvalue("Port=5432;Foo=bar"))

    def test_unrecognized_keys_stay_in_options(self):
        conn = parse_keyvalue("Server=host;Encrypt=yes;Database=db")
        self.assertEqual(conn.options, {"encrypt": "yes"})


class ParseDispatchTests(unittest.TestCase):
    def test_dispatches_url_style(self):
        conn = parse(" postgres://user:pass@host/db ")
        self.assertEqual(conn.style, "url")

    def test_dispatches_keyvalue_style(self):
        conn = parse("Server=host;Database=db")
        self.assertEqual(conn.style, "kv")

    def test_garbage_input_returns_none(self):
        self.assertIsNone(parse("this is just some sentence"))


if __name__ == "__main__":
    unittest.main()
