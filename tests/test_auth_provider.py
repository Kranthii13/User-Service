import unittest
import sys
import os
from uuid import uuid4

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from application.ports.auth_provider import AuthProvider
from infrastructure.adapters.supabase_auth_adapter import SupabaseAuthProvider


class TestAuthProvider(unittest.TestCase):

    def test_supabase_auth_adapter_instantiation(self):
        adapter = SupabaseAuthProvider(
            supabase_url="https://example.supabase.co",
            service_role_key="service-key-test",
            anon_key="anon-key-test"
        )
        self.assertEqual(adapter.supabase_url, "https://example.supabase.co")
        self.assertTrue(isinstance(adapter, AuthProvider))


if __name__ == "__main__":
    unittest.main()
