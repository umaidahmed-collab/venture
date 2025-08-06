import unittest
import sys
import os
import datetime
import jwt

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from authentication import AuthenticationSystem, UserRole, User

class TestAuthenticationSystem(unittest.TestCase):
    """Comprehensive test cases for AuthenticationSystem."""

    def setUp(self):
        """Set up test fixtures."""
        self.auth = AuthenticationSystem("test-secret-key-12345")

    def test_password_validation(self):
        """Test password strength validation."""
        # Valid password
        result = self.auth.validate_password_strength("SecurePass123!")
        self.assertTrue(result['valid'])
        self.assertEqual(result['score'], 5)

        # Too short
        result = self.auth.validate_password_strength("short")
        self.assertFalse(result['valid'])
        self.assertIn('at least 8 characters', ' '.join(result['issues']))

        # Missing uppercase
        result = self.auth.validate_password_strength("lowercase123!")
        self.assertFalse(result['valid'])
        self.assertIn('uppercase letter', ' '.join(result['issues']))

    def test_email_validation(self):
        """Test email format validation."""
        valid_emails = [
            "user@example.com",
            "test.email+tag@domain.co.uk",
            "user123@test-domain.org"
        ]

        invalid_emails = [
            "invalid-email",
            "@domain.com",
            "user@",
            "user@domain",
            "user.domain.com"
        ]

        for email in valid_emails:
            self.assertTrue(self.auth.validate_email(email))

        for email in invalid_emails:
            self.assertFalse(self.auth.validate_email(email))

    def test_user_registration_success(self):
        """Test successful user registration."""
        result = self.auth.register_user(
            "testuser",
            "SecurePass123!",
            "test@example.com"
        )

        self.assertTrue(result['success'])
        self.assertEqual(result['user_id'], "testuser")
        self.assertIn("testuser", self.auth.users)

    def test_user_registration_duplicate_username(self):
        """Test registration with duplicate username."""
        # Register first user
        self.auth.register_user("testuser", "SecurePass123!", "test1@example.com")

        # Try to register with same username
        result = self.auth.register_user("testuser", "SecurePass456!", "test2@example.com")

        self.assertFalse(result['success'])
        self.assertIn("already exists", result['error'])

    def test_user_registration_duplicate_email(self):
        """Test registration with duplicate email."""
        # Register first user
        self.auth.register_user("user1", "SecurePass123!", "test@example.com")

        # Try to register with same email
        result = self.auth.register_user("user2", "SecurePass456!", "test@example.com")

        self.assertFalse(result['success'])
        self.assertIn("already registered", result['error'])

    def test_user_registration_weak_password(self):
        """Test registration with weak password."""
        result = self.auth.register_user("testuser", "weak", "test@example.com")

        self.assertFalse(result['success'])
        self.assertIn("does not meet requirements", result['error'])
        self.assertIn("issues", result)

    def test_user_authentication_success(self):
        """Test successful user authentication."""
        # Register user
        self.auth.register_user("authuser", "SecurePass123!", "auth@example.com")

        # Authenticate
        result = self.auth.authenticate_user("authuser", "SecurePass123!")

        self.assertTrue(result['success'])
        self.assertIn("user", result)
        self.assertEqual(result['user']['username'], "authuser")

    def test_user_authentication_wrong_password(self):
        """Test authentication with wrong password."""
        # Register user
        self.auth.register_user("authuser", "SecurePass123!", "auth@example.com")

        # Try wrong password
        result = self.auth.authenticate_user("authuser", "WrongPassword")

        self.assertFalse(result['success'])
        self.assertIn("Invalid credentials", result['error'])

    def test_user_authentication_nonexistent_user(self):
        """Test authentication with non-existent user."""
        result = self.auth.authenticate_user("nonexistent", "password")

        self.assertFalse(result['success'])
        self.assertIn("Invalid credentials", result['error'])

    def test_account_lockout(self):
        """Test account lockout after failed attempts."""
        # Register user
        self.auth.register_user("lockuser", "SecurePass123!", "lock@example.com")

        # Make multiple failed attempts
        for _ in range(5):
            result = self.auth.authenticate_user("lockuser", "wrongpassword")
            self.assertFalse(result['success'])

        # Account should be locked now
        result = self.auth.authenticate_user("lockuser", "SecurePass123!")
        self.assertFalse(result['success'])
        self.assertIn("locked", result['error'].lower())

    def test_jwt_token_generation(self):
        """Test JWT token generation."""
        # Register user
        self.auth.register_user("tokenuser", "SecurePass123!", "token@example.com")

        # Generate token
        token = self.auth.generate_jwt_token("tokenuser")

        self.assertIsNotNone(token)
        self.assertIsInstance(token, str)

        # Verify token structure
        try:
            payload = jwt.decode(token, self.auth.secret_key, algorithms=['HS256'])
            self.assertEqual(payload['username'], "tokenuser")
            self.assertIn('exp', payload)
            self.assertIn('iat', payload)
            self.assertIn('jti', payload)
        except jwt.InvalidTokenError:
            self.fail("Generated token is invalid")

    def test_jwt_token_verification(self):
        """Test JWT token verification."""
        # Register user and generate token
        self.auth.register_user("verifyuser", "SecurePass123!", "verify@example.com")
        token = self.auth.generate_jwt_token("verifyuser")

        # Verify valid token
        payload = self.auth.verify_jwt_token(token)
        self.assertIsNotNone(payload)
        self.assertEqual(payload['username'], "verifyuser")

        # Verify invalid token
        payload = self.auth.verify_jwt_token("invalid.token.here")
        self.assertIsNone(payload)

    def test_token_revocation(self):
        """Test JWT token revocation."""
        # Register user and generate token
        self.auth.register_user("revokeuser", "SecurePass123!", "revoke@example.com")
        token = self.auth.generate_jwt_token("revokeuser")

        # Token should be valid initially
        payload = self.auth.verify_jwt_token(token)
        self.assertIsNotNone(payload)

        # Revoke token
        revoked = self.auth.revoke_token(token)
        self.assertTrue(revoked)

        # Token should be invalid after revocation
        payload = self.auth.verify_jwt_token(token)
        self.assertIsNone(payload)

    def test_complete_login_flow(self):
        """Test complete login process."""
        # Register user
        self.auth.register_user("loginuser", "SecurePass123!", "login@example.com")

        # Login
        result = self.auth.login("loginuser", "SecurePass123!")

        self.assertTrue(result['success'])
        self.assertIn('token', result)
        self.assertIn('expires_in', result)

        # Failed login
        result = self.auth.login("loginuser", "wrongpassword")
        self.assertFalse(result['success'])
        self.assertNotIn('token', result)

    def test_logout(self):
        """Test logout functionality."""
        # Register and login user
        self.auth.register_user("logoutuser", "SecurePass123!", "logout@example.com")
        login_result = self.auth.login("logoutuser", "SecurePass123!")
        token = login_result['token']

        # Logout
        logout_result = self.auth.logout(token)
        self.assertTrue(logout_result['success'])

        # Token should be invalid after logout
        payload = self.auth.verify_jwt_token(token)
        self.assertIsNone(payload)

    def test_password_change(self):
        """Test password change functionality."""
        # Register user
        self.auth.register_user("changeuser", "OldPass123!", "change@example.com")

        # Change password
        result = self.auth.change_password("changeuser", "OldPass123!", "NewPass456!")
        self.assertTrue(result['success'])

        # Old password should not work
        auth_result = self.auth.authenticate_user("changeuser", "OldPass123!")
        self.assertFalse(auth_result['success'])

        # New password should work
        auth_result = self.auth.authenticate_user("changeuser", "NewPass456!")
        self.assertTrue(auth_result['success'])

    def test_get_user_info(self):
        """Test getting user information."""
        # Register user
        self.auth.register_user("infouser", "SecurePass123!", "info@example.com", UserRole.ADMIN)

        # Get user info
        user_info = self.auth.get_user_info("infouser")

        self.assertIsNotNone(user_info)
        self.assertEqual(user_info['username'], "infouser")
        self.assertEqual(user_info['email'], "info@example.com")
        self.assertEqual(user_info['role'], "admin")
        self.assertTrue(user_info['is_active'])
        self.assertFalse(user_info['is_locked'])

        # Non-existent user
        user_info = self.auth.get_user_info("nonexistent")
        self.assertIsNone(user_info)

class TestUserRoles(unittest.TestCase):
    """Test user role functionality."""

    def test_user_roles(self):
        """Test different user roles."""
        auth = AuthenticationSystem("test-key")

        # Register users with different roles
        auth.register_user("admin", "AdminPass123!", "admin@example.com", UserRole.ADMIN)
        auth.register_user("user", "UserPass123!", "user@example.com", UserRole.USER)
        auth.register_user("mod", "ModPass123!", "mod@example.com", UserRole.MODERATOR)

        # Check roles in tokens
        admin_token = auth.generate_jwt_token("admin")
        user_token = auth.generate_jwt_token("user")
        mod_token = auth.generate_jwt_token("mod")

        admin_payload = auth.verify_jwt_token(admin_token)
        user_payload = auth.verify_jwt_token(user_token)
        mod_payload = auth.verify_jwt_token(mod_token)

        self.assertEqual(admin_payload['role'], "admin")
        self.assertEqual(user_payload['role'], "user")
        self.assertEqual(mod_payload['role'], "moderator")

if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)
