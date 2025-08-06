"""
User Authentication System with JWT Tokens

This module provides a comprehensive authentication system with JWT tokens,
password hashing, session management, and security features.

Task ID: TASK-63
Generated on: 2025-08-06 09:12:06
"""

import hashlib
import hmac
import secrets
import jwt
import datetime
import re
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from enum import Enum

class UserRole(Enum):
    """User role enumeration."""
    ADMIN = "admin"
    USER = "user"
    MODERATOR = "moderator"
    GUEST = "guest"

@dataclass
class User:
    """User data class."""
    username: str
    email: str
    password_hash: str
    salt: str
    role: UserRole = UserRole.USER
    created_at: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    last_login: Optional[datetime.datetime] = None
    is_active: bool = True
    failed_login_attempts: int = 0
    locked_until: Optional[datetime.datetime] = None

class AuthenticationSystem:
    """
    Comprehensive user authentication system with JWT tokens.

    Features:
    - Secure password hashing with salt
    - JWT token generation and validation
    - Session management
    - Account lockout protection
    - Role-based access control
    - Password strength validation
    """

    def __init__(self, secret_key: str, token_expiry_hours: int = 24):
        """
        Initialize authentication system.

        Args:
            secret_key: Secret key for JWT token generation
            token_expiry_hours: JWT token expiry time in hours
        """
        self.secret_key = secret_key
        self.token_expiry_hours = token_expiry_hours
        self.users: Dict[str, User] = {}
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        self.max_failed_attempts = 5
        self.lockout_duration_minutes = 30

    def _generate_salt(self) -> str:
        """Generate a random salt for password hashing."""
        return secrets.token_hex(32)

    def _hash_password(self, password: str, salt: str) -> str:
        """
        Hash a password with salt using PBKDF2.

        Args:
            password: Plain text password
            salt: Salt for hashing

        Returns:
            Hashed password
        """
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()

    def _verify_password(self, password: str, salt: str, password_hash: str) -> bool:
        """
        Verify a password against its hash.

        Args:
            password: Plain text password
            salt: Salt used for hashing
            password_hash: Stored password hash

        Returns:
            True if password matches, False otherwise
        """
        return hmac.compare_digest(self._hash_password(password, salt), password_hash)

    def validate_password_strength(self, password: str) -> Dict[str, Any]:
        """
        Validate password strength.

        Args:
            password: Password to validate

        Returns:
            Dictionary with validation results
        """
        result = {
            'valid': True,
            'score': 0,
            'issues': []
        }

        if len(password) < 8:
            result['valid'] = False
            result['issues'].append('Password must be at least 8 characters long')
        else:
            result['score'] += 1

        if not re.search(r'[A-Z]', password):
            result['valid'] = False
            result['issues'].append('Password must contain at least one uppercase letter')
        else:
            result['score'] += 1

        if not re.search(r'[a-z]', password):
            result['valid'] = False
            result['issues'].append('Password must contain at least one lowercase letter')
        else:
            result['score'] += 1

        if not re.search(r'\d', password):
            result['valid'] = False
            result['issues'].append('Password must contain at least one digit')
        else:
            result['score'] += 1

        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            result['issues'].append('Password should contain at least one special character')
        else:
            result['score'] += 1

        return result

    def validate_email(self, email: str) -> bool:
        """
        Validate email format.

        Args:
            email: Email address to validate

        Returns:
            True if email is valid, False otherwise
        """
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    def register_user(self, username: str, password: str, email: str,
                     role: UserRole = UserRole.USER) -> Dict[str, Any]:
        """
        Register a new user.

        Args:
            username: Username
            password: Plain text password
            email: User email
            role: User role

        Returns:
            Registration result dictionary
        """
        # Validate inputs
        if username in self.users:
            return {'success': False, 'error': 'Username already exists'}

        if not self.validate_email(email):
            return {'success': False, 'error': 'Invalid email format'}

        # Check if email is already registered
        for user in self.users.values():
            if user.email == email:
                return {'success': False, 'error': 'Email already registered'}

        # Validate password strength
        password_validation = self.validate_password_strength(password)
        if not password_validation['valid']:
            return {
                'success': False,
                'error': 'Password does not meet requirements',
                'issues': password_validation['issues']
            }

        # Create user
        salt = self._generate_salt()
        password_hash = self._hash_password(password, salt)

        user = User(
            username=username,
            email=email,
            password_hash=password_hash,
            salt=salt,
            role=role
        )

        self.users[username] = user

        return {
            'success': True,
            'message': 'User registered successfully',
            'user_id': username
        }

    def _is_account_locked(self, user: User) -> bool:
        """Check if user account is locked."""
        if user.locked_until is None:
            return False
        return datetime.datetime.utcnow() < user.locked_until

    def _lock_account(self, user: User) -> None:
        """Lock user account after too many failed attempts."""
        user.locked_until = datetime.datetime.utcnow() + datetime.timedelta(
            minutes=self.lockout_duration_minutes
        )

    def authenticate_user(self, username: str, password: str) -> Dict[str, Any]:
        """
        Authenticate a user with username and password.

        Args:
            username: Username
            password: Plain text password

        Returns:
            Authentication result dictionary
        """
        if username not in self.users:
            return {'success': False, 'error': 'Invalid credentials'}

        user = self.users[username]

        if not user.is_active:
            return {'success': False, 'error': 'Account is deactivated'}

        if self._is_account_locked(user):
            return {
                'success': False,
                'error': f'Account is locked until {user.locked_until.strftime("%Y-%m-%d %H:%M:%S")}'
            }

        if self._verify_password(password, user.salt, user.password_hash):
            # Successful authentication
            user.failed_login_attempts = 0
            user.last_login = datetime.datetime.utcnow()
            user.locked_until = None

            return {
                'success': True,
                'message': 'Authentication successful',
                'user': {
                    'username': user.username,
                    'email': user.email,
                    'role': user.role.value,
                    'last_login': user.last_login.isoformat()
                }
            }
        else:
            # Failed authentication
            user.failed_login_attempts += 1

            if user.failed_login_attempts >= self.max_failed_attempts:
                self._lock_account(user)
                return {
                    'success': False,
                    'error': f'Account locked due to {self.max_failed_attempts} failed attempts'
                }

            remaining_attempts = self.max_failed_attempts - user.failed_login_attempts
            return {
                'success': False,
                'error': f'Invalid credentials. {remaining_attempts} attempts remaining'
            }

    def generate_jwt_token(self, username: str) -> Optional[str]:
        """
        Generate JWT token for authenticated user.

        Args:
            username: Username

        Returns:
            JWT token or None if user not found
        """
        if username not in self.users:
            return None

        user = self.users[username]

        payload = {
            'username': username,
            'email': user.email,
            'role': user.role.value,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=self.token_expiry_hours),
            'iat': datetime.datetime.utcnow(),
            'jti': secrets.token_hex(16)  # JWT ID for token revocation
        }

        token = jwt.encode(payload, self.secret_key, algorithm='HS256')

        # Store active session
        self.active_sessions[payload['jti']] = {
            'username': username,
            'created_at': datetime.datetime.utcnow(),
            'expires_at': payload['exp']
        }

        return token

    def verify_jwt_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Verify and decode JWT token.

        Args:
            token: JWT token

        Returns:
            Decoded payload or None if invalid
        """
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])

            # Check if session is still active
            jti = payload.get('jti')
            if jti not in self.active_sessions:
                return None

            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    def revoke_token(self, token: str) -> bool:
        """
        Revoke a JWT token.

        Args:
            token: JWT token to revoke

        Returns:
            True if token was revoked, False otherwise
        """
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            jti = payload.get('jti')

            if jti in self.active_sessions:
                del self.active_sessions[jti]
                return True
        except jwt.InvalidTokenError:
            pass

        return False

    def login(self, username: str, password: str) -> Dict[str, Any]:
        """
        Complete login process: authenticate and generate token.

        Args:
            username: Username
            password: Password

        Returns:
            Login result with token if successful
        """
        auth_result = self.authenticate_user(username, password)

        if auth_result['success']:
            token = self.generate_jwt_token(username)
            auth_result['token'] = token
            auth_result['expires_in'] = self.token_expiry_hours * 3600  # seconds

        return auth_result

    def logout(self, token: str) -> Dict[str, Any]:
        """
        Logout user by revoking token.

        Args:
            token: JWT token to revoke

        Returns:
            Logout result
        """
        if self.revoke_token(token):
            return {'success': True, 'message': 'Logged out successfully'}
        else:
            return {'success': False, 'error': 'Invalid or expired token'}

    def change_password(self, username: str, old_password: str, new_password: str) -> Dict[str, Any]:
        """
        Change user password.

        Args:
            username: Username
            old_password: Current password
            new_password: New password

        Returns:
            Password change result
        """
        # Authenticate with old password
        auth_result = self.authenticate_user(username, old_password)
        if not auth_result['success']:
            return {'success': False, 'error': 'Current password is incorrect'}

        # Validate new password
        password_validation = self.validate_password_strength(new_password)
        if not password_validation['valid']:
            return {
                'success': False,
                'error': 'New password does not meet requirements',
                'issues': password_validation['issues']
            }

        # Update password
        user = self.users[username]
        user.salt = self._generate_salt()
        user.password_hash = self._hash_password(new_password, user.salt)

        return {'success': True, 'message': 'Password changed successfully'}

    def get_user_info(self, username: str) -> Optional[Dict[str, Any]]:
        """
        Get user information.

        Args:
            username: Username

        Returns:
            User information dictionary or None if not found
        """
        if username not in self.users:
            return None

        user = self.users[username]
        return {
            'username': user.username,
            'email': user.email,
            'role': user.role.value,
            'created_at': user.created_at.isoformat(),
            'last_login': user.last_login.isoformat() if user.last_login else None,
            'is_active': user.is_active,
            'is_locked': self._is_account_locked(user)
        }

# Example usage and CLI interface
if __name__ == "__main__":
    import sys

    # Initialize authentication system
    auth = AuthenticationSystem("your-secret-key-here")

    if len(sys.argv) > 1:
        command = sys.argv[1]

        if command == "register":
            username = input("Username: ")
            password = input("Password: ")
            email = input("Email: ")

            result = auth.register_user(username, password, email)
            print(f"Registration: {'✓' if result['success'] else '✗'} {result.get('message', result.get('error'))}")

        elif command == "login":
            username = input("Username: ")
            password = input("Password: ")

            result = auth.login(username, password)
            if result['success']:
                print(f"✓ Login successful!")
                print(f"Token: {result['token'][:20]}...")
                print(f"Expires in: {result['expires_in']} seconds")
            else:
                print(f"✗ Login failed: {result['error']}")

        elif command == "demo":
            print("🔐 Authentication System Demo")
            print("=" * 50)

            # Register demo user
            print("
1. Registering demo user...")
            result = auth.register_user("demo_user", "SecurePass123!", "demo@example.com")
            print(f"Registration: {'✓' if result['success'] else '✗'} {result.get('message', result.get('error'))}")

            # Login demo user
            print("
2. Logging in demo user...")
            login_result = auth.login("demo_user", "SecurePass123!")
            if login_result['success']:
                print("✓ Login successful!")
                token = login_result['token']
                print(f"Token: {token[:30]}...")

                # Verify token
                print("
3. Verifying token...")
                payload = auth.verify_jwt_token(token)
                if payload:
                    print(f"✓ Token valid for user: {payload['username']}")
                    print(f"Role: {payload['role']}")
                    print(f"Expires: {datetime.datetime.fromtimestamp(payload['exp'])}")

                # Get user info
                print("
4. Getting user info...")
                user_info = auth.get_user_info("demo_user")
                if user_info:
                    print(f"User: {user_info['username']}")
                    print(f"Email: {user_info['email']}")
                    print(f"Role: {user_info['role']}")
                    print(f"Active: {user_info['is_active']}")

                # Logout
                print("
5. Logging out...")
                logout_result = auth.logout(token)
                print(f"Logout: {'✓' if logout_result['success'] else '✗'} {logout_result.get('message', logout_result.get('error'))}")
            else:
                print(f"✗ Login failed: {login_result['error']}")
    else:
        print("🔐 Authentication System")
        print("Usage: python authentication.py [register|login|demo]")
