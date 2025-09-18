import pytest
from app import AuthSystem  # Lager classen

# User Authentication Tester 
def test_login_success():
    auth = AuthSystem()
    auth.register("zahra", "secret", role="user")
    assert auth.login("zahra", "secret") == True

def test_login_fail_wrong_password():
    auth = AuthSystem()
    auth.register("zahra", "secret", role="user")
    assert auth.login("zahra", "wrong") == False

def test_login_fail_nonexistent_user():
    auth = AuthSystem()
    assert auth.login("nonexistent", "password") == False

#  Additional Scenario: User Role 
def test_is_admin():
    auth = AuthSystem()
    auth.register("admin", "adminpass", role="admin")
    assert auth.is_admin("admin") == True

def test_is_not_admin():
    auth = AuthSystem()
    auth.register("zahra", "secret", role="user")
    assert auth.is_admin("zahra") == False
