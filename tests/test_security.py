"""Unit tests for security module."""
import pytest

from backend.app.core.security import (
    hash_password,
    validate_password_policy,
    verify_password,
    create_access_token,
    decode_token,
)


def test_password_hashing():
    hashed = hash_password("TestPassword123!")
    assert verify_password("TestPassword123!", hashed)
    assert not verify_password("wrong", hashed)


def test_password_policy():
    valid, _ = validate_password_policy("Weak")
    assert not valid
    valid, _ = validate_password_policy("StrongPass123!")
    assert valid


def test_jwt_token():
    token = create_access_token({"sub": "test-user-id"})
    payload = decode_token(token)
    assert payload is not None
    assert payload["sub"] == "test-user-id"
