from __future__ import annotations

from lighthouse_firewall_auto_allow.security import generate_token, hash_token, verify_token


def test_token_hashing_round_trip() -> None:
    token = generate_token()
    token_hash = hash_token(token)

    assert verify_token(token, token_hash)
    assert not verify_token(f"{token}x", token_hash)
