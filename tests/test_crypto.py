"""Tests for the rolling-key cipher primitives."""

from __future__ import annotations

import pytest

from game_protocol_cracker.crypto import (
    DEFAULT_WRAP_KEY,
    RollingKeyCipher,
    compute_check,
    decrypt_byte,
    decrypt_payload,
    derive_key_params,
    encrypt_byte,
    encrypt_payload,
    update_key,
)


class TestKeyDerivation:
    def test_w8_w9_for_zero_key(self):
        w8, w9 = derive_key_params(0)
        assert w8 == 0xFF
        assert w9 == 0xFFF

    def test_w8_w9_for_non_zero_key(self):
        w8, w9 = derive_key_params(0x1234)
        assert 0 <= w8 <= 0xFF
        assert 0 <= w9 <= 0xFFF

    def test_derivation_is_deterministic(self):
        assert derive_key_params(5) == derive_key_params(5)


class TestBytePrimitives:
    @pytest.mark.parametrize("key", [0, 1, 2, 5, 100, 0x70A2])
    @pytest.mark.parametrize("plain", [0, 1, 42, 127, 255])
    def test_roundtrip(self, key: int, plain: int):
        w8, w9 = derive_key_params(key)
        enc = encrypt_byte(plain, w8, w9)
        dec = decrypt_byte(enc, w8, w9)
        assert dec == plain

    def test_encrypt_produces_byte_in_range(self):
        w8, w9 = derive_key_params(7)
        for plain in range(256):
            enc = encrypt_byte(plain, w8, w9)
            assert 0 <= enc <= 0xFF


class TestUpdateKey:
    def test_increments_normally(self):
        assert update_key(0) == 1
        assert update_key(100) == 101

    def test_wraps_at_default(self):
        assert update_key(DEFAULT_WRAP_KEY - 1) == 0

    def test_wraps_at_custom_value(self):
        assert update_key(99, wrap_at=100) == 0
        assert update_key(50, wrap_at=100) == 51


class TestPayloadRoundtrip:
    def test_empty_payload(self):
        enc, key = encrypt_payload(b"", 0)
        assert enc == b""
        dec, key = decrypt_payload(enc, 0)
        assert dec == b""

    def test_roundtrip_preserves_bytes(self):
        plain = b"hello world " * 10
        enc, enc_key = encrypt_payload(plain, 0)
        dec, dec_key = decrypt_payload(enc, 0)
        assert dec == plain
        assert enc_key == dec_key

    @pytest.mark.parametrize("key", [0, 1, 7, 42, 0x70A1])
    def test_roundtrip_with_various_keys(self, key: int):
        plain = bytes(range(256))
        enc, _ = encrypt_payload(plain, key)
        dec, _ = decrypt_payload(enc, key)
        assert dec == plain

    def test_roundtrip_across_wrap(self):
        plain = b"payload"
        enc, new_key = encrypt_payload(plain, DEFAULT_WRAP_KEY - 1)
        assert new_key == 0
        dec, _ = decrypt_payload(enc, DEFAULT_WRAP_KEY - 1)
        assert dec == plain


class TestComputeCheck:
    def test_check_is_byte(self):
        check = compute_check(b"hello", 7)
        assert 0 <= check <= 0xFF

    def test_check_sensitive_to_plaintext(self):
        key = 10
        a = compute_check(b"abc", key)
        b = compute_check(b"abd", key)
        assert a != b

    def test_check_sensitive_to_key(self):
        a = compute_check(b"payload", 5)
        b = compute_check(b"payload", 6)
        assert a != b


class TestRollingKeyCipher:
    def test_advances_key_on_each_call(self):
        cipher = RollingKeyCipher(key=0)
        cipher.encrypt(b"one")
        assert cipher.key == 1
        cipher.encrypt(b"two")
        assert cipher.key == 2

    def test_decrypt_reverses_encrypt_via_fork(self):
        encoder = RollingKeyCipher(key=3)
        decoder = encoder.fork()
        for msg in [b"first", b"second", b"third payload"]:
            ct = encoder.encrypt(msg)
            pt = decoder.decrypt(ct)
            assert pt == msg

    def test_fork_is_independent(self):
        cipher = RollingKeyCipher(key=5)
        copy = cipher.fork()
        cipher.encrypt(b"x")
        assert cipher.key == 6
        assert copy.key == 5

    def test_check_byte_matches_compute_check(self):
        cipher = RollingKeyCipher(key=2)
        check = cipher.check_byte(b"payload")
        probe = update_key(2)
        assert check == compute_check(b"payload", probe)
