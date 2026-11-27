"""Tests for CNG RSA2 -> PEM conversion and --entropy parsing."""
import struct

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from dploot.lib.crypto import BCRYPT_RSAPRIVATE_MAGIC, cng_rsa_private_to_pem
from dploot.lib.utils import parse_entropy


def _build_rsa2_blob(private_key: rsa.RSAPrivateKey) -> bytes:
    """Serialise a cryptography RSA private key as a BCRYPT_RSAKEY_BLOB (RSA2)."""
    priv = private_key.private_numbers()
    pub = priv.public_numbers

    def to_be(value: int) -> bytes:
        length = (value.bit_length() + 7) // 8
        return value.to_bytes(length, "big")

    e = to_be(pub.e)
    n = to_be(pub.n)
    p = to_be(priv.p)
    q = to_be(priv.q)

    header = struct.pack(
        "<6I",
        BCRYPT_RSAPRIVATE_MAGIC,
        private_key.key_size,
        len(e),
        len(n),
        len(p),
        len(q),
    )
    return header + e + n + p + q


def test_cng_rsa_private_to_pem_roundtrip():
    original = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    blob = _build_rsa2_blob(original)

    pem = cng_rsa_private_to_pem(blob)
    assert pem is not None
    assert pem.startswith(b"-----BEGIN RSA PRIVATE KEY-----")

    # Loadable, and equivalent to the original key.
    loaded = load_pem_private_key(pem, password=None)
    assert loaded.private_numbers().p * loaded.private_numbers().q == \
        original.private_numbers().public_numbers.n
    assert loaded.public_key().public_numbers() == original.public_key().public_numbers()


def test_cng_rsa_private_to_pem_rejects_non_rsa2():
    # Wrong magic / garbage payloads must not crash, just return None.
    assert cng_rsa_private_to_pem(b"") is None
    assert cng_rsa_private_to_pem(b"not-a-key") is None
    assert cng_rsa_private_to_pem(b"RSA1" + b"\x00" * 40) is None
    # Truncated blob (announces more data than present).
    truncated = struct.pack("<6I", BCRYPT_RSAPRIVATE_MAGIC, 2048, 3, 256, 128, 128)
    assert cng_rsa_private_to_pem(truncated) is None


def test_parse_entropy_variants():
    assert parse_entropy(None) is None
    assert parse_entropy("") is None
    assert parse_entropy(b"raw\x00") == b"raw\x00"
    # Plain string stays as its utf-8/latin-1 bytes.
    assert parse_entropy("xT5rZW5qVVbrvpuA") == b"xT5rZW5qVVbrvpuA"
    # Literal escape sequence is decoded to a trailing null byte.
    assert parse_entropy("xT5rZW5qVVbrvpuA\\x00") == b"xT5rZW5qVVbrvpuA\x00"
    # Already-literal null byte is preserved.
    assert parse_entropy("abc\x00") == b"abc\x00"
    # Result is always bytes (never str), so it can reach C crypto code.
    assert isinstance(parse_entropy("anything"), bytes)
