# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

"""
Tests for Hybrid KEM (Key Encapsulation Mechanism) implementations.
"""

import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import hybrid_kem


@pytest.mark.supported(
    only_if=lambda backend: backend.mlkem768_supported()
    and backend.x25519_supported(),
    skip_message="Requires OpenSSL with ML-KEM-768 and X25519 support",
)
class TestX25519MLKEM768:
    """Tests for X25519 + ML-KEM-768 hybrid KEM (X-Wing)"""

    def test_generate_and_encapsulate_decapsulate(self):
        """Test basic key generation, encapsulation, and decapsulation"""
        # Generate key pair
        private_key = hybrid_kem.X25519MLKEM768PrivateKey.generate()
        public_key = private_key.public_key()

        # Encapsulate
        ciphertext, encap_shared_secret = public_key.encapsulate()

        # Verify ciphertext size: 32 (X25519) + 1088 (ML-KEM-768)
        assert len(ciphertext) == 1120

        # Verify shared secret size
        assert len(encap_shared_secret) == 32

        # Decapsulate
        decap_shared_secret = private_key.decapsulate(ciphertext)

        # Verify shared secrets match
        assert encap_shared_secret == decap_shared_secret

    def test_multiple_encapsulations_different(self):
        """Verify that multiple encapsulations produce different results"""
        private_key = hybrid_kem.X25519MLKEM768PrivateKey.generate()
        public_key = private_key.public_key()

        ct1, ss1 = public_key.encapsulate()
        ct2, ss2 = public_key.encapsulate()
        ct3, ss3 = public_key.encapsulate()

        # Ciphertexts should be different (randomized)
        assert ct1 != ct2
        assert ct2 != ct3
        assert ct1 != ct3

        # Shared secrets should be different
        assert ss1 != ss2
        assert ss2 != ss3
        assert ss1 != ss3

        # But all should decapsulate correctly
        assert private_key.decapsulate(ct1) == ss1
        assert private_key.decapsulate(ct2) == ss2
        assert private_key.decapsulate(ct3) == ss3

    def test_public_key_serialization(self):
        """Test public key serialization and deserialization"""
        private_key = hybrid_kem.X25519MLKEM768PrivateKey.generate()
        public_key = private_key.public_key()

        # Serialize
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        # Verify size: 32 (X25519) + 1184 (ML-KEM-768)
        assert len(public_bytes) == 1216

        # Deserialize
        loaded_public_key = (
            hybrid_kem.X25519MLKEM768PublicKey.from_public_bytes(public_bytes)
        )

        # Verify it works
        ct, ss = loaded_public_key.encapsulate()
        assert len(ct) == 1120
        assert len(ss) == 32

        # Should be able to decapsulate with original private key
        decap_ss = private_key.decapsulate(ct)
        assert decap_ss == ss

    def test_private_key_serialization(self):
        """Test private key serialization and deserialization"""
        private_key = hybrid_kem.X25519MLKEM768PrivateKey.generate()

        # Serialize
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # Verify size: 32 (X25519) + 2400 (ML-KEM-768)
        assert len(private_bytes) == 2432

        # Deserialize
        loaded_private_key = (
            hybrid_kem.X25519MLKEM768PrivateKey.from_private_bytes(
                private_bytes
            )
        )

        # Verify it works - encapsulate with original public key
        public_key = private_key.public_key()
        ct, ss1 = public_key.encapsulate()

        # Decapsulate with loaded private key
        ss2 = loaded_private_key.decapsulate(ct)

        # Should match
        assert ss1 == ss2

    def test_invalid_ciphertext_length(self):
        """Test that invalid ciphertext length raises error"""
        private_key = hybrid_kem.X25519MLKEM768PrivateKey.generate()

        with pytest.raises(ValueError, match="Invalid ciphertext length"):
            private_key.decapsulate(b"too short")

        with pytest.raises(ValueError, match="Invalid ciphertext length"):
            private_key.decapsulate(b"x" * 1000)  # Wrong size

    def test_invalid_public_key_bytes(self):
        """Test that invalid public key bytes raise error"""
        with pytest.raises(ValueError, match="Invalid key length"):
            hybrid_kem.X25519MLKEM768PublicKey.from_public_bytes(b"too short")

        with pytest.raises(ValueError, match="Invalid key length"):
            hybrid_kem.X25519MLKEM768PublicKey.from_public_bytes(b"x" * 1000)

    def test_invalid_private_key_bytes(self):
        """Test that invalid private key bytes raise error"""
        with pytest.raises(ValueError, match="Invalid key length"):
            hybrid_kem.X25519MLKEM768PrivateKey.from_private_bytes(
                b"too short"
            )

        with pytest.raises(ValueError, match="Invalid key length"):
            hybrid_kem.X25519MLKEM768PrivateKey.from_private_bytes(b"x" * 1000)

    def test_public_key_serialization_unsupported_formats(self):
        """Test that non-Raw formats raise errors"""
        private_key = hybrid_kem.X25519MLKEM768PrivateKey.generate()
        public_key = private_key.public_key()

        with pytest.raises(ValueError, match="Only Raw encoding/format"):
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

    def test_private_key_serialization_unsupported_formats(self):
        """Test that non-Raw formats raise errors"""
        private_key = hybrid_kem.X25519MLKEM768PrivateKey.generate()

        with pytest.raises(ValueError, match="Only Raw encoding/format"):
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

    def test_private_key_serialization_no_encryption_only(self):
        """Test that encryption is not supported for raw format"""
        from cryptography.hazmat.primitives.serialization import (
            BestAvailableEncryption,
        )

        private_key = hybrid_kem.X25519MLKEM768PrivateKey.generate()

        with pytest.raises(ValueError, match="Encryption is not supported"):
            private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=BestAvailableEncryption(b"password"),
            )

    def test_roundtrip_full_workflow(self):
        """Test complete workflow: generate, serialize, deserialize, use"""
        # Generate keys
        private_key = hybrid_kem.X25519MLKEM768PrivateKey.generate()
        public_key = private_key.public_key()

        # Serialize both keys
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        # Deserialize
        loaded_private = (
            hybrid_kem.X25519MLKEM768PrivateKey.from_private_bytes(
                private_bytes
            )
        )
        loaded_public = hybrid_kem.X25519MLKEM768PublicKey.from_public_bytes(
            public_bytes
        )

        # Use loaded public key to encapsulate
        ct, ss1 = loaded_public.encapsulate()

        # Use loaded private key to decapsulate
        ss2 = loaded_private.decapsulate(ct)

        # Should match
        assert ss1 == ss2

    def test_shared_secret_is_derived(self):
        """Verify shared secret is properly derived, not just concatenated"""
        private_key = hybrid_kem.X25519MLKEM768PrivateKey.generate()
        public_key = private_key.public_key()

        ct, ss = public_key.encapsulate()

        # Shared secret should be 32 bytes (HKDF output)
        assert len(ss) == 32

        # Should not be predictable from ciphertext alone
        assert ss not in ct


@pytest.mark.supported(
    only_if=lambda backend: backend.mlkem1024_supported()
    and backend.x448_supported(),
    skip_message="Requires OpenSSL with ML-KEM-1024 and X448 support",
)
class TestX448MLKEM1024:
    """Tests for X448 + ML-KEM-1024 hybrid KEM"""

    def test_generate_and_encapsulate_decapsulate(self):
        """Test basic key generation, encapsulation, and decapsulation"""
        private_key = hybrid_kem.X448MLKEM1024PrivateKey.generate()
        public_key = private_key.public_key()

        # Encapsulate
        ciphertext, encap_shared_secret = public_key.encapsulate()

        # Verify ciphertext size: 56 (X448) + 1568 (ML-KEM-1024)
        assert len(ciphertext) == 1624

        # Verify shared secret size
        assert len(encap_shared_secret) == 32

        # Decapsulate
        decap_shared_secret = private_key.decapsulate(ciphertext)

        # Verify shared secrets match
        assert encap_shared_secret == decap_shared_secret

    def test_public_key_serialization(self):
        """Test public key serialization"""
        private_key = hybrid_kem.X448MLKEM1024PrivateKey.generate()
        public_key = private_key.public_key()

        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        # Verify size: 56 (X448) + 1568 (ML-KEM-1024)
        assert len(public_bytes) == 1624

        # Deserialize and verify
        loaded_public_key = (
            hybrid_kem.X448MLKEM1024PublicKey.from_public_bytes(public_bytes)
        )

        ct, ss = loaded_public_key.encapsulate()
        assert len(ct) == 1624
        assert len(ss) == 32
        assert private_key.decapsulate(ct) == ss

    def test_private_key_serialization(self):
        """Test private key serialization"""
        private_key = hybrid_kem.X448MLKEM1024PrivateKey.generate()

        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # Verify size: 56 (X448) + 3168 (ML-KEM-1024)
        assert len(private_bytes) == 3224

        # Deserialize and verify
        loaded_private_key = (
            hybrid_kem.X448MLKEM1024PrivateKey.from_private_bytes(
                private_bytes
            )
        )

        public_key = private_key.public_key()
        ct, ss1 = public_key.encapsulate()
        ss2 = loaded_private_key.decapsulate(ct)
        assert ss1 == ss2

    def test_multiple_encapsulations(self):
        """Verify randomization"""
        private_key = hybrid_kem.X448MLKEM1024PrivateKey.generate()
        public_key = private_key.public_key()

        ct1, ss1 = public_key.encapsulate()
        ct2, ss2 = public_key.encapsulate()

        # Should be different
        assert ct1 != ct2
        assert ss1 != ss2

        # But both should decapsulate correctly
        assert private_key.decapsulate(ct1) == ss1
        assert private_key.decapsulate(ct2) == ss2

    def test_invalid_ciphertext_length(self):
        """Test error handling for invalid ciphertext"""
        private_key = hybrid_kem.X448MLKEM1024PrivateKey.generate()

        with pytest.raises(ValueError, match="Invalid ciphertext length"):
            private_key.decapsulate(b"wrong size")


@pytest.mark.supported(
    only_if=lambda backend: backend.mlkem768_supported()
    and backend.mlkem1024_supported()
    and backend.x25519_supported()
    and backend.x448_supported(),
    skip_message=(
        "Requires OpenSSL with ML-KEM-768/1024 and X25519/X448 support"
    ),
)
class TestHybridKEMSecurity:
    """Security-focused tests for hybrid KEMs"""

    def test_x25519mlkem768_different_keys_different_secrets(self):
        """Verify different key pairs produce different shared secrets"""
        # Generate two independent key pairs
        private1 = hybrid_kem.X25519MLKEM768PrivateKey.generate()
        private2 = hybrid_kem.X25519MLKEM768PrivateKey.generate()

        public1 = private1.public_key()
        private2.public_key()

        # Encapsulate with first public key
        ct1, ss1_from_pub1 = public1.encapsulate()

        # Try to decapsulate with wrong private key
        # (This should succeed cryptographically but give different secret)
        ss1_from_priv2 = private2.decapsulate(ct1)

        # Secrets should be different
        assert ss1_from_pub1 != ss1_from_priv2

        # Only the correct private key should recover the correct secret
        ss1_from_priv1 = private1.decapsulate(ct1)
        assert ss1_from_pub1 == ss1_from_priv1

    def test_x448mlkem1024_different_keys_different_secrets(self):
        """Same test for X448MLKEM1024"""
        private1 = hybrid_kem.X448MLKEM1024PrivateKey.generate()
        private2 = hybrid_kem.X448MLKEM1024PrivateKey.generate()

        public1 = private1.public_key()

        ct1, ss1_from_pub1 = public1.encapsulate()
        ss1_from_priv2 = private2.decapsulate(ct1)

        # Should be different
        assert ss1_from_pub1 != ss1_from_priv2

        # Correct key recovers correct secret
        ss1_from_priv1 = private1.decapsulate(ct1)
        assert ss1_from_pub1 == ss1_from_priv1


@pytest.mark.supported(
    only_if=lambda backend: backend.mlkem768_supported(),
    skip_message="Requires OpenSSL with ML-KEM-768 and SecP256r1 support",
)
class TestSecP256r1MLKEM768:
    """Tests for NIST P-256 + ML-KEM-768 hybrid KEM"""

    def test_generate_and_encapsulate_decapsulate(self):
        """Test basic key generation, encapsulation, and decapsulation"""
        # Generate key pair
        private_key = hybrid_kem.SecP256r1MLKEM768PrivateKey.generate()
        public_key = private_key.public_key()

        # Encapsulate
        ciphertext, encap_shared_secret = public_key.encapsulate()

        # Verify ciphertext size: 65 (P-256) + 1088 (ML-KEM-768)
        assert len(ciphertext) == 1153

        # Verify shared secret size
        assert len(encap_shared_secret) == 32

        # Decapsulate
        decap_shared_secret = private_key.decapsulate(ciphertext)

        # Verify shared secrets match
        assert encap_shared_secret == decap_shared_secret

    def test_multiple_encapsulations_different(self):
        """Verify that multiple encapsulations produce different results"""
        private_key = hybrid_kem.SecP256r1MLKEM768PrivateKey.generate()
        public_key = private_key.public_key()

        ct1, ss1 = public_key.encapsulate()
        ct2, ss2 = public_key.encapsulate()
        ct3, ss3 = public_key.encapsulate()

        # Ciphertexts should be different (randomized)
        assert ct1 != ct2
        assert ct2 != ct3
        assert ct1 != ct3

        # Shared secrets should be different
        assert ss1 != ss2
        assert ss2 != ss3
        assert ss1 != ss3

        # But all should decapsulate correctly
        assert private_key.decapsulate(ct1) == ss1
        assert private_key.decapsulate(ct2) == ss2
        assert private_key.decapsulate(ct3) == ss3

    def test_public_key_serialization(self):
        """Test public key serialization and deserialization"""
        private_key = hybrid_kem.SecP256r1MLKEM768PrivateKey.generate()
        public_key = private_key.public_key()

        # Serialize
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        # Verify size: 65 (P-256) + 1184 (ML-KEM-768)
        assert len(public_bytes) == 1249

        # Deserialize
        loaded_public_key = (
            hybrid_kem.SecP256r1MLKEM768PublicKey.from_public_bytes(
                public_bytes
            )
        )

        # Verify it works
        ct, ss = loaded_public_key.encapsulate()
        assert len(ct) == 1153
        assert len(ss) == 32

        # Should be able to decapsulate with original private key
        decap_ss = private_key.decapsulate(ct)
        assert decap_ss == ss

    def test_private_key_serialization(self):
        """Test private key serialization and deserialization"""
        private_key = hybrid_kem.SecP256r1MLKEM768PrivateKey.generate()

        # Serialize
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # Verify size: 32 (P-256) + 2400 (ML-KEM-768)
        assert len(private_bytes) == 2432

        # Deserialize
        loaded_private_key = (
            hybrid_kem.SecP256r1MLKEM768PrivateKey.from_private_bytes(
                private_bytes
            )
        )

        # Verify it works - encapsulate with original public key
        public_key = private_key.public_key()
        ct, ss1 = public_key.encapsulate()

        # Decapsulate with loaded private key
        ss2 = loaded_private_key.decapsulate(ct)

        # Should match
        assert ss1 == ss2

    def test_invalid_ciphertext_length(self):
        """Test that invalid ciphertext length raises error"""
        private_key = hybrid_kem.SecP256r1MLKEM768PrivateKey.generate()

        with pytest.raises(ValueError, match="Invalid ciphertext length"):
            private_key.decapsulate(b"too short")

        with pytest.raises(ValueError, match="Invalid ciphertext length"):
            private_key.decapsulate(b"x" * 1000)  # Wrong size

    def test_invalid_public_key_bytes(self):
        """Test that invalid public key bytes raise error"""
        with pytest.raises(ValueError, match="Invalid key length"):
            hybrid_kem.SecP256r1MLKEM768PublicKey.from_public_bytes(
                b"too short"
            )

        with pytest.raises(ValueError, match="Invalid key length"):
            hybrid_kem.SecP256r1MLKEM768PublicKey.from_public_bytes(
                b"x" * 1000
            )

    def test_invalid_private_key_bytes(self):
        """Test that invalid private key bytes raise error"""
        with pytest.raises(ValueError, match="Invalid key length"):
            hybrid_kem.SecP256r1MLKEM768PrivateKey.from_private_bytes(
                b"too short"
            )

        with pytest.raises(ValueError, match="Invalid key length"):
            hybrid_kem.SecP256r1MLKEM768PrivateKey.from_private_bytes(
                b"x" * 1000
            )

    def test_roundtrip_full_workflow(self):
        """Test complete workflow: generate, serialize, deserialize, use"""
        # Generate keys
        private_key = hybrid_kem.SecP256r1MLKEM768PrivateKey.generate()
        public_key = private_key.public_key()

        # Serialize both keys
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        # Deserialize
        loaded_private = (
            hybrid_kem.SecP256r1MLKEM768PrivateKey.from_private_bytes(
                private_bytes
            )
        )
        loaded_public = (
            hybrid_kem.SecP256r1MLKEM768PublicKey.from_public_bytes(
                public_bytes
            )
        )

        # Use loaded public key to encapsulate
        ct, ss1 = loaded_public.encapsulate()

        # Use loaded private key to decapsulate
        ss2 = loaded_private.decapsulate(ct)

        # Should match
        assert ss1 == ss2


@pytest.mark.supported(
    only_if=lambda backend: backend.mlkem1024_supported(),
    skip_message="Requires OpenSSL with ML-KEM-1024 and SecP384r1 support",
)
class TestSecP384r1MLKEM1024:
    """Tests for NIST P-384 + ML-KEM-1024 hybrid KEM"""

    def test_generate_and_encapsulate_decapsulate(self):
        """Test basic key generation, encapsulation, and decapsulation"""
        private_key = hybrid_kem.SecP384r1MLKEM1024PrivateKey.generate()
        public_key = private_key.public_key()

        # Encapsulate
        ciphertext, encap_shared_secret = public_key.encapsulate()

        # Verify ciphertext size: 97 (P-384) + 1568 (ML-KEM-1024)
        assert len(ciphertext) == 1665

        # Verify shared secret size
        assert len(encap_shared_secret) == 32

        # Decapsulate
        decap_shared_secret = private_key.decapsulate(ciphertext)

        # Verify shared secrets match
        assert encap_shared_secret == decap_shared_secret

    def test_public_key_serialization(self):
        """Test public key serialization"""
        private_key = hybrid_kem.SecP384r1MLKEM1024PrivateKey.generate()
        public_key = private_key.public_key()

        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        # Verify size: 97 (P-384) + 1568 (ML-KEM-1024)
        assert len(public_bytes) == 1665

        # Deserialize and verify
        loaded_public_key = (
            hybrid_kem.SecP384r1MLKEM1024PublicKey.from_public_bytes(
                public_bytes
            )
        )

        ct, ss = loaded_public_key.encapsulate()
        assert len(ct) == 1665
        assert len(ss) == 32
        assert private_key.decapsulate(ct) == ss

    def test_private_key_serialization(self):
        """Test private key serialization"""
        private_key = hybrid_kem.SecP384r1MLKEM1024PrivateKey.generate()

        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # Verify size: 48 (P-384) + 3168 (ML-KEM-1024)
        assert len(private_bytes) == 3216

        # Deserialize and verify
        loaded_private_key = (
            hybrid_kem.SecP384r1MLKEM1024PrivateKey.from_private_bytes(
                private_bytes
            )
        )

        public_key = private_key.public_key()
        ct, ss1 = public_key.encapsulate()
        ss2 = loaded_private_key.decapsulate(ct)
        assert ss1 == ss2

    def test_multiple_encapsulations(self):
        """Verify randomization"""
        private_key = hybrid_kem.SecP384r1MLKEM1024PrivateKey.generate()
        public_key = private_key.public_key()

        ct1, ss1 = public_key.encapsulate()
        ct2, ss2 = public_key.encapsulate()

        # Should be different
        assert ct1 != ct2
        assert ss1 != ss2

        # But both should decapsulate correctly
        assert private_key.decapsulate(ct1) == ss1
        assert private_key.decapsulate(ct2) == ss2

    def test_invalid_ciphertext_length(self):
        """Test error handling for invalid ciphertext"""
        private_key = hybrid_kem.SecP384r1MLKEM1024PrivateKey.generate()

        with pytest.raises(ValueError, match="Invalid ciphertext length"):
            private_key.decapsulate(b"wrong size")

    def test_different_keys_different_secrets(self):
        """Verify different key pairs produce different shared secrets"""
        private1 = hybrid_kem.SecP384r1MLKEM1024PrivateKey.generate()
        private2 = hybrid_kem.SecP384r1MLKEM1024PrivateKey.generate()

        public1 = private1.public_key()

        ct1, ss1_from_pub1 = public1.encapsulate()
        ss1_from_priv2 = private2.decapsulate(ct1)

        # Should be different
        assert ss1_from_pub1 != ss1_from_priv2

        # Correct key recovers correct secret
        ss1_from_priv1 = private1.decapsulate(ct1)
        assert ss1_from_pub1 == ss1_from_priv1
