# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import copy

import pytest

from cryptography.exceptions import _Reasons
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.mlkem768 import (
    MlKem768PrivateKey,
    MlKem768PublicKey,
)

from ...doubles import DummyKeySerializationEncryption
from ...utils import raises_unsupported_algorithm


@pytest.mark.supported(
    only_if=lambda backend: not backend.mlkem768_supported(),
    skip_message="Requires OpenSSL without ML-KEM-768 support",
)
def test_mlkem768_unsupported(backend):
    with raises_unsupported_algorithm(
        _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
    ):
        MlKem768PublicKey.from_public_bytes(b"0" * 1184)

    with raises_unsupported_algorithm(
        _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
    ):
        MlKem768PrivateKey.from_private_bytes(b"0" * 2400)

    with raises_unsupported_algorithm(
        _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
    ):
        MlKem768PrivateKey.generate()


@pytest.mark.supported(
    only_if=lambda backend: backend.mlkem768_supported(),
    skip_message="Requires OpenSSL with ML-KEM-768 support",
)
class TestMlKem768:
    def test_encapsulate_decapsulate(self, backend):
        private_key = MlKem768PrivateKey.generate()
        public_key = private_key.public_key()

        # Encapsulate
        ciphertext, shared_secret_sender = public_key.encapsulate()

        # ML-KEM-768 ciphertext is 1088 bytes
        assert len(ciphertext) == 1088
        # All ML-KEM variants produce 32-byte shared secrets
        assert len(shared_secret_sender) == 32

        # Decapsulate
        shared_secret_receiver = private_key.decapsulate(ciphertext)

        # Shared secrets must match
        assert shared_secret_sender == shared_secret_receiver
        assert len(shared_secret_receiver) == 32

    def test_decapsulate_invalid_ciphertext(self, backend):
        private_key = MlKem768PrivateKey.generate()

        # Invalid ciphertext would raise ValueError or produce different secret
        invalid_ciphertext = b"0" * 1088
        # This should not raise, but the shared secret will be different
        # ML-KEM decapsulation always succeeds (implicit rejection)
        shared_secret = private_key.decapsulate(invalid_ciphertext)
        assert len(shared_secret) == 32

    def test_decapsulate_wrong_length(self, backend):
        private_key = MlKem768PrivateKey.generate()

        with pytest.raises(ValueError):
            private_key.decapsulate(b"0" * 100)

    def test_encapsulate_deterministic(self, backend):
        # Each encapsulation produce different results (due to randomness)
        private_key = MlKem768PrivateKey.generate()
        public_key = private_key.public_key()

        ct1, ss1 = public_key.encapsulate()
        ct2, ss2 = public_key.encapsulate()

        # Ciphertexts should be different (randomized)
        assert ct1 != ct2
        # Shared secrets should be different
        assert ss1 != ss2

    def test_encapsulate_buffer(self, backend):
        private_key = MlKem768PrivateKey.generate()
        public_key = private_key.public_key()

        ciphertext, shared_secret = public_key.encapsulate()

        # Test decapsulate with bytearray
        shared_secret2 = private_key.decapsulate(bytearray(ciphertext))
        assert shared_secret == shared_secret2

    def test_generate(self, backend):
        key = MlKem768PrivateKey.generate()
        assert key
        assert key.public_key()

    def test_pub_priv_bytes_raw(self, backend):
        private_key = MlKem768PrivateKey.generate()
        private_raw = private_key.private_bytes_raw()
        public_raw = private_key.public_key().public_bytes_raw()

        # ML-KEM-768 key sizes
        assert len(private_raw) == 2400
        assert len(public_raw) == 1184

        # Verify we can load the keys back
        loaded_private = MlKem768PrivateKey.from_private_bytes(private_raw)
        loaded_public = MlKem768PublicKey.from_public_bytes(public_raw)

        # Verify the loaded keys work
        ciphertext, shared_secret1 = loaded_public.encapsulate()
        shared_secret2 = loaded_private.decapsulate(ciphertext)
        assert shared_secret1 == shared_secret2

    def test_load_public_bytes(self, backend):
        public_key = MlKem768PrivateKey.generate().public_key()
        public_bytes = public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        public_key2 = MlKem768PublicKey.from_public_bytes(public_bytes)
        assert public_bytes == public_key2.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def test_public_bytes_der(self, backend):
        private_key = MlKem768PrivateKey.generate()
        public_key = private_key.public_key()
        public_der = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        # Load it back
        loaded_public = serialization.load_der_public_key(public_der)
        assert isinstance(loaded_public, MlKem768PublicKey)

        # Verify it works
        ciphertext, ss1 = loaded_public.encapsulate()
        ss2 = private_key.decapsulate(ciphertext)
        assert ss1 == ss2

    def test_public_bytes_pem(self, backend):
        private_key = MlKem768PrivateKey.generate()
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        assert b"BEGIN PUBLIC KEY" in public_pem

        # Load it back
        loaded_public = serialization.load_pem_public_key(public_pem)
        assert isinstance(loaded_public, MlKem768PublicKey)

    def test_private_bytes_der(self, backend):
        private_key = MlKem768PrivateKey.generate()
        private_der = private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        # Load it back
        loaded_private = serialization.load_der_private_key(
            private_der, password=None
        )
        assert isinstance(loaded_private, MlKem768PrivateKey)

        # Verify it works
        public_key = private_key.public_key()
        ciphertext, ss1 = public_key.encapsulate()
        ss2 = loaded_private.decapsulate(ciphertext)
        assert ss1 == ss2

    def test_private_bytes_pem(self, backend):
        private_key = MlKem768PrivateKey.generate()
        private_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        assert b"BEGIN PRIVATE KEY" in private_pem

        # Load it back
        loaded_private = serialization.load_pem_private_key(
            private_pem, password=None
        )
        assert isinstance(loaded_private, MlKem768PrivateKey)

    def test_private_bytes_encrypted(self, backend):
        private_key = MlKem768PrivateKey.generate()
        private_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(b"password"),
        )
        assert b"BEGIN ENCRYPTED PRIVATE KEY" in private_pem

        # Load it back with password
        loaded_private = serialization.load_pem_private_key(
            private_pem, password=b"password"
        )
        assert isinstance(loaded_private, MlKem768PrivateKey)

    def test_private_bytes_raw_unsupported_encryption(self, backend):
        private_key = MlKem768PrivateKey.generate()
        with pytest.raises(ValueError):
            private_key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.BestAvailableEncryption(b"password"),
            )

    def test_private_bytes_invalid_encoding(self, backend):
        private_key = MlKem768PrivateKey.generate()
        with pytest.raises(ValueError):
            private_key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )

    def test_public_bytes_invalid_encoding(self, backend):
        public_key = MlKem768PrivateKey.generate().public_key()
        with pytest.raises(ValueError):
            public_key.public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )

    def test_invalid_private_bytes(self, backend):
        with pytest.raises(ValueError):
            MlKem768PrivateKey.from_private_bytes(b"0" * 100)

    def test_invalid_public_bytes(self, backend):
        with pytest.raises(ValueError):
            MlKem768PublicKey.from_public_bytes(b"0" * 100)

    def test_copy(self, backend):
        private_key = MlKem768PrivateKey.generate()
        private_key_copy = copy.copy(private_key)
        public_key = private_key.public_key()
        public_key_copy = copy.copy(public_key)

        # Verify copies work
        ciphertext, ss1 = public_key_copy.encapsulate()
        ss2 = private_key_copy.decapsulate(ciphertext)
        assert ss1 == ss2

    def test_deepcopy(self, backend):
        private_key = MlKem768PrivateKey.generate()
        private_key_copy = copy.deepcopy(private_key)
        public_key = private_key.public_key()
        public_key_copy = copy.deepcopy(public_key)

        # Verify copies work
        ciphertext, ss1 = public_key_copy.encapsulate()
        ss2 = private_key_copy.decapsulate(ciphertext)
        assert ss1 == ss2

    def test_equality(self, backend):
        private_key1 = MlKem768PrivateKey.generate()
        private_key2 = MlKem768PrivateKey.generate()

        assert private_key1 == private_key1
        assert private_key1 != private_key2
        assert private_key1 != object()

        public_key1 = private_key1.public_key()
        public_key2 = private_key2.public_key()

        assert public_key1 == public_key1
        assert public_key1 != public_key2
        assert public_key1 != object()

    def test_private_bytes_unsupported_type(self, backend):
        private_key = MlKem768PrivateKey.generate()
        with pytest.raises(ValueError):
            private_key.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                DummyKeySerializationEncryption(),
            )

    def test_roundtrip_encapsulation(self, backend):
        # Test that we can serialize keys, load them, and do encapsulation
        private_key = MlKem768PrivateKey.generate()
        public_key = private_key.public_key()

        # Serialize both keys
        private_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        public_pem = public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Load them back
        loaded_private = serialization.load_pem_private_key(
            private_pem, password=None
        )
        loaded_public = serialization.load_pem_public_key(public_pem)

        assert isinstance(loaded_public, MlKem768PublicKey)
        assert isinstance(loaded_private, MlKem768PrivateKey)
        # Do encapsulation/decapsulation
        ciphertext, ss1 = loaded_public.encapsulate()
        ss2 = loaded_private.decapsulate(ciphertext)

        assert ss1 == ss2
        assert len(ss1) == 32
        assert len(ciphertext) == 1088
