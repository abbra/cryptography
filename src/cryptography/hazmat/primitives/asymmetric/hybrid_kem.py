# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

"""
Hybrid Key Encapsulation Mechanisms (KEMs)

Combines classical key exchange with post-quantum ML-KEM for defense-in-depth.
Supports:
- X25519 + ML-KEM-768 (X-Wing / draft-connolly-cfrg-xwing-kem)
- X448 + ML-KEM-1024
- ECDH P-256 + ML-KEM-768
- ECDH P-384 + ML-KEM-1024

The hybrid approach provides security even if either component is compromised.
"""

from __future__ import annotations

import abc
import typing

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    ec,
    mlkem768,
    mlkem1024,
    x448,
    x25519,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class HybridKEMPublicKey(metaclass=abc.ABCMeta):
    """Base class for hybrid KEM public keys"""

    @abc.abstractmethod
    def encapsulate(self) -> tuple[bytes, bytes]:
        """
        Encapsulate a shared secret using both classical and PQ components.

        Returns:
            tuple[bytes, bytes]: (combined_ciphertext, shared_secret)
            The ciphertext contains both classical and PQ ciphertexts.
        """

    @abc.abstractmethod
    def public_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PublicFormat,
    ) -> bytes:
        """Serialize the hybrid public key"""


class HybridKEMPrivateKey(metaclass=abc.ABCMeta):
    """Base class for hybrid KEM private keys"""

    @abc.abstractmethod
    def decapsulate(self, ciphertext: bytes) -> bytes:
        """
        Decapsulate a shared secret from combined ciphertext.

        Args:
            ciphertext: Combined ciphertext from encapsulate()

        Returns:
            bytes: The shared secret (derived from both components)
        """

    @abc.abstractmethod
    def public_key(self) -> HybridKEMPublicKey:
        """Get the corresponding public key"""

    @abc.abstractmethod
    def private_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PrivateFormat,
        encryption_algorithm: serialization.KeySerializationEncryption,
    ) -> bytes:
        """Serialize the hybrid private key"""


class X25519MLKEM768PublicKey(HybridKEMPublicKey):
    """
    Hybrid public key combining X25519 and ML-KEM-768.

    Also known as X-Wing (draft-connolly-cfrg-xwing-kem).
    Provides NIST Level 3 post-quantum security with classical ECDH fallback.
    """

    def __init__(
        self,
        x25519_key: x25519.X25519PublicKey,
        mlkem_key: mlkem768.MlKem768PublicKey,
    ):
        self._x25519_key = x25519_key
        self._mlkem_key = mlkem_key

    def encapsulate(self) -> tuple[bytes, bytes]:
        """
        Encapsulate using both X25519 ECDH and ML-KEM-768.

        Returns:
            tuple[bytes, bytes]: (ciphertext, shared_secret)
            - ciphertext: 32 bytes (X25519 ephemeral public) +
                  1088 bytes (ML-KEM-768 ciphertext)
            - shared_secret: 32 bytes (HKDF-derived from both secrets)
        """
        # Generate ephemeral X25519 key for ECDH
        x25519_ephemeral_private = x25519.X25519PrivateKey.generate()
        x25519_ephemeral_public = x25519_ephemeral_private.public_key()

        # Perform X25519 ECDH
        x25519_shared = x25519_ephemeral_private.exchange(self._x25519_key)

        # Encapsulate with ML-KEM-768
        mlkem_ciphertext, mlkem_shared = self._mlkem_key.encapsulate()

        # Combine ciphertexts: X25519 ephemeral public (32 bytes) +
        #                      ML-KEM ciphertext (1088 bytes)
        x25519_public_bytes = x25519_ephemeral_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        combined_ciphertext = x25519_public_bytes + mlkem_ciphertext

        # Derive shared secret using HKDF
        # Concatenate: X25519 shared || ML-KEM shared
        combined_input = x25519_shared + mlkem_shared

        # Use HKDF to derive final shared secret
        shared_secret = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"X25519MLKEM768",
        ).derive(combined_input)

        return combined_ciphertext, shared_secret

    def public_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PublicFormat,
    ) -> bytes:
        """
        Serialize the hybrid public key.

        Currently only supports Raw encoding which produces:
        32 bytes (X25519) + 1184 bytes (ML-KEM-768) = 1216 bytes
        """
        if (
            encoding != serialization.Encoding.Raw
            or format != serialization.PublicFormat.Raw
        ):
            raise ValueError(
                "Only Raw encoding/format is supported for hybrid keys"
            )

        x25519_bytes = self._x25519_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        mlkem_bytes = self._mlkem_key.public_bytes_raw()

        return x25519_bytes + mlkem_bytes

    @classmethod
    def from_public_bytes(cls, data: bytes) -> X25519MLKEM768PublicKey:
        """
        Load hybrid public key from raw bytes.

        Args:
            data: 1216 bytes (32 X25519 + 1184 ML-KEM-768)
        """
        if len(data) != 1216:
            raise ValueError(
                f"Invalid key length: expected 1216 bytes, got {len(data)}"
            )

        x25519_bytes = data[:32]
        mlkem_bytes = data[32:]

        x25519_key = x25519.X25519PublicKey.from_public_bytes(x25519_bytes)
        mlkem_key = mlkem768.MlKem768PublicKey.from_public_bytes(mlkem_bytes)

        return cls(x25519_key, mlkem_key)


class X25519MLKEM768PrivateKey(HybridKEMPrivateKey):
    """
    Hybrid private key combining X25519 and ML-KEM-768.
    """

    def __init__(
        self,
        x25519_key: x25519.X25519PrivateKey,
        mlkem_key: mlkem768.MlKem768PrivateKey,
    ):
        self._x25519_key = x25519_key
        self._mlkem_key = mlkem_key

    @classmethod
    def generate(cls) -> X25519MLKEM768PrivateKey:
        """Generate a new hybrid private key"""
        x25519_key = x25519.X25519PrivateKey.generate()
        mlkem_key = mlkem768.MlKem768PrivateKey.generate()
        return cls(x25519_key, mlkem_key)

    def public_key(self) -> X25519MLKEM768PublicKey:
        """Get the corresponding hybrid public key"""
        return X25519MLKEM768PublicKey(
            self._x25519_key.public_key(),
            self._mlkem_key.public_key(),
        )

    def decapsulate(self, ciphertext: bytes) -> bytes:
        """
        Decapsulate the shared secret from combined ciphertext.

        Args:
            ciphertext: 1120 bytes (32 X25519 ephemeral + 1088 ML-KEM-768)

        Returns:
            bytes: 32-byte shared secret
        """
        if len(ciphertext) != 1120:
            raise ValueError(
                "Invalid ciphertext length: "
                f"expected 1120 bytes, got {len(ciphertext)}"
            )

        # Split ciphertext
        x25519_ephemeral_bytes = ciphertext[:32]
        mlkem_ciphertext = ciphertext[32:]

        # Recover X25519 shared secret
        x25519_ephemeral_public = x25519.X25519PublicKey.from_public_bytes(
            x25519_ephemeral_bytes
        )
        x25519_shared = self._x25519_key.exchange(x25519_ephemeral_public)

        # Decapsulate ML-KEM shared secret
        mlkem_shared = self._mlkem_key.decapsulate(mlkem_ciphertext)

        # Derive shared secret using HKDF (same as encapsulate)
        combined_input = x25519_shared + mlkem_shared

        shared_secret = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"X25519MLKEM768",
        ).derive(combined_input)

        return shared_secret

    def private_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PrivateFormat,
        encryption_algorithm: serialization.KeySerializationEncryption,
    ) -> bytes:
        """
        Serialize the hybrid private key.

        Currently only supports Raw encoding which produces:
        32 bytes (X25519) + 2400 bytes (ML-KEM-768) = 2432 bytes
        """
        if (
            encoding != serialization.Encoding.Raw
            or format != serialization.PrivateFormat.Raw
        ):
            raise ValueError(
                "Only Raw encoding/format is supported for hybrid keys"
            )

        if not isinstance(encryption_algorithm, serialization.NoEncryption):
            raise ValueError(
                "Encryption is not supported for raw hybrid private keys"
            )

        x25519_bytes = self._x25519_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        mlkem_bytes = self._mlkem_key.private_bytes_raw()

        return x25519_bytes + mlkem_bytes

    @classmethod
    def from_private_bytes(cls, data: bytes) -> X25519MLKEM768PrivateKey:
        """
        Load hybrid private key from raw bytes.

        Args:
            data: 2432 bytes (32 X25519 + 2400 ML-KEM-768)
        """
        if len(data) != 2432:
            raise ValueError(
                f"Invalid key length: expected 2432 bytes, got {len(data)}"
            )

        x25519_bytes = data[:32]
        mlkem_bytes = data[32:]

        x25519_key = x25519.X25519PrivateKey.from_private_bytes(x25519_bytes)
        mlkem_key = mlkem768.MlKem768PrivateKey.from_private_bytes(mlkem_bytes)

        return cls(x25519_key, mlkem_key)


class X448MLKEM1024PublicKey(HybridKEMPublicKey):
    """
    Hybrid public key combining X448 and ML-KEM-1024.

    Provides NIST Level 5 post-quantum security with classical ECDH fallback.
    """

    def __init__(
        self,
        x448_key: x448.X448PublicKey,
        mlkem_key: mlkem1024.MlKem1024PublicKey,
    ):
        self._x448_key = x448_key
        self._mlkem_key = mlkem_key

    def encapsulate(self) -> tuple[bytes, bytes]:
        """
        Encapsulate using both X448 ECDH and ML-KEM-1024.

        Returns:
            tuple[bytes, bytes]: (ciphertext, shared_secret)
            - ciphertext: 56 bytes (X448) + 1568 bytes (ML-KEM-1024)
            - shared_secret: 32 bytes
        """
        # Generate ephemeral X448 key
        x448_ephemeral_private = x448.X448PrivateKey.generate()
        x448_ephemeral_public = x448_ephemeral_private.public_key()

        # Perform X448 ECDH
        x448_shared = x448_ephemeral_private.exchange(self._x448_key)

        # Encapsulate with ML-KEM-1024
        mlkem_ciphertext, mlkem_shared = self._mlkem_key.encapsulate()

        # Combine ciphertexts
        x448_public_bytes = x448_ephemeral_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        combined_ciphertext = x448_public_bytes + mlkem_ciphertext

        # Derive shared secret
        combined_input = x448_shared + mlkem_shared

        shared_secret = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"X448MLKEM1024",
        ).derive(combined_input)

        return combined_ciphertext, shared_secret

    def public_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PublicFormat,
    ) -> bytes:
        """Serialize sizes: 56b (X448) + 1568b (ML-KEM-1024) = 1624b"""
        if (
            encoding != serialization.Encoding.Raw
            or format != serialization.PublicFormat.Raw
        ):
            raise ValueError("Only Raw encoding/format is currently supported")

        x448_bytes = self._x448_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        mlkem_bytes = self._mlkem_key.public_bytes_raw()

        return x448_bytes + mlkem_bytes

    @classmethod
    def from_public_bytes(cls, data: bytes) -> X448MLKEM1024PublicKey:
        """Load from 1624 bytes"""
        if len(data) != 1624:
            raise ValueError(
                f"Invalid key length: expected 1624 bytes, got {len(data)}"
            )

        x448_bytes = data[:56]
        mlkem_bytes = data[56:]

        x448_key = x448.X448PublicKey.from_public_bytes(x448_bytes)
        mlkem_key = mlkem1024.MlKem1024PublicKey.from_public_bytes(mlkem_bytes)

        return cls(x448_key, mlkem_key)


class X448MLKEM1024PrivateKey(HybridKEMPrivateKey):
    """Hybrid private key combining X448 and ML-KEM-1024"""

    def __init__(
        self,
        x448_key: x448.X448PrivateKey,
        mlkem_key: mlkem1024.MlKem1024PrivateKey,
    ):
        self._x448_key = x448_key
        self._mlkem_key = mlkem_key

    @classmethod
    def generate(cls) -> X448MLKEM1024PrivateKey:
        """Generate a new hybrid private key"""
        x448_key = x448.X448PrivateKey.generate()
        mlkem_key = mlkem1024.MlKem1024PrivateKey.generate()
        return cls(x448_key, mlkem_key)

    def public_key(self) -> X448MLKEM1024PublicKey:
        """Get the corresponding hybrid public key"""
        return X448MLKEM1024PublicKey(
            self._x448_key.public_key(),
            self._mlkem_key.public_key(),
        )

    def decapsulate(self, ciphertext: bytes) -> bytes:
        """Decapsulate from 1624 bytes (56 X448 + 1568 ML-KEM-1024)"""
        if len(ciphertext) != 1624:
            raise ValueError(
                "Invalid ciphertext length: "
                f"expected 1624 bytes, got {len(ciphertext)}"
            )

        x448_ephemeral_bytes = ciphertext[:56]
        mlkem_ciphertext = ciphertext[56:]

        x448_ephemeral_public = x448.X448PublicKey.from_public_bytes(
            x448_ephemeral_bytes
        )
        x448_shared = self._x448_key.exchange(x448_ephemeral_public)

        mlkem_shared = self._mlkem_key.decapsulate(mlkem_ciphertext)

        combined_input = x448_shared + mlkem_shared

        shared_secret = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"X448MLKEM1024",
        ).derive(combined_input)

        return shared_secret

    def private_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PrivateFormat,
        encryption_algorithm: serialization.KeySerializationEncryption,
    ) -> bytes:
        """Serialize sizes: 56b (X448) + 3168b (ML-KEM-1024) = 3224b"""
        if (
            encoding != serialization.Encoding.Raw
            or format != serialization.PrivateFormat.Raw
        ):
            raise ValueError("Only Raw encoding/format is currently supported")

        if not isinstance(encryption_algorithm, serialization.NoEncryption):
            raise ValueError(
                "Encryption is not supported for raw hybrid private keys"
            )

        x448_bytes = self._x448_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        mlkem_bytes = self._mlkem_key.private_bytes_raw()

        return x448_bytes + mlkem_bytes

    @classmethod
    def from_private_bytes(cls, data: bytes) -> X448MLKEM1024PrivateKey:
        """Load from 3224 bytes"""
        if len(data) != 3224:
            raise ValueError(
                f"Invalid key length: expected 3224 bytes, got {len(data)}"
            )

        x448_bytes = data[:56]
        mlkem_bytes = data[56:]

        x448_key = x448.X448PrivateKey.from_private_bytes(x448_bytes)
        mlkem_key = mlkem1024.MlKem1024PrivateKey.from_private_bytes(
            mlkem_bytes
        )

        return cls(x448_key, mlkem_key)


class SecP256r1MLKEM768PublicKey(HybridKEMPublicKey):
    """
    Hybrid public key combining NIST P-256 (secp256r1) and ML-KEM-768.

    Provides NIST Level 3 post-quantum security with NIST-standardized
    elliptic curve fallback.
    """

    def __init__(
        self,
        ec_key: ec.EllipticCurvePublicKey,
        mlkem_key: mlkem768.MlKem768PublicKey,
    ):
        # Verify it's actually a P-256 key
        if not isinstance(ec_key.curve, ec.SECP256R1):
            raise ValueError("EC key must use SECP256R1 curve")
        self._ec_key = ec_key
        self._mlkem_key = mlkem_key

    def encapsulate(self) -> tuple[bytes, bytes]:
        """
        Encapsulate using both P-256 ECDH and ML-KEM-768.

        Returns:
            tuple[bytes, bytes]: (ciphertext, shared_secret)
            - ciphertext: 65 bytes (P-256 ephemeral public) +
                1088 bytes (ML-KEM-768)
            - shared_secret: 32 bytes (HKDF-derived)
        """
        # Generate ephemeral P-256 key for ECDH
        ec_ephemeral_private = ec.generate_private_key(ec.SECP256R1())
        ec_ephemeral_public = ec_ephemeral_private.public_key()

        # Perform P-256 ECDH
        ec_shared = ec_ephemeral_private.exchange(ec.ECDH(), self._ec_key)

        # Encapsulate with ML-KEM-768
        mlkem_ciphertext, mlkem_shared = self._mlkem_key.encapsulate()

        # Combine ciphertexts: P-256 ephemeral public (65 bytes) +
        #                      ML-KEM ciphertext (1088 bytes)
        ec_public_bytes = ec_ephemeral_public.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        combined_ciphertext = ec_public_bytes + mlkem_ciphertext

        # Derive shared secret using HKDF
        combined_input = ec_shared + mlkem_shared

        shared_secret = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"SecP256r1MLKEM768",
        ).derive(combined_input)

        return combined_ciphertext, shared_secret

    def public_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PublicFormat,
    ) -> bytes:
        """
        Serialize the hybrid public key.

        Returns: 65 bytes (P-256) + 1184 bytes (ML-KEM-768) = 1249 bytes
        """
        if (
            encoding != serialization.Encoding.Raw
            or format != serialization.PublicFormat.Raw
        ):
            raise ValueError(
                "Only Raw encoding/format is supported for hybrid keys"
            )

        ec_bytes = self._ec_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        mlkem_bytes = self._mlkem_key.public_bytes_raw()

        return ec_bytes + mlkem_bytes

    @classmethod
    def from_public_bytes(cls, data: bytes) -> SecP256r1MLKEM768PublicKey:
        """
        Load hybrid public key from raw bytes.

        Args:
            data: 1249 bytes (65 P-256 + 1184 ML-KEM-768)
        """
        if len(data) != 1249:
            raise ValueError(
                f"Invalid key length: expected 1249 bytes, got {len(data)}"
            )

        ec_bytes = data[:65]
        mlkem_bytes = data[65:]

        ec_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), ec_bytes
        )
        mlkem_key = mlkem768.MlKem768PublicKey.from_public_bytes(mlkem_bytes)

        return cls(ec_key, mlkem_key)


class SecP256r1MLKEM768PrivateKey(HybridKEMPrivateKey):
    """
    Hybrid private key combining NIST P-256 and ML-KEM-768.
    """

    def __init__(
        self,
        ec_key: ec.EllipticCurvePrivateKey,
        mlkem_key: mlkem768.MlKem768PrivateKey,
    ):
        # Verify it's actually a P-256 key
        if not isinstance(ec_key.curve, ec.SECP256R1):
            raise ValueError("EC key must use SECP256R1 curve")
        self._ec_key = ec_key
        self._mlkem_key = mlkem_key

    @classmethod
    def generate(cls) -> SecP256r1MLKEM768PrivateKey:
        """Generate a new hybrid private key"""
        ec_key = ec.generate_private_key(ec.SECP256R1())
        mlkem_key = mlkem768.MlKem768PrivateKey.generate()
        return cls(ec_key, mlkem_key)

    def public_key(self) -> SecP256r1MLKEM768PublicKey:
        """Get the corresponding hybrid public key"""
        return SecP256r1MLKEM768PublicKey(
            self._ec_key.public_key(),
            self._mlkem_key.public_key(),
        )

    def decapsulate(self, ciphertext: bytes) -> bytes:
        """
        Decapsulate the shared secret from combined ciphertext.

        Args:
            ciphertext: 1153 bytes (65 P-256 ephemeral + 1088 ML-KEM-768)

        Returns:
            bytes: 32-byte shared secret
        """
        if len(ciphertext) != 1153:
            raise ValueError(
                "Invalid ciphertext length: "
                f"expected 1153 bytes, got {len(ciphertext)}"
            )

        # Split ciphertext
        ec_ephemeral_bytes = ciphertext[:65]
        mlkem_ciphertext = ciphertext[65:]

        # Recover P-256 shared secret
        ec_ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), ec_ephemeral_bytes
        )
        ec_shared = self._ec_key.exchange(ec.ECDH(), ec_ephemeral_public)

        # Decapsulate ML-KEM
        mlkem_shared = self._mlkem_key.decapsulate(mlkem_ciphertext)

        # Derive same shared secret
        combined_input = ec_shared + mlkem_shared

        shared_secret = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"SecP256r1MLKEM768",
        ).derive(combined_input)

        return shared_secret

    def private_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PrivateFormat,
        encryption_algorithm: serialization.KeySerializationEncryption,
    ) -> bytes:
        """
        Serialize the hybrid private key.

        Returns: 32 bytes (P-256) + 2400 bytes (ML-KEM-768) = 2432 bytes
        """
        if (
            encoding != serialization.Encoding.Raw
            or format != serialization.PrivateFormat.Raw
        ):
            raise ValueError("Only Raw encoding/format is currently supported")

        if not isinstance(encryption_algorithm, serialization.NoEncryption):
            raise ValueError("Encryption is not supported for raw hybrid keys")

        # Extract EC private key scalar value
        ec_private_value = self._ec_key.private_numbers().private_value
        ec_bytes = ec_private_value.to_bytes(32, byteorder="big")
        mlkem_bytes = self._mlkem_key.private_bytes_raw()

        return ec_bytes + mlkem_bytes

    @classmethod
    def from_private_bytes(cls, data: bytes) -> SecP256r1MLKEM768PrivateKey:
        """
        Load hybrid private key from raw bytes.

        Args:
            data: 2432 bytes (32 P-256 + 2400 ML-KEM-768)
        """
        if len(data) != 2432:
            raise ValueError(
                f"Invalid key length: expected 2432 bytes, got {len(data)}"
            )

        ec_bytes = data[:32]
        mlkem_bytes = data[32:]

        ec_key = ec.derive_private_key(
            int.from_bytes(ec_bytes, byteorder="big"), ec.SECP256R1()
        )
        mlkem_key = mlkem768.MlKem768PrivateKey.from_private_bytes(mlkem_bytes)

        return cls(ec_key, mlkem_key)


class SecP384r1MLKEM1024PublicKey(HybridKEMPublicKey):
    """
    Hybrid public key combining NIST P-384 (secp384r1) and ML-KEM-1024.

    Provides NIST Level 5 post-quantum security with NIST-standardized
    elliptic curve fallback.
    """

    def __init__(
        self,
        ec_key: ec.EllipticCurvePublicKey,
        mlkem_key: mlkem1024.MlKem1024PublicKey,
    ):
        # Verify it's actually a P-384 key
        if not isinstance(ec_key.curve, ec.SECP384R1):
            raise ValueError("EC key must use SECP384R1 curve")
        self._ec_key = ec_key
        self._mlkem_key = mlkem_key

    def encapsulate(self) -> tuple[bytes, bytes]:
        """
        Encapsulate using both P-384 ECDH and ML-KEM-1024.

        Returns:
            tuple[bytes, bytes]: (ciphertext, shared_secret)
            - ciphertext: 97 bytes (P-384 ephemeral public) +
                1568 bytes (ML-KEM-1024)
            - shared_secret: 32 bytes
        """
        # Generate ephemeral P-384 key for ECDH
        ec_ephemeral_private = ec.generate_private_key(ec.SECP384R1())
        ec_ephemeral_public = ec_ephemeral_private.public_key()

        # Perform P-384 ECDH
        ec_shared = ec_ephemeral_private.exchange(ec.ECDH(), self._ec_key)

        # Encapsulate with ML-KEM-1024
        mlkem_ciphertext, mlkem_shared = self._mlkem_key.encapsulate()

        # Combine ciphertexts: P-384 ephemeral public (97 bytes) +
        #                      ML-KEM ciphertext (1568 bytes)
        ec_public_bytes = ec_ephemeral_public.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        combined_ciphertext = ec_public_bytes + mlkem_ciphertext

        # Derive shared secret using HKDF
        combined_input = ec_shared + mlkem_shared

        shared_secret = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"SecP384r1MLKEM1024",
        ).derive(combined_input)

        return combined_ciphertext, shared_secret

    def public_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PublicFormat,
    ) -> bytes:
        """
        Serialize the hybrid public key.

        Returns: 97 bytes (P-384) + 1568 bytes (ML-KEM-1024) = 1665 bytes
        """
        if (
            encoding != serialization.Encoding.Raw
            or format != serialization.PublicFormat.Raw
        ):
            raise ValueError(
                "Only Raw encoding/format is supported for hybrid keys"
            )

        ec_bytes = self._ec_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        mlkem_bytes = self._mlkem_key.public_bytes_raw()

        return ec_bytes + mlkem_bytes

    @classmethod
    def from_public_bytes(cls, data: bytes) -> SecP384r1MLKEM1024PublicKey:
        """
        Load hybrid public key from raw bytes.

        Args:
            data: 1665 bytes (97 P-384 + 1568 ML-KEM-1024)
        """
        if len(data) != 1665:
            raise ValueError(
                f"Invalid key length: expected 1665 bytes, got {len(data)}"
            )

        ec_bytes = data[:97]
        mlkem_bytes = data[97:]

        ec_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP384R1(), ec_bytes
        )
        mlkem_key = mlkem1024.MlKem1024PublicKey.from_public_bytes(mlkem_bytes)

        return cls(ec_key, mlkem_key)


class SecP384r1MLKEM1024PrivateKey(HybridKEMPrivateKey):
    """
    Hybrid private key combining NIST P-384 and ML-KEM-1024.
    """

    def __init__(
        self,
        ec_key: ec.EllipticCurvePrivateKey,
        mlkem_key: mlkem1024.MlKem1024PrivateKey,
    ):
        # Verify it's actually a P-384 key
        if not isinstance(ec_key.curve, ec.SECP384R1):
            raise ValueError("EC key must use SECP384R1 curve")
        self._ec_key = ec_key
        self._mlkem_key = mlkem_key

    @classmethod
    def generate(cls) -> SecP384r1MLKEM1024PrivateKey:
        """Generate a new hybrid private key"""
        ec_key = ec.generate_private_key(ec.SECP384R1())
        mlkem_key = mlkem1024.MlKem1024PrivateKey.generate()
        return cls(ec_key, mlkem_key)

    def public_key(self) -> SecP384r1MLKEM1024PublicKey:
        """Get the corresponding hybrid public key"""
        return SecP384r1MLKEM1024PublicKey(
            self._ec_key.public_key(),
            self._mlkem_key.public_key(),
        )

    def decapsulate(self, ciphertext: bytes) -> bytes:
        """
        Decapsulate the shared secret from combined ciphertext.

        Args:
            ciphertext: 1665 bytes (97 P-384 ephemeral + 1568 ML-KEM-1024)

        Returns:
            bytes: 32-byte shared secret
        """
        if len(ciphertext) != 1665:
            raise ValueError(
                "Invalid ciphertext length: "
                f"expected 1665 bytes, got {len(ciphertext)}"
            )

        # Split ciphertext
        ec_ephemeral_bytes = ciphertext[:97]
        mlkem_ciphertext = ciphertext[97:]

        # Recover P-384 shared secret
        ec_ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP384R1(), ec_ephemeral_bytes
        )
        ec_shared = self._ec_key.exchange(ec.ECDH(), ec_ephemeral_public)

        # Decapsulate ML-KEM
        mlkem_shared = self._mlkem_key.decapsulate(mlkem_ciphertext)

        # Derive same shared secret
        combined_input = ec_shared + mlkem_shared

        shared_secret = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"SecP384r1MLKEM1024",
        ).derive(combined_input)

        return shared_secret

    def private_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PrivateFormat,
        encryption_algorithm: serialization.KeySerializationEncryption,
    ) -> bytes:
        """
        Serialize the hybrid private key.

        Returns: 48 bytes (P-384) + 3168 bytes (ML-KEM-1024) = 3216 bytes
        """
        if (
            encoding != serialization.Encoding.Raw
            or format != serialization.PrivateFormat.Raw
        ):
            raise ValueError("Only Raw encoding/format is currently supported")

        if not isinstance(encryption_algorithm, serialization.NoEncryption):
            raise ValueError("Encryption is not supported for raw hybrid keys")

        # Extract EC private key scalar value
        ec_private_value = self._ec_key.private_numbers().private_value
        ec_bytes = ec_private_value.to_bytes(48, byteorder="big")
        mlkem_bytes = self._mlkem_key.private_bytes_raw()

        return ec_bytes + mlkem_bytes

    @classmethod
    def from_private_bytes(cls, data: bytes) -> SecP384r1MLKEM1024PrivateKey:
        """
        Load hybrid private key from raw bytes.

        Args:
            data: 3216 bytes (48 P-384 + 3168 ML-KEM-1024)
        """
        if len(data) != 3216:
            raise ValueError(
                f"Invalid key length: expected 3216 bytes, got {len(data)}"
            )

        ec_bytes = data[:48]
        mlkem_bytes = data[48:]

        ec_key = ec.derive_private_key(
            int.from_bytes(ec_bytes, byteorder="big"), ec.SECP384R1()
        )
        mlkem_key = mlkem1024.MlKem1024PrivateKey.from_private_bytes(
            mlkem_bytes
        )

        return cls(ec_key, mlkem_key)


# Type aliases for convenience
HybridKEMPublicKeyTypes = typing.Union[
    X25519MLKEM768PublicKey,
    X448MLKEM1024PublicKey,
    SecP256r1MLKEM768PublicKey,
    SecP384r1MLKEM1024PublicKey,
]

HybridKEMPrivateKeyTypes = typing.Union[
    X25519MLKEM768PrivateKey,
    X448MLKEM1024PrivateKey,
    SecP256r1MLKEM768PrivateKey,
    SecP384r1MLKEM1024PrivateKey,
]
