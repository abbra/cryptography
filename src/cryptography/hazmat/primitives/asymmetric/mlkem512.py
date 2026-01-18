# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import abc

from cryptography.exceptions import UnsupportedAlgorithm, _Reasons
from cryptography.hazmat.bindings._rust import openssl as rust_openssl
from cryptography.hazmat.primitives import _serialization
from cryptography.utils import Buffer


class MlKem512PublicKey(metaclass=abc.ABCMeta):
    @classmethod
    def from_public_bytes(cls, data: bytes) -> MlKem512PublicKey:
        from cryptography.hazmat.backends.openssl.backend import backend

        if not backend.mlkem512_supported():
            raise UnsupportedAlgorithm(
                "ML-KEM-512 is not supported by this version of OpenSSL.",
                _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM,
            )
        mlkem512 = getattr(rust_openssl, "mlkem512")
        return mlkem512.from_public_bytes(data)

    @abc.abstractmethod
    def public_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PublicFormat,
    ) -> bytes:
        """
        The serialized bytes of the public key.
        """

    @abc.abstractmethod
    def public_bytes_raw(self) -> bytes:
        """
        The raw bytes of the public key.
        Equivalent to public_bytes(Raw, Raw).
        """

    @abc.abstractmethod
    def encapsulate(self) -> tuple[bytes, bytes]:
        """
        Encapsulate a shared secret.

        Returns:
            tuple[bytes, bytes]: A tuple of (ciphertext, shared_secret).
            The ciphertext should be sent to the holder of the private key,
            who can decapsulate it to recover the same shared_secret.
        """

    @abc.abstractmethod
    def __eq__(self, other: object) -> bool:
        """
        Checks equality.
        """

    @abc.abstractmethod
    def __copy__(self) -> MlKem512PublicKey:
        """
        Returns a copy.
        """

    @abc.abstractmethod
    def __deepcopy__(self, memo: dict) -> MlKem512PublicKey:
        """
        Returns a deep copy.
        """


if hasattr(rust_openssl, "mlkem512"):
    MlKem512PublicKey.register(rust_openssl.mlkem512.MlKem512PublicKey)


class MlKem512PrivateKey(metaclass=abc.ABCMeta):
    @classmethod
    def generate(cls) -> MlKem512PrivateKey:
        from cryptography.hazmat.backends.openssl.backend import backend

        if not backend.mlkem512_supported():
            raise UnsupportedAlgorithm(
                "ML-KEM-512 is not supported by this version of OpenSSL.",
                _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM,
            )

        mlkem512 = getattr(rust_openssl, "mlkem512")
        return mlkem512.generate_key()

    @classmethod
    def from_private_bytes(cls, data: Buffer) -> MlKem512PrivateKey:
        from cryptography.hazmat.backends.openssl.backend import backend

        if not backend.mlkem512_supported():
            raise UnsupportedAlgorithm(
                "ML-KEM-512 is not supported by this version of OpenSSL.",
                _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM,
            )

        mlkem512 = getattr(rust_openssl, "mlkem512")
        return mlkem512.from_private_bytes(data)

    @abc.abstractmethod
    def public_key(self) -> MlKem512PublicKey:
        """
        The MlKem512PublicKey derived from the private key.
        """

    @abc.abstractmethod
    def private_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PrivateFormat,
        encryption_algorithm: _serialization.KeySerializationEncryption,
    ) -> bytes:
        """
        The serialized bytes of the private key.
        """

    @abc.abstractmethod
    def private_bytes_raw(self) -> bytes:
        """
        The raw bytes of the private key.
        Equivalent to private_bytes(Raw, Raw, NoEncryption()).
        """

    @abc.abstractmethod
    def decapsulate(self, ciphertext: Buffer) -> bytes:
        """
        Decapsulate a shared secret from ciphertext.

        Args:
            ciphertext: The ciphertext produced by encapsulate() on the
                corresponding public key.

        Returns:
            bytes: The shared_secret, which will be identical to the one
            returned from the encapsulate() call that produced the ciphertext.
        """

    @abc.abstractmethod
    def __copy__(self) -> MlKem512PrivateKey:
        """
        Returns a copy.
        """

    @abc.abstractmethod
    def __deepcopy__(self, memo: dict) -> MlKem512PrivateKey:
        """
        Returns a deep copy.
        """


if hasattr(rust_openssl, "mlkem512"):
    MlKem512PrivateKey.register(rust_openssl.mlkem512.MlKem512PrivateKey)
