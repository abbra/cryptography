# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import abc

from cryptography.exceptions import UnsupportedAlgorithm, _Reasons
from cryptography.hazmat.bindings._rust import openssl as rust_openssl
from cryptography.hazmat.primitives import _serialization
from cryptography.utils import Buffer


class MlDsa87PublicKey(metaclass=abc.ABCMeta):
    @classmethod
    def from_public_bytes(cls, data: bytes) -> MlDsa87PublicKey:
        from cryptography.hazmat.backends.openssl.backend import backend

        if not backend.mldsa87_supported():
            raise UnsupportedAlgorithm(
                "ML-DSA-87 is not supported by this version of OpenSSL.",
                _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM,
            )
        mldsa87 = getattr(rust_openssl, "mldsa87")
        return mldsa87.from_public_bytes(data)

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
    def verify(self, signature: Buffer, data: Buffer) -> None:
        """
        Verify the signature.
        """

    @abc.abstractmethod
    def __eq__(self, other: object) -> bool:
        """
        Checks equality.
        """

    @abc.abstractmethod
    def __copy__(self) -> MlDsa87PublicKey:
        """
        Returns a copy.
        """

    @abc.abstractmethod
    def __deepcopy__(self, memo: dict) -> MlDsa87PublicKey:
        """
        Returns a deep copy.
        """


if hasattr(rust_openssl, "mldsa87"):
    MlDsa87PublicKey.register(rust_openssl.mldsa87.MlDsa87PublicKey)


class MlDsa87PrivateKey(metaclass=abc.ABCMeta):
    @classmethod
    def generate(cls) -> MlDsa87PrivateKey:
        from cryptography.hazmat.backends.openssl.backend import backend

        if not backend.mldsa87_supported():
            raise UnsupportedAlgorithm(
                "ML-DSA-87 is not supported by this version of OpenSSL.",
                _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM,
            )

        mldsa87 = getattr(rust_openssl, "mldsa87")
        return mldsa87.generate_key()

    @classmethod
    def from_private_bytes(cls, data: Buffer) -> MlDsa87PrivateKey:
        from cryptography.hazmat.backends.openssl.backend import backend

        if not backend.mldsa87_supported():
            raise UnsupportedAlgorithm(
                "ML-DSA-87 is not supported by this version of OpenSSL.",
                _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM,
            )

        mldsa87 = getattr(rust_openssl, "mldsa87")
        return mldsa87.from_private_bytes(data)

    @abc.abstractmethod
    def public_key(self) -> MlDsa87PublicKey:
        """
        The MlDsa87PublicKey derived from the private key.
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
    def sign(self, data: Buffer) -> bytes:
        """
        Signs the data.
        """

    @abc.abstractmethod
    def __copy__(self) -> MlDsa87PrivateKey:
        """
        Returns a copy.
        """

    @abc.abstractmethod
    def __deepcopy__(self, memo: dict) -> MlDsa87PrivateKey:
        """
        Returns a deep copy.
        """


if hasattr(rust_openssl, "mldsa87"):
    MlDsa87PrivateKey.register(rust_openssl.mldsa87.MlDsa87PrivateKey)
