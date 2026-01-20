.. hazmat::

ML-KEM-1024 key encapsulation
==============================

.. currentmodule:: cryptography.hazmat.primitives.asymmetric.mlkem1024


ML-KEM-1024 is a post-quantum key encapsulation mechanism (KEM) based on
module lattices, standardized in `FIPS 203`_. It provides NIST security level 5
(equivalent to AES-256) and offers the highest security level of the ML-KEM
family. ML-KEM-1024 allows one party to securely encapsulate a shared secret
that can only be decapsulated by the holder of the corresponding private key.

ML-KEM-1024 is suitable for applications requiring the highest post-quantum
security guarantees, such as long-term data protection and critical
infrastructure. For most applications, :doc:`mlkem768` provides a good balance
of security and performance.


Key Encapsulation Mechanism
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Unlike traditional key exchange algorithms (such as X25519), where both parties
contribute to the shared secret, ML-KEM is asymmetric: the encapsulating party
generates both the ciphertext and the shared secret, which the decapsulating
party can recover using their private key.

For most applications the ``shared_secret`` should be passed to a key
derivation function to derive encryption keys. This allows mixing of additional
information into the key and derivation of multiple keys.

.. doctest::

    >>> from cryptography.hazmat.primitives import hashes
    >>> from cryptography.hazmat.primitives.asymmetric.mlkem1024 import MlKem1024PrivateKey
    >>> from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    >>> from cryptography.hazmat.primitives import serialization
    >>> # Server generates a key pair
    >>> server_private_key = MlKem1024PrivateKey.generate()
    >>> server_public_key = server_private_key.public_key()
    >>> # Server sends public key to client (serialized)
    >>> public_key_bytes = server_public_key.public_bytes(
    ...     encoding=serialization.Encoding.DER,
    ...     format=serialization.PublicFormat.SubjectPublicKeyInfo
    ... )
    >>> # Client loads the public key
    >>> loaded_public_key = serialization.load_der_public_key(public_key_bytes)
    >>> # Client encapsulates to generate shared secret and ciphertext
    >>> ciphertext, client_shared_secret = loaded_public_key.encapsulate()
    >>> # Client sends ciphertext to server
    >>> # Server decapsulates to recover the shared secret
    >>> server_shared_secret = server_private_key.decapsulate(ciphertext)
    >>> # Both parties now have the same shared secret
    >>> assert client_shared_secret == server_shared_secret
    >>> # Derive an encryption key from the shared secret
    >>> derived_key = HKDF(
    ...     algorithm=hashes.SHA256(),
    ...     length=32,
    ...     salt=None,
    ...     info=b'application context',
    ... ).derive(client_shared_secret)

Key interfaces
~~~~~~~~~~~~~~

.. class:: MlKem1024PrivateKey

    .. versionadded:: 47.0

    .. classmethod:: generate()

        Generate an ML-KEM-1024 private (decapsulation) key.

        :returns: :class:`MlKem1024PrivateKey`

        :raises cryptography.exceptions.UnsupportedAlgorithm: If ML-KEM-1024 is
            not supported by the OpenSSL version ``cryptography`` is using.

    .. classmethod:: from_private_bytes(data)

        A class method for loading an ML-KEM-1024 key encoded as
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.Raw`.

        :param bytes data: 3168 byte private key.

        :returns: :class:`MlKem1024PrivateKey`

        :raises ValueError: If the private key is not 3168 bytes.

        :raises cryptography.exceptions.UnsupportedAlgorithm: If ML-KEM-1024 is
            not supported by the OpenSSL version ``cryptography`` is using.

        .. doctest::

            >>> from cryptography.hazmat.primitives import serialization
            >>> from cryptography.hazmat.primitives.asymmetric import mlkem1024
            >>> private_key = mlkem1024.MlKem1024PrivateKey.generate()
            >>> private_bytes = private_key.private_bytes(
            ...     encoding=serialization.Encoding.Raw,
            ...     format=serialization.PrivateFormat.Raw,
            ...     encryption_algorithm=serialization.NoEncryption()
            ... )
            >>> loaded_private_key = mlkem1024.MlKem1024PrivateKey.from_private_bytes(private_bytes)

    .. method:: public_key()

        :returns: :class:`MlKem1024PublicKey`

    .. method:: decapsulate(ciphertext)

        Decapsulates the ciphertext to recover the shared secret.

        :param ciphertext: The 1568-byte ciphertext from encapsulation.
        :type ciphertext: :term:`bytes-like`

        :returns bytes: A 32-byte shared secret.

        :raises ValueError: If the ciphertext is not 1568 bytes.

    .. method:: private_bytes(encoding, format, encryption_algorithm)

        Allows serialization of the key to bytes. Encoding (
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.PEM`,
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.DER`, or
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.Raw`) and
        format (
        :attr:`~cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8`
        or
        :attr:`~cryptography.hazmat.primitives.serialization.PrivateFormat.Raw`
        ) are chosen to define the exact serialization.

        :param encoding: A value from the
            :class:`~cryptography.hazmat.primitives.serialization.Encoding` enum.

        :param format: A value from the
            :class:`~cryptography.hazmat.primitives.serialization.PrivateFormat`
            enum. If the ``encoding`` is
            :attr:`~cryptography.hazmat.primitives.serialization.Encoding.Raw`
            then ``format`` must be
            :attr:`~cryptography.hazmat.primitives.serialization.PrivateFormat.Raw`
            , otherwise it must be
            :attr:`~cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8`.

        :param encryption_algorithm: An instance of an object conforming to the
            :class:`~cryptography.hazmat.primitives.serialization.KeySerializationEncryption`
            interface.

        :return bytes: Serialized key.

    .. method:: private_bytes_raw()

        Allows serialization of the key to raw bytes. This method is a
        convenience shortcut for calling :meth:`private_bytes` with
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.Raw`
        encoding,
        :attr:`~cryptography.hazmat.primitives.serialization.PrivateFormat.Raw`
        format, and
        :class:`~cryptography.hazmat.primitives.serialization.NoEncryption`.

        :return bytes: 3168-byte raw private key.

.. class:: MlKem1024PublicKey

    .. versionadded:: 47.0

    .. classmethod:: from_public_bytes(data)

        :param bytes data: 1568 byte public (encapsulation) key.

        :returns: :class:`MlKem1024PublicKey`

        :raises ValueError: If the public key is not 1568 bytes.

        :raises cryptography.exceptions.UnsupportedAlgorithm: If ML-KEM-1024 is
            not supported by the OpenSSL version ``cryptography`` is using.

        .. doctest::

            >>> from cryptography.hazmat.primitives import serialization
            >>> from cryptography.hazmat.primitives.asymmetric import mlkem1024
            >>> private_key = mlkem1024.MlKem1024PrivateKey.generate()
            >>> public_key = private_key.public_key()
            >>> public_bytes = public_key.public_bytes(
            ...     encoding=serialization.Encoding.Raw,
            ...     format=serialization.PublicFormat.Raw
            ... )
            >>> loaded_public_key = mlkem1024.MlKem1024PublicKey.from_public_bytes(public_bytes)

    .. method:: encapsulate()

        Generates a shared secret and encapsulates it into a ciphertext.

        :returns tuple[bytes, bytes]: A tuple of (ciphertext, shared_secret).
            The ciphertext is 1568 bytes and the shared_secret is 32 bytes.

    .. method:: public_bytes(encoding, format)

        Allows serialization of the key to bytes. Encoding (
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.PEM`,
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.DER`, or
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.Raw`) and
        format (
        :attr:`~cryptography.hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo`
        or
        :attr:`~cryptography.hazmat.primitives.serialization.PublicFormat.Raw`
        ) are chosen to define the exact serialization.

        :param encoding: A value from the
            :class:`~cryptography.hazmat.primitives.serialization.Encoding` enum.

        :param format: A value from the
            :class:`~cryptography.hazmat.primitives.serialization.PublicFormat`
            enum. If the ``encoding`` is
            :attr:`~cryptography.hazmat.primitives.serialization.Encoding.Raw`
            then ``format`` must be
            :attr:`~cryptography.hazmat.primitives.serialization.PublicFormat.Raw`
            , otherwise it must be
            :attr:`~cryptography.hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo`.

        :returns bytes: The public key bytes.

    .. method:: public_bytes_raw()

        Allows serialization of the key to raw bytes. This method is a
        convenience shortcut for calling :meth:`public_bytes` with
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.Raw`
        encoding and
        :attr:`~cryptography.hazmat.primitives.serialization.PublicFormat.Raw`
        format.

        :return bytes: 1568-byte raw public key.


.. _`FIPS 203`: https://csrc.nist.gov/pubs/fips/203/final
