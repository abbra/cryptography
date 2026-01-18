.. hazmat::

Hybrid Key Encapsulation Mechanisms
====================================

.. currentmodule:: cryptography.hazmat.primitives.asymmetric.hybrid_kem

Hybrid Key Encapsulation Mechanisms (KEMs) combine classical key exchange
algorithms (like X25519 or X448) with post-quantum algorithms (like ML-KEM)
to provide defense-in-depth security. The hybrid approach ensures that the
shared secret remains secure even if one of the underlying algorithms is
compromised.

This is particularly important during the transition to post-quantum
cryptography, as it provides:

1. **Security against quantum computers** via ML-KEM
2. **Security against classical attacks** via proven elliptic curve algorithms
3. **Transitional confidence** during the PQC migration period

Available Hybrid KEMs
~~~~~~~~~~~~~~~~~~~~~

X25519 + ML-KEM-768 (X-Wing)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Combines X25519 with ML-KEM-768, providing NIST security level 3
(comparable to 192-bit security). This combination is also known as X-Wing
and is defined in draft-connolly-cfrg-xwing-kem.

**Recommended for general-purpose use.**

X448 + ML-KEM-1024
^^^^^^^^^^^^^^^^^^

Combines X448 with ML-KEM-1024, providing NIST security level 5
(comparable to 256-bit security). Use this for high-security applications
requiring maximum protection.

NIST P-256 + ML-KEM-768
^^^^^^^^^^^^^^^^^^^^^^^^

Combines NIST P-256 (secp256r1) with ML-KEM-768, providing NIST security
level 3. This variant uses NIST-standardized elliptic curves and may be
preferred in environments requiring NIST compliance.

NIST P-384 + ML-KEM-1024
^^^^^^^^^^^^^^^^^^^^^^^^^

Combines NIST P-384 (secp384r1) with ML-KEM-1024, providing NIST security
level 5. This is the highest-security variant using NIST-standardized curves.

Basic Usage
~~~~~~~~~~~

.. doctest::

    >>> from cryptography.hazmat.primitives.asymmetric import hybrid_kem
    >>> from cryptography.hazmat.primitives import serialization
    >>> # Server generates a key pair
    >>> server_private_key = hybrid_kem.X25519MLKEM768PrivateKey.generate()
    >>> server_public_key = server_private_key.public_key()
    >>> # Server sends public key to client (serialized)
    >>> public_bytes = server_public_key.public_bytes(
    ...     encoding=serialization.Encoding.Raw,
    ...     format=serialization.PublicFormat.Raw
    ... )
    >>> # Client loads the public key
    >>> client_public_key = hybrid_kem.X25519MLKEM768PublicKey.from_public_bytes(
    ...     public_bytes
    ... )
    >>> # Client encapsulates to generate shared secret and ciphertext
    >>> ciphertext, client_shared_secret = client_public_key.encapsulate()
    >>> # Client sends ciphertext to server
    >>> # Server decapsulates to recover the shared secret
    >>> server_shared_secret = server_private_key.decapsulate(ciphertext)
    >>> # Both parties now have the same shared secret
    >>> assert client_shared_secret == server_shared_secret

Key Derivation for Encryption
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The shared secret should be passed to a key derivation function (KDF) to
derive encryption keys:

.. doctest::

    >>> from cryptography.hazmat.primitives import hashes
    >>> from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    >>> from cryptography.hazmat.primitives.asymmetric import hybrid_kem
    >>> # Generate keys and encapsulate
    >>> private_key = hybrid_kem.X25519MLKEM768PrivateKey.generate()
    >>> public_key = private_key.public_key()
    >>> ciphertext, shared_secret = public_key.encapsulate()
    >>> # Derive encryption key from shared secret
    >>> encryption_key = HKDF(
    ...     algorithm=hashes.SHA256(),
    ...     length=32,
    ...     salt=None,
    ...     info=b'application-specific context',
    ... ).derive(shared_secret)

High-Security Variant
~~~~~~~~~~~~~~~~~~~~~

For applications requiring maximum security (NIST Level 5):

.. doctest::

    >>> from cryptography.hazmat.primitives.asymmetric import hybrid_kem
    >>> from cryptography.hazmat.primitives import serialization
    >>> # Use X448 + ML-KEM-1024
    >>> private_key = hybrid_kem.X448MLKEM1024PrivateKey.generate()
    >>> public_key = private_key.public_key()
    >>> # Encapsulate
    >>> ciphertext, shared_secret = public_key.encapsulate()
    >>> # Decapsulate
    >>> recovered_secret = private_key.decapsulate(ciphertext)
    >>> assert shared_secret == recovered_secret

Technical Details
~~~~~~~~~~~~~~~~~

Ciphertext Sizes
^^^^^^^^^^^^^^^^

+---------------------+------------------+------------------+
| Hybrid KEM          | Ciphertext Size  | Shared Secret    |
+=====================+==================+==================+
| X25519MLKEM768      | 1120 bytes       | 32 bytes         |
+---------------------+------------------+------------------+
| X448MLKEM1024       | 1624 bytes       | 32 bytes         |
+---------------------+------------------+------------------+
| SecP256r1MLKEM768   | 1153 bytes       | 32 bytes         |
+---------------------+------------------+------------------+
| SecP384r1MLKEM1024  | 1665 bytes       | 32 bytes         |
+---------------------+------------------+------------------+

Key Sizes
^^^^^^^^^

+---------------------+------------------+------------------+
| Hybrid KEM          | Public Key       | Private Key      |
+=====================+==================+==================+
| X25519MLKEM768      | 1216 bytes       | 2432 bytes       |
+---------------------+------------------+------------------+
| X448MLKEM1024       | 1624 bytes       | 3224 bytes       |
+---------------------+------------------+------------------+
| SecP256r1MLKEM768   | 1249 bytes       | 2432 bytes       |
+---------------------+------------------+------------------+
| SecP384r1MLKEM1024  | 1665 bytes       | 3216 bytes       |
+---------------------+------------------+------------------+

Shared Secret Derivation
^^^^^^^^^^^^^^^^^^^^^^^^^

The hybrid shared secret is derived as follows:

1. Perform classical key exchange (X25519 or X448) to get ``classical_secret``
2. Perform ML-KEM encapsulation to get ``pq_secret``
3. Concatenate: ``combined = classical_secret || pq_secret``
4. Derive final secret: ``HKDF-SHA256(combined, info="X25519MLKEM768")``

This ensures that the final shared secret benefits from both algorithms.

API Reference
~~~~~~~~~~~~~

X25519MLKEM768PrivateKey
^^^^^^^^^^^^^^^^^^^^^^^^

.. class:: X25519MLKEM768PrivateKey

    .. versionadded:: 47.0

    .. classmethod:: generate()

        Generate a new hybrid private key.

        :returns: :class:`X25519MLKEM768PrivateKey`

        :raises cryptography.exceptions.UnsupportedAlgorithm: If ML-KEM-768 is
            not supported by the OpenSSL version ``cryptography`` is using.

    .. classmethod:: from_private_bytes(data)

        Load a private key from raw bytes.

        :param bytes data: 2432 bytes (32 X25519 + 2400 ML-KEM-768)

        :returns: :class:`X25519MLKEM768PrivateKey`

        :raises ValueError: If the key is not 2432 bytes.

        .. doctest::

            >>> from cryptography.hazmat.primitives import serialization
            >>> from cryptography.hazmat.primitives.asymmetric import hybrid_kem
            >>> private_key = hybrid_kem.X25519MLKEM768PrivateKey.generate()
            >>> private_bytes = private_key.private_bytes(
            ...     encoding=serialization.Encoding.Raw,
            ...     format=serialization.PrivateFormat.Raw,
            ...     encryption_algorithm=serialization.NoEncryption()
            ... )
            >>> loaded_private_key = hybrid_kem.X25519MLKEM768PrivateKey.from_private_bytes(
            ...     private_bytes
            ... )

    .. method:: public_key()

        :returns: :class:`X25519MLKEM768PublicKey`

    .. method:: decapsulate(ciphertext)

        Decapsulate the ciphertext to recover the shared secret.

        :param bytes ciphertext: The 1120-byte ciphertext from encapsulation.

        :returns bytes: A 32-byte shared secret.

        :raises ValueError: If the ciphertext is not 1120 bytes.

    .. method:: private_bytes(encoding, format, encryption_algorithm)

        Serialize the private key to bytes.

        Currently only :attr:`~cryptography.hazmat.primitives.serialization.Encoding.Raw`
        encoding with :attr:`~cryptography.hazmat.primitives.serialization.PrivateFormat.Raw`
        format is supported.

        :param encoding: Must be
            :attr:`~cryptography.hazmat.primitives.serialization.Encoding.Raw`

        :param format: Must be
            :attr:`~cryptography.hazmat.primitives.serialization.PrivateFormat.Raw`

        :param encryption_algorithm: Must be
            :class:`~cryptography.hazmat.primitives.serialization.NoEncryption`

        :return bytes: 2432-byte raw private key.

X25519MLKEM768PublicKey
^^^^^^^^^^^^^^^^^^^^^^^

.. class:: X25519MLKEM768PublicKey

    .. versionadded:: 47.0

    .. classmethod:: from_public_bytes(data)

        Load a public key from raw bytes.

        :param bytes data: 1216 bytes (32 X25519 + 1184 ML-KEM-768)

        :returns: :class:`X25519MLKEM768PublicKey`

        :raises ValueError: If the key is not 1216 bytes.

        .. doctest::

            >>> from cryptography.hazmat.primitives import serialization
            >>> from cryptography.hazmat.primitives.asymmetric import hybrid_kem
            >>> private_key = hybrid_kem.X25519MLKEM768PrivateKey.generate()
            >>> public_key = private_key.public_key()
            >>> public_bytes = public_key.public_bytes(
            ...     encoding=serialization.Encoding.Raw,
            ...     format=serialization.PublicFormat.Raw
            ... )
            >>> loaded_public_key = hybrid_kem.X25519MLKEM768PublicKey.from_public_bytes(
            ...     public_bytes
            ... )

    .. method:: encapsulate()

        Generate a shared secret and encapsulate it.

        :returns tuple[bytes, bytes]: A tuple of (ciphertext, shared_secret).
            The ciphertext is 1120 bytes and the shared_secret is 32 bytes.

    .. method:: public_bytes(encoding, format)

        Serialize the public key to bytes.

        Currently only :attr:`~cryptography.hazmat.primitives.serialization.Encoding.Raw`
        encoding with :attr:`~cryptography.hazmat.primitives.serialization.PublicFormat.Raw`
        format is supported.

        :param encoding: Must be
            :attr:`~cryptography.hazmat.primitives.serialization.Encoding.Raw`

        :param format: Must be
            :attr:`~cryptography.hazmat.primitives.serialization.PublicFormat.Raw`

        :return bytes: 1216-byte raw public key.

X448MLKEM1024PrivateKey
^^^^^^^^^^^^^^^^^^^^^^^

.. class:: X448MLKEM1024PrivateKey

    .. versionadded:: 47.0

    Higher security variant using X448 and ML-KEM-1024.

    .. classmethod:: generate()

        Generate a new hybrid private key.

        :returns: :class:`X448MLKEM1024PrivateKey`

    .. classmethod:: from_private_bytes(data)

        Load from 3224 bytes (56 X448 + 3168 ML-KEM-1024).

        :param bytes data: 3224-byte private key.

        :returns: :class:`X448MLKEM1024PrivateKey`

    .. method:: public_key()

        :returns: :class:`X448MLKEM1024PublicKey`

    .. method:: decapsulate(ciphertext)

        Decapsulate from 1624-byte ciphertext.

        :param bytes ciphertext: The ciphertext from encapsulation.

        :returns bytes: A 32-byte shared secret.

    .. method:: private_bytes(encoding, format, encryption_algorithm)

        Serialize to 3224 bytes (Raw format only).

        :return bytes: 3224-byte raw private key.

X448MLKEM1024PublicKey
^^^^^^^^^^^^^^^^^^^^^^

.. class:: X448MLKEM1024PublicKey

    .. versionadded:: 47.0

    .. classmethod:: from_public_bytes(data)

        Load from 1624 bytes (56 X448 + 1568 ML-KEM-1024).

        :param bytes data: 1624-byte public key.

        :returns: :class:`X448MLKEM1024PublicKey`

    .. method:: encapsulate()

        Generate shared secret and 1624-byte ciphertext.

        :returns tuple[bytes, bytes]: (ciphertext, shared_secret)

    .. method:: public_bytes(encoding, format)

        Serialize to 1624 bytes (Raw format only).

        :return bytes: 1624-byte raw public key.

SecP256r1MLKEM768PrivateKey
^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. class:: SecP256r1MLKEM768PrivateKey

    .. versionadded:: 47.0

    NIST P-256 + ML-KEM-768 hybrid private key.

    .. classmethod:: generate()

        Generate a new hybrid private key.

        :returns: :class:`SecP256r1MLKEM768PrivateKey`

    .. classmethod:: from_private_bytes(data)

        Load from 2432 bytes (32 P-256 + 2400 ML-KEM-768).

        :param bytes data: 2432-byte private key.

        :returns: :class:`SecP256r1MLKEM768PrivateKey`

    .. method:: public_key()

        :returns: :class:`SecP256r1MLKEM768PublicKey`

    .. method:: decapsulate(ciphertext)

        Decapsulate from 1153-byte ciphertext.

        :param bytes ciphertext: The ciphertext from encapsulation.

        :returns bytes: A 32-byte shared secret.

    .. method:: private_bytes(encoding, format, encryption_algorithm)

        Serialize to 2432 bytes (Raw format only).

        :return bytes: 2432-byte raw private key.

SecP256r1MLKEM768PublicKey
^^^^^^^^^^^^^^^^^^^^^^^^^^

.. class:: SecP256r1MLKEM768PublicKey

    .. versionadded:: 47.0

    NIST P-256 + ML-KEM-768 hybrid public key.

    .. classmethod:: from_public_bytes(data)

        Load from 1249 bytes (65 P-256 + 1184 ML-KEM-768).

        :param bytes data: 1249-byte public key.

        :returns: :class:`SecP256r1MLKEM768PublicKey`

    .. method:: encapsulate()

        Generate shared secret and 1153-byte ciphertext.

        :returns tuple[bytes, bytes]: (ciphertext, shared_secret)

    .. method:: public_bytes(encoding, format)

        Serialize to 1249 bytes (Raw format only).

        :return bytes: 1249-byte raw public key.

SecP384r1MLKEM1024PrivateKey
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. class:: SecP384r1MLKEM1024PrivateKey

    .. versionadded:: 47.0

    NIST P-384 + ML-KEM-1024 hybrid private key.

    .. classmethod:: generate()

        Generate a new hybrid private key.

        :returns: :class:`SecP384r1MLKEM1024PrivateKey`

    .. classmethod:: from_private_bytes(data)

        Load from 3216 bytes (48 P-384 + 3168 ML-KEM-1024).

        :param bytes data: 3216-byte private key.

        :returns: :class:`SecP384r1MLKEM1024PrivateKey`

    .. method:: public_key()

        :returns: :class:`SecP384r1MLKEM1024PublicKey`

    .. method:: decapsulate(ciphertext)

        Decapsulate from 1665-byte ciphertext.

        :param bytes ciphertext: The ciphertext from encapsulation.

        :returns bytes: A 32-byte shared secret.

    .. method:: private_bytes(encoding, format, encryption_algorithm)

        Serialize to 3216 bytes (Raw format only).

        :return bytes: 3216-byte raw private key.

SecP384r1MLKEM1024PublicKey
^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. class:: SecP384r1MLKEM1024PublicKey

    .. versionadded:: 47.0

    NIST P-384 + ML-KEM-1024 hybrid public key.

    .. classmethod:: from_public_bytes(data)

        Load from 1665 bytes (97 P-384 + 1568 ML-KEM-1024).

        :param bytes data: 1665-byte public key.

        :returns: :class:`SecP384r1MLKEM1024PublicKey`

    .. method:: encapsulate()

        Generate shared secret and 1665-byte ciphertext.

        :returns tuple[bytes, bytes]: (ciphertext, shared_secret)

    .. method:: public_bytes(encoding, format)

        Serialize to 1665 bytes (Raw format only).

        :return bytes: 1665-byte raw public key.

Security Considerations
~~~~~~~~~~~~~~~~~~~~~~~

**Defense in Depth**: The hybrid approach ensures that breaking one algorithm
does not compromise the overall security. An attacker would need to break
*both* the classical and post-quantum components.

**Quantum Resistance**: The ML-KEM component provides security against quantum
computer attacks, while the classical component (X25519/X448/P-256/P-384)
provides security against classical attacks.

**No Weakest Link**: The shared secret derivation uses HKDF to combine both
secrets, ensuring that the final key is at least as strong as the stronger
component.

**Standardization**: X25519MLKEM768 (X-Wing) is being standardized in
draft-connolly-cfrg-xwing-kem. The other variants (X448MLKEM1024,
SecP256r1MLKEM768, SecP384r1MLKEM1024) follow the same construction pattern
with their respective elliptic curves.

**NIST Compliance**: The SecP256r1MLKEM768 and SecP384r1MLKEM1024 variants use
NIST-standardized elliptic curves (P-256 and P-384) which may be required in
certain compliance environments.

References
~~~~~~~~~~

- `FIPS 203 <https://csrc.nist.gov/pubs/fips/203/final>`_ - ML-KEM Standard
- `draft-connolly-cfrg-xwing <https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/>`_ - X-Wing KEM
- `RFC 7748 <https://www.rfc-editor.org/rfc/rfc7748.html>`_ - X25519 and X448
- `draft-ietf-tls-mlkem-05 <https://datatracker.ietf.org/doc/html/draft-ietf-tls-mlkem-05>`_ - ML-KEM in TLS
