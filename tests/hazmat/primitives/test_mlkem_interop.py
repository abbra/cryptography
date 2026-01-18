# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

"""
Tests for ML-KEM interoperability with OpenSSL.
These tests validate that python-cryptography's ML-KEM implementation
can exchange keys with OpenSSL-generated keys.
"""

import subprocess
import tempfile

import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import (
    mlkem512,
    mlkem768,
    mlkem1024,
)


def _openssl_supports_mlkem():
    """Check if OpenSSL supports ML-KEM"""
    try:
        result = subprocess.run(
            ["openssl", "list", "-kem-algorithms"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return "ML-KEM" in result.stdout
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


# Skip all tests in this module if OpenSSL doesn't support ML-KEM
pytestmark = pytest.mark.skipif(
    not _openssl_supports_mlkem(),
    reason="OpenSSL does not support ML-KEM",
)


class TestMLKEMOpenSSLInterop:
    """Test ML-KEM interoperability with OpenSSL command-line tools"""

    @pytest.mark.parametrize(
        "algorithm,key_class,pub_size",
        [
            ("ML-KEM-512", mlkem512.MlKem512PublicKey, 800),
            ("ML-KEM-768", mlkem768.MlKem768PublicKey, 1184),
            ("ML-KEM-1024", mlkem1024.MlKem1024PublicKey, 1568),
        ],
    )
    def test_load_openssl_public_key(self, algorithm, key_class, pub_size):
        """Test loading OpenSSL-generated public keys"""
        # Generate key with OpenSSL
        with tempfile.NamedTemporaryFile(suffix=".pem") as priv_file:
            subprocess.run(
                [
                    "openssl",
                    "genpkey",
                    "-algorithm",
                    algorithm,
                    "-out",
                    priv_file.name,
                ],
                check=True,
                capture_output=True,
            )

            # Extract public key
            with tempfile.NamedTemporaryFile(suffix=".pem") as pub_file:
                subprocess.run(
                    [
                        "openssl",
                        "pkey",
                        "-in",
                        priv_file.name,
                        "-pubout",
                        "-out",
                        pub_file.name,
                    ],
                    check=True,
                    capture_output=True,
                )

                # Load in python-cryptography
                with open(pub_file.name, "rb") as f:
                    pub_pem = f.read()

                loaded_pub = serialization.load_pem_public_key(pub_pem)
                assert isinstance(loaded_pub, key_class)

                # Verify size
                raw_pub = loaded_pub.public_bytes_raw()
                assert len(raw_pub) == pub_size

                # Test encapsulation works
                _ct, ss = loaded_pub.encapsulate()
                assert len(ss) == 32  # Shared secret is always 32 bytes

    @pytest.mark.parametrize(
        "algorithm,priv_class,public_class",
        [
            (
                "ML-KEM-512",
                mlkem512.MlKem512PrivateKey,
                mlkem512.MlKem512PublicKey,
            ),
            (
                "ML-KEM-768",
                mlkem768.MlKem768PrivateKey,
                mlkem768.MlKem768PublicKey,
            ),
            (
                "ML-KEM-1024",
                mlkem1024.MlKem1024PrivateKey,
                mlkem1024.MlKem1024PublicKey,
            ),
        ],
    )
    def test_openssl_parses_python_keys(
        self, algorithm, priv_class, public_class
    ):
        """Test that OpenSSL can parse python-generated keys"""
        # Generate with python
        private_key = priv_class.generate()

        # Save as PEM
        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        with tempfile.NamedTemporaryFile(
            suffix=".pem", delete=False
        ) as priv_file:
            priv_file.write(priv_pem)
            priv_file.flush()

            # Try to parse with OpenSSL
            result = subprocess.run(
                ["openssl", "pkey", "-in", priv_file.name, "-text", "-noout"],
                capture_output=True,
            )

            # Should succeed
            assert result.returncode == 0, (
                f"OpenSSL failed to parse key: {result.stderr.decode()}"
            )

            # Try to extract public key with OpenSSL
            with tempfile.NamedTemporaryFile(suffix=".pem") as pub_file:
                result = subprocess.run(
                    [
                        "openssl",
                        "pkey",
                        "-in",
                        priv_file.name,
                        "-pubout",
                        "-out",
                        pub_file.name,
                    ],
                    capture_output=True,
                )

                assert result.returncode == 0, (
                    "OpenSSL failed to extract public key"
                )

                # Load back in python
                with open(pub_file.name, "rb") as f:
                    pub_pem = f.read()

                loaded_pub = serialization.load_pem_public_key(pub_pem)
                assert isinstance(loaded_pub, public_class)
                # Should get back the same public key
                assert (
                    loaded_pub.public_bytes_raw()
                    == private_key.public_key().public_bytes_raw()
                )

    def test_cross_implementation_encap_decap(self):
        """
        Test encapsulation/decapsulation between implementations.
        Python generates and encapsulates, OpenSSL decapsulates.
        """
        # Generate with python
        py_private = mlkem768.MlKem768PrivateKey.generate()
        py_public = py_private.public_key()

        # Encapsulate with python
        ciphertext, py_shared_secret = py_public.encapsulate()

        # Save private key for OpenSSL
        with tempfile.NamedTemporaryFile(suffix=".pem") as priv_file:
            priv_pem = py_private.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            priv_file.write(priv_pem)
            priv_file.flush()

            # Save ciphertext
            with tempfile.NamedTemporaryFile(suffix=".bin") as ct_file:
                ct_file.write(ciphertext)
                ct_file.flush()

                # Decapsulate with OpenSSL
                with tempfile.NamedTemporaryFile(suffix=".bin") as ss_file:
                    res = subprocess.run(
                        [
                            "openssl",
                            "pkeyutl",
                            "-decap",
                            "-inkey",
                            priv_file.name,
                            "-in",
                            ct_file.name,
                            "-out",
                            ss_file.name,
                        ],
                        capture_output=True,
                    )

                    assert res.returncode == 0, (
                        f"OpenSSL decapsulation failed: {res.stderr.decode()}"
                    )

                    # Read OpenSSL's shared secret
                    with open(ss_file.name, "rb") as f:
                        openssl_shared_secret = f.read()

                    # Compare
                    assert py_shared_secret == openssl_shared_secret, (
                        "Shared secrets do not match!"
                    )

    def test_pkcs8_format_compliance(self):
        """
        Verify that ML-KEM private keys use correct PKCS#8 format
        with parameter-less AlgorithmIdentifier (no NULL parameters).
        """
        private_key = mlkem768.MlKem768PrivateKey.generate()

        # Get DER encoding
        priv_der = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # Check that AlgorithmIdentifier is 11 bytes (parameter-less)
        # Format: SEQUENCE (30) + length (0b) + OID header (06 09) + OID (9b)
        # The first bytes should be: 30 82 09 78 02 01 00 30 0b 06 09 ...
        #               11-byte AlgorithmIdentifier ----> ^^^^^
        # NOT: 30 82 09 7a 02 01 00 30 0d 06 09 ... 05 00 (with NULL)
        assert priv_der[7:9] == b"\x30\x0b", (
            "AlgorithmIdentifier should be 11 bytes (parameter-less)"
        )

        # Verify OpenSSL agrees
        with tempfile.NamedTemporaryFile(suffix=".der") as der_file:
            der_file.write(priv_der)
            der_file.flush()

            result = subprocess.run(
                [
                    "openssl",
                    "pkey",
                    "-inform",
                    "DER",
                    "-in",
                    der_file.name,
                    "-text",
                    "-noout",
                ],
                capture_output=True,
            )

            assert result.returncode == 0, (
                "OpenSSL should accept parameter-less format"
            )
