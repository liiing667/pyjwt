from __future__ import annotations

import json
import time
from collections.abc import Iterator
from typing import Any

from .algorithms import get_default_algorithms, has_crypto, requires_cryptography
from .exceptions import (
    InvalidKeyError,
    MissingCryptographyError,
    PyJWKError,
    PyJWKSetError,
    PyJWTError,
)
from .types import JWKDict


class PyJWK:
    def __init__(self, jwk_data: JWKDict, algorithm: str | None = None) -> None:
        """A class that represents a `JSON Web Key <https://www.rfc-editor.org/rfc/rfc7517>`_.

        :param jwk_data: The decoded JWK data.
        :type jwk_data: dict[str, typing.Any]
        :param algorithm: The key algorithm. If not specified, the key's ``alg`` will be used.
        :type algorithm: str or None
        :raises InvalidKeyError: If the key type (``kty``) is not found or unsupported, or if the curve (``crv``) is not found or unsupported.
        :raises MissingCryptographyError: If the algorithm requires ``cryptography`` to be installed and it is not available.
        :raises PyJWKError: If unable to find an algorithm for the key.
        """
        self._jwk_data = jwk_data

        kty = self._jwk_data.get("kty", None)
        if not kty:
            raise InvalidKeyError(f"kty is not found: {self._jwk_data}")

        if not algorithm and isinstance(self._jwk_data, dict):
            algorithm = self._jwk_data.get("alg", None)

        if not algorithm:
            # Determine alg with kty (and crv).
            crv = self._jwk_data.get("crv", None)
            if kty == "EC":
                if crv == "P-256" or not crv:
                    algorithm = "ES256"
                elif crv == "P-384":
                    algorithm = "ES384"
                elif crv == "P-521":
                    algorithm = "ES512"
                elif crv == "secp256k1":
                    algorithm = "ES256K"
                else:
                    raise InvalidKeyError(f"Unsupported crv: {crv}")
            elif kty == "RSA":
                algorithm = "RS256"
            elif kty == "oct":
                algorithm = "HS256"
            elif kty == "OKP":
                if not crv:
                    raise InvalidKeyError(f"crv is not found: {self._jwk_data}")
                if crv == "Ed25519":
                    algorithm = "EdDSA"
                else:
                    raise InvalidKeyError(f"Unsupported crv: {crv}")
            else:
                raise InvalidKeyError(f"Unsupported kty: {kty}")

        if not has_crypto and algorithm in requires_cryptography:
            raise MissingCryptographyError(
                f"{algorithm} requires 'cryptography' to be installed."
            )

        self.algorithm_name = algorithm

        try:
            self.Algorithm = get_default_algorithms()[algorithm]
        except KeyError:
            raise PyJWKError(
                f"Unable to find an algorithm for key: {self._jwk_data}",
            ) from None

        try:
            self.key = self.Algorithm.from_jwk(self._jwk_data)
        except (TypeError, ValueError) as error:
            raise InvalidKeyError(
                f"Unable to construct key from JWK: {error}"
            ) from error

    @staticmethod
    def from_dict(obj: JWKDict, algorithm: str | None = None) -> PyJWK:
        """Creates a :class:`PyJWK` object from a JSON-like dictionary.

        :param obj: The JWK data, as a dictionary
        :type obj: dict[str, typing.Any]
        :param algorithm: The key algorithm. If not specified, the key's ``alg`` will be used.
        :type algorithm: str or None
        :rtype: PyJWK
        """
        return PyJWK(obj, algorithm)

    @staticmethod
    def from_json(data: str, algorithm: str | None = None) -> PyJWK:
        """Create a :class:`PyJWK` object from a JSON string.
        Implicitly calls :meth:`PyJWK.from_dict()`.

        :param str data: The JWK data, as a JSON string.
        :param algorithm:  The key algorithm.  If not specific, the key's ``alg`` will be used.
        :type algorithm: str or None

        :rtype: PyJWK
        """
        obj = json.loads(data)
        return PyJWK.from_dict(obj, algorithm)

    @property
    def key_type(self) -> str | None:
        """The `kty` property from the JWK.

        :rtype: str or None
        """
        return self._jwk_data.get("kty", None)

    @property
    def key_id(self) -> str | None:
        """The `kid` property from the JWK.

        :rtype: str or None
        """
        return self._jwk_data.get("kid", None)

    @property
    def public_key_use(self) -> str | None:
        """The `use` property from the JWK.

        :rtype: str or None
        """
        return self._jwk_data.get("use", None)

    @property
    def is_private_key(self) -> bool:
        """Whether the JWK carries private key material.

        Asymmetric JWKs (``RSA``, ``EC`` and ``OKP``) expose their private
        exponent/curve key through the ``d`` member, while symmetric
        (``oct``) keys are neither public nor private and always report
        ``False`` here.

        :rtype: bool
        """
        if self.key_type == "oct":
            return False
        return "d" in self._jwk_data

    @property
    def has_certificate_chain(self) -> bool:
        """Whether the JWK embeds an X.509 certificate chain in ``x5c``.

        :rtype: bool
        """
        x5c = self._jwk_data.get("x5c")
        return isinstance(x5c, list) and len(x5c) > 0

    def matches(
        self,
        key_id: str,
        algorithm: str | None = None,
        key_type: str | None = None,
        intended_use: str | None = None,
        allow_private: bool = False,
    ) -> bool:
        """Check whether this key satisfies every supplied selector.

        Every supplied criterion must match; criteria left as ``None`` are
        not evaluated. Matching on ``algorithm`` also requires the key type
        (``kty``) supported by that algorithm, so a key can never be
        selected solely because its ``kid`` collides with another member.

        :param key_id: The required ``kid``.
        :param algorithm: The required algorithm name (e.g. ``"RS256"``).
        :param key_type: The required ``kty`` (e.g. ``"RSA"``).
        :param intended_use: The required ``use``; ``"sig"`` additionally
            accepts keys that do not declare a ``use``.
        :param allow_private: Whether asymmetric keys containing private
            material (``d``) are eligible.
        :rtype: bool
        """
        if self.key_id != key_id:
            return False

        if algorithm is not None and self.algorithm_name != algorithm:
            return False

        if key_type is not None and self.key_type != key_type:
            return False

        if intended_use is not None:
            if intended_use == "sig":
                if self.public_key_use not in ("sig", None):
                    return False
            elif self.public_key_use != intended_use:
                return False

        if not allow_private and self.is_private_key:
            return False

        return True


class PyJWKSet:
    def __init__(self, keys: list[JWKDict]) -> None:
        self.keys: list[PyJWK] = []

        if not keys:
            raise PyJWKSetError("The JWK Set did not contain any keys")

        if not isinstance(keys, list):
            raise PyJWKSetError("Invalid JWK Set value")

        for key in keys:
            if not isinstance(key, dict):
                # skip members that aren't JWK objects
                continue
            try:
                self.keys.append(PyJWK(key))
            except PyJWTError as error:
                if isinstance(error, MissingCryptographyError):
                    raise error
                # skip unusable keys
                continue

        if len(self.keys) == 0:
            raise PyJWKSetError(
                "The JWK Set did not contain any usable keys. Perhaps 'cryptography' is not installed?"
            )

    @staticmethod
    def from_dict(obj: dict[str, Any]) -> PyJWKSet:
        keys = obj.get("keys", [])
        return PyJWKSet(keys)

    @staticmethod
    def from_json(data: str) -> PyJWKSet:
        obj = json.loads(data)
        return PyJWKSet.from_dict(obj)

    def __getitem__(self, kid: str) -> PyJWK:
        return self.find_key(kid)

    def find_key(
        self,
        kid: str,
        algorithm: str | None = None,
        key_type: str | None = None,
        intended_use: str | None = None,
        allow_private: bool = False,
    ) -> PyJWK:
        """Return the unique set member matching every supplied selector.

        Selection is driven by the set membership (a key must actually be
        part of this set), its ``kid``, key type (``kty``), algorithm and
        intended use (``use``) together. When more than one member still
        matches, the request is ambiguous and fails closed instead of
        silently picking the first one, which lets callers cache the
        result without risking that an unrelated key sharing the same
        ``kid`` (a private key, a certificate-backed copy or a key for
        another algorithm) is returned.

        :param kid: The required ``kid``.
        :param algorithm: Optional required algorithm name.
        :param key_type: Optional required ``kty``.
        :param intended_use: Optional required ``use``; ``"sig"`` also
            accepts keys without an explicit ``use``.
        :param allow_private: Whether asymmetric private keys are eligible.
        :rtype: PyJWK
        :raises KeyError: If no member matches the selectors.
        :raises PyJWKSetError: If more than one member matches.
        """
        matches = [
            key
            for key in self.keys
            if key.matches(
                kid,
                algorithm=algorithm,
                key_type=key_type,
                intended_use=intended_use,
                allow_private=allow_private,
            )
        ]

        if not matches:
            raise KeyError(f"keyset has no key for kid: {kid}")

        if len(matches) > 1:
            raise PyJWKSetError(
                f"keyset has {len(matches)} ambiguous keys for kid: {kid}; "
                "narrow the selection with the algorithm, key type or use"
            )

        return matches[0]

    def __iter__(self) -> Iterator[PyJWK]:
        return iter(self.keys)


class PyJWTSetWithTimestamp:
    def __init__(self, jwk_set: PyJWKSet):
        self.jwk_set = jwk_set
        self.timestamp = time.monotonic()

    def get_jwk_set(self) -> PyJWKSet:
        return self.jwk_set

    def get_timestamp(self) -> float:
        return self.timestamp
