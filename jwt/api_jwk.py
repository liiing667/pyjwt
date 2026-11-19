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
    PyJWKSetAmbiguousKeyError,
    PyJWKSetError,
    PyJWTError,
)
from .types import JWKDict

#: Maps every supported JWS algorithm to the key type (``kty``) it uses,
#: so an algorithm-aware lookup can reject a key whose family cannot
#: perform the requested algorithm even when the JWK omits ``alg``.
_ALGORITHM_KEY_TYPES: dict[str, str] = {
    "HS256": "oct",
    "HS384": "oct",
    "HS512": "oct",
    "RS256": "RSA",
    "RS384": "RSA",
    "RS512": "RSA",
    "PS256": "RSA",
    "PS384": "RSA",
    "PS512": "RSA",
    "ES256": "EC",
    "ES256K": "EC",
    "ES384": "EC",
    "ES512": "EC",
    "ES521": "EC",
    "EdDSA": "OKP",
}

#: JWK members that mark an asymmetric key as carrying private material.
#: ``oct`` keys are symmetric secrets and stay usable for verification.
_PRIVATE_KEY_MEMBERS = frozenset(("d",))

#: JWK members that carry certificate material.
_CERTIFICATE_MEMBERS = frozenset(("x5c", "x5t", "x5t#S256"))


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
    def has_private_key(self) -> bool:
        """Whether the JWK carries asymmetric private-key material.

        Asymmetric keys with a private member (``d``) can sign but must
        never be picked for signature verification against another key's
        ``kid``. Symmetric (``oct``) keys are not considered private here:
        their secret is both the signing and the verification material.

        :rtype: bool
        """
        if self.key_type == "oct":
            return False
        return any(member in self._jwk_data for member in _PRIVATE_KEY_MEMBERS)

    @property
    def is_symmetric(self) -> bool:
        """Whether the JWK is a symmetric (``oct``) key.

        :rtype: bool
        """
        return self.key_type == "oct"

    @property
    def has_certificate(self) -> bool:
        """Whether the JWK embeds certificate material (``x5c``/``x5t``).

        A key represented through a certificate chain is a distinct member
        from a plain public-key JWK, even when both share a ``kid``.

        :rtype: bool
        """
        return any(member in self._jwk_data for member in _CERTIFICATE_MEMBERS)

    @property
    def key_material(self) -> str:
        """A stable label for the kind of key material the JWK represents.

        One of ``"symmetric"``, ``"private"``, ``"certificate"`` or
        ``"public"``. Together with :attr:`key_type`,
        :attr:`algorithm_name` and :attr:`public_key_use` this lets a key
        set tell same-``kid`` members apart instead of relying on their
        position in the set.

        :rtype: str
        """
        if self.is_symmetric:
            return "symmetric"
        if self.has_private_key:
            return "private"
        if self.has_certificate:
            return "certificate"
        return "public"


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
        try:
            return self.get_key(kid)
        except PyJWKSetAmbiguousKeyError as error:
            # Keep the mapping protocol: an ambiguous or missing kid is a
            # KeyError for __getitem__ callers, while the explicit
            # get_key() API surfaces the ambiguity reason.
            raise KeyError(str(error)) from error

    def __iter__(self) -> Iterator[PyJWK]:
        return iter(self.keys)

    def get_key(
        self,
        kid: str,
        algorithm: str | None = None,
        use: str | None = None,
        verification_key: bool = True,
    ) -> PyJWK:
        """Return the single key matching *kid* and the other constraints.

        Selection is driven by every dimension that distinguishes set
        members, rather than the order they appear in:

        - ``kid`` must match;
        - *algorithm* (the JWS ``alg`` of the token being verified, if
          known) must be compatible with the key's family and with an
          explicit ``alg`` member;
        - *use* must be compatible with the key's ``use`` member;
        - when *verification_key* is true, asymmetric private keys are
          excluded so a signing key can never be returned where only a
          verification key is safe.

        If the constraints still match more than one distinguishable key,
        the lookup fails closed with :class:`PyJWKSetAmbiguousKeyError`
        instead of returning whichever member happens to come first.

        :param kid: The key ID to match.
        :type kid: str
        :param algorithm: The JWS algorithm the key must support.
        :type algorithm: str or None
        :param use: The intended public key use (e.g. ``"sig"``).
        :type use: str or None
        :param verification_key: Reject asymmetric private keys when true.
        :type verification_key: bool
        :rtype: PyJWK
        :raises PyJWKSetAmbiguousKeyError: If zero or multiple keys match.
        """
        matches = select_keys(
            self.keys,
            kid,
            algorithm=algorithm,
            use=use,
            verification_key=verification_key,
        )

        if not matches:
            raise PyJWKSetAmbiguousKeyError(
                f"keyset has no key for kid: {kid!r}, algorithm: "
                f"{algorithm!r}, use: {use!r}"
            )

        fingerprints = _member_fingerprints(matches)
        if len(fingerprints) > 1:
            raise PyJWKSetAmbiguousKeyError(
                f"kid {kid!r} is not unique in the JWK Set: "
                f"{len(fingerprints)} distinguishable keys match "
                f"algorithm {algorithm!r} and use {use!r}"
            )

        return matches[0]


def select_keys(
    keys: list[PyJWK],
    kid: str,
    algorithm: str | None = None,
    use: str | None = None,
    verification_key: bool = True,
) -> list[PyJWK]:
    """Filter *keys* to the members compatible with a key-selection request.

    See :meth:`PyJWKSet.get_key` for the meaning of each constraint. Every
    constraint narrows the candidates; nothing here guesses between keys.
    """
    expected_kty = _ALGORITHM_KEY_TYPES.get(algorithm) if algorithm else None

    matches: list[PyJWK] = []
    for key in keys:
        if key.key_id != kid:
            continue

        if verification_key and key.has_private_key:
            # An asymmetric private key can sign but must not be handed to
            # a verifier, even when it shares the requested kid.
            continue

        if use is not None and key.public_key_use not in (use, None):
            continue

        if expected_kty is not None and key.key_type != expected_kty:
            continue

        if algorithm is not None:
            declared = key._jwk_data.get("alg")
            if declared is not None and declared != algorithm:
                continue

        matches.append(key)

    return matches


def _member_fingerprints(keys: list[PyJWK]) -> set[str]:
    """Canonical fingerprints of the JWK payloads in *keys*.

    Member order is ignored, so a repeated copy of the same JWK produces a
    single fingerprint instead of looking like a second identity.
    """
    return {
        json.dumps(key._jwk_data, sort_keys=True, separators=(",", ":")) for key in keys
    }


def has_distinct_members(keys: list[PyJWK]) -> bool:
    """Whether *keys* hold more than one distinguishable JWK identity.

    Repeated copies of the same JWK (common while a rotation window keeps
    old and new documents overlapping) are not ambiguity, but keys whose
    members differ are distinct identities and must fail closed.
    """
    return len(_member_fingerprints(keys)) > 1


class PyJWTSetWithTimestamp:
    def __init__(self, jwk_set: PyJWKSet):
        self.jwk_set = jwk_set
        self.timestamp = time.monotonic()

    def get_jwk_set(self) -> PyJWKSet:
        return self.jwk_set

    def get_timestamp(self) -> float:
        return self.timestamp
