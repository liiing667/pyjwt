from __future__ import annotations

import binascii
import json
import warnings
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from .algorithms import (
    Algorithm,
    get_default_algorithms,
    has_crypto,
    requires_cryptography,
)
from .api_jwk import PyJWK
from .exceptions import (
    DecodeError,
    InvalidAlgorithmError,
    InvalidKeyError,
    InvalidSignatureError,
    InvalidTokenError,
)
from .utils import base64url_decode, base64url_encode
from .warnings import InsecureKeyLengthWarning, RemovedInPyjwt3Warning

if TYPE_CHECKING:
    from .algorithms import AllowedPrivateKeys, AllowedPublicKeys
    from .types import SigOptions

_ALGORITHM_UNSET = object()
_BASE64URL_ALPHABET = (
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)
# Header parameter names registered in RFC 7515 §4.1, plus the RFC 7797
# "b64" extension. Per RFC 7515 §4.1.11, "crit" lists extension header
# parameters only; standard names must never appear in it.
_STANDARD_HEADER_PARAMETERS = frozenset(
    {
        "alg",
        "jku",
        "jwk",
        "kid",
        "x5u",
        "x5c",
        "x5t",
        "x5t#S256",
        "typ",
        "cty",
        "crit",
        "b64",
    }
)


def _reject_duplicate_header_members(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    # JSON objects with duplicate member names are ambiguous: Python keeps
    # the last value while other JOSE processors may keep the first, so two
    # verifiers can disagree on "b64"/"crit" and hence on which payload the
    # signature covers. RFC 8725 §4.0.5 requires rejecting such headers.
    header: dict[str, Any] = {}
    for name, value in pairs:
        if name in header:
            raise DecodeError(
                f"Invalid header string: duplicate header parameter {name!r}"
            )
        header[name] = value
    return header


class PyJWS:
    header_typ = "JWT"

    def __init__(
        self,
        algorithms: Sequence[str] | None = None,
        options: SigOptions | None = None,
    ) -> None:
        self._algorithms = get_default_algorithms()
        self._valid_algs = (
            set(algorithms) if algorithms is not None else set(self._algorithms)
        )

        # Remove algorithms that aren't on the whitelist
        for key in list(self._algorithms.keys()):
            if key not in self._valid_algs:
                del self._algorithms[key]

        self.options: SigOptions = self._get_default_options()
        if options is not None:
            self.options = {**self.options, **options}

    @staticmethod
    def _get_default_options() -> SigOptions:
        return {"verify_signature": True, "enforce_minimum_key_length": False}

    def register_algorithm(self, alg_id: str, alg_obj: Algorithm) -> None:
        """
        Registers a new Algorithm for use when creating and verifying tokens.

        :param str alg_id: the ID of the Algorithm
        :param alg_obj: the Algorithm object
        :type alg_obj: Algorithm
        """
        if alg_id in self._algorithms:
            raise ValueError("Algorithm already has a handler.")

        if not isinstance(alg_obj, Algorithm):
            raise TypeError("Object is not of type `Algorithm`")

        self._algorithms[alg_id] = alg_obj
        self._valid_algs.add(alg_id)

    def unregister_algorithm(self, alg_id: str) -> None:
        """
        Unregisters an Algorithm for use when creating and verifying tokens
        :param str alg_id: the ID of the Algorithm
        :raises KeyError: if algorithm is not registered.
        """
        if alg_id not in self._algorithms:
            raise KeyError(
                "The specified algorithm could not be removed"
                " because it is not registered."
            )

        del self._algorithms[alg_id]
        self._valid_algs.remove(alg_id)

    def get_algorithms(self) -> list[str]:
        """
        Returns a list of supported values for the `alg` parameter.

        :rtype: list[str]
        """
        return list(self._valid_algs)

    def get_algorithm_by_name(self, alg_name: str) -> Algorithm:
        """
        For a given string name, return the matching Algorithm object.

        Example usage:
        >>> jws_obj = PyJWS()
        >>> jws_obj.get_algorithm_by_name("RS256")

        :param alg_name: The name of the algorithm to retrieve
        :type alg_name: str
        :rtype: Algorithm
        """
        try:
            return self._algorithms[alg_name]
        except KeyError as e:
            if not has_crypto and alg_name in requires_cryptography:
                raise NotImplementedError(
                    f"Algorithm '{alg_name}' could not be found. Do you have cryptography installed?"
                ) from e
            raise NotImplementedError("Algorithm not supported") from e

    def encode(
        self,
        payload: bytes,
        key: AllowedPrivateKeys | PyJWK | str | bytes,
        algorithm: str | None = _ALGORITHM_UNSET,  # type: ignore[assignment]
        headers: dict[str, Any] | None = None,
        json_encoder: type[json.JSONEncoder] | None = None,
        is_payload_detached: bool = False,
        sort_headers: bool = True,
    ) -> str:
        segments: list[bytes] = []

        # declare a new var to narrow the type for type checkers
        if algorithm is _ALGORITHM_UNSET:
            if isinstance(key, PyJWK):
                algorithm_ = key.algorithm_name
            else:
                algorithm_ = "HS256"
        elif algorithm is None:
            if isinstance(key, PyJWK):
                algorithm_ = key.algorithm_name
            else:
                algorithm_ = "none"
        else:
            algorithm_ = algorithm

        # Prefer headers values if present to function parameters.
        if headers:
            self._validate_headers(headers, encoding=True)

            headers_alg = headers.get("alg")
            if headers_alg:
                algorithm_ = headers["alg"]

            headers_b64 = headers.get("b64")
            if headers_b64 is False:
                is_payload_detached = True

        # Header
        header: dict[str, Any] = {"typ": self.header_typ, "alg": algorithm_}

        if headers:
            header.update(headers)

        if not header["typ"]:
            del header["typ"]

        if is_payload_detached:
            header["b64"] = False
            # RFC 7797 §3: producers MUST list "b64" in "crit" whenever
            # "b64" appears in the protected header, so b64-unaware
            # verifiers don't silently treat an unencoded payload as
            # base64-encoded.
            existing_crit = header.get("crit")
            if existing_crit is None:
                header["crit"] = ["b64"]
            else:
                # A non-list "crit" cannot be extended safely; deeper
                # semantic/uniqueness validation stays on the decode path so
                # producers can still forward headers they do not implement.
                if not isinstance(existing_crit, list):
                    raise InvalidTokenError(
                        "Invalid 'crit' header: must be a non-empty list"
                    )
            if existing_crit is not None and "b64" not in existing_crit:
                header["crit"] = [*existing_crit, "b64"]
        elif "b64" in header:
            # True is the standard value for b64, so no need for it
            del header["b64"]

        json_header = json.dumps(
            header, separators=(",", ":"), cls=json_encoder, sort_keys=sort_headers
        ).encode()

        segments.append(base64url_encode(json_header))

        if is_payload_detached:
            msg_payload = payload
        else:
            msg_payload = base64url_encode(payload)
        segments.append(msg_payload)

        # Segments
        signing_input = b".".join(segments)

        alg_obj = self.get_algorithm_by_name(algorithm_)
        if isinstance(key, PyJWK):
            key = key.key
        key = alg_obj.prepare_key(key)

        key_length_msg = alg_obj.check_key_length(key)
        if key_length_msg:
            if self.options.get("enforce_minimum_key_length", False):
                raise InvalidKeyError(key_length_msg)
            else:
                warnings.warn(key_length_msg, InsecureKeyLengthWarning, stacklevel=2)

        signature = alg_obj.sign(signing_input, key)

        segments.append(base64url_encode(signature))

        # Don't put the payload content inside the encoded token when detached
        if is_payload_detached:
            segments[1] = b""
        encoded_string = b".".join(segments)

        return encoded_string.decode("utf-8")

    def decode_complete(
        self,
        jwt: str | bytes,
        key: AllowedPublicKeys | PyJWK | str | bytes = "",
        algorithms: Sequence[str] | None = None,
        options: SigOptions | None = None,
        detached_payload: bytes | None = None,
        **kwargs: dict[str, Any],
    ) -> dict[str, Any]:
        if kwargs:
            warnings.warn(
                "passing additional kwargs to decode_complete() is deprecated "
                "and will be removed in pyjwt version 3. "
                f"Unsupported kwargs: {tuple(kwargs.keys())}",
                RemovedInPyjwt3Warning,
                stacklevel=2,
            )
        merged_options: SigOptions
        if options is None:
            merged_options = self.options
        else:
            merged_options = {**self.options, **options}

        verify_signature = merged_options["verify_signature"]

        if verify_signature and not algorithms and not isinstance(key, PyJWK):
            raise DecodeError(
                'It is required that you pass in a value for the "algorithms" argument when calling decode().'
            )

        payload, signing_input, header, signature = self._load(jwt)

        self._validate_headers(header)

        b64_value = header.get("b64", True)
        if "b64" in header and not isinstance(b64_value, bool):
            # RFC 7797 §3: "b64" must be a JSON boolean. Values such as
            # "false", 0 or null let different processors pick different
            # payloads (detached vs. base64url), so reject rather than guess.
            raise InvalidTokenError("The 'b64' header parameter must be a JSON boolean")

        if detached_payload is not None and not isinstance(detached_payload, bytes):
            # The detached payload is concatenated into the signing input.
            # A str (or any non-bytes value) would be implicitly encoded by
            # the join below, so pin the type explicitly and fail closed.
            raise DecodeError('"detached_payload" must be bytes')

        if detached_payload is not None and b64_value is not False:
            raise DecodeError(
                'It is only valid to pass "detached_payload" when the protected header has "b64" set to false.'
            )

        if b64_value is False:
            # RFC 7797 §3: when "b64" is present in the protected header,
            # it MUST also appear in "crit". A token that sets b64=false
            # without declaring it critical is malformed.
            crit = header.get("crit") or []
            if not isinstance(crit, list) or "b64" not in crit:
                raise InvalidTokenError(
                    "The 'b64' header parameter requires 'b64' to be listed in 'crit'."
                )
            if detached_payload is None:
                raise DecodeError(
                    'It is required that you pass in a value for the "detached_payload" argument to decode a message having the b64 header set to false.'
                )
            # Bind the caller-supplied payload to the exact bytes covered by
            # the signature. _load already guaranteed the compact-form middle
            # segment is empty, so no token-borne bytes participate here.
            payload = detached_payload
            signing_input = b".".join([signing_input.rsplit(b".", 1)[0], payload])

        if verify_signature:
            self._verify_signature(
                signing_input,
                header,
                signature,
                key,
                algorithms,
                options=merged_options,
            )

        return {
            "payload": payload,
            "header": header,
            "signature": signature,
        }

    def decode(
        self,
        jwt: str | bytes,
        key: AllowedPublicKeys | PyJWK | str | bytes = "",
        algorithms: Sequence[str] | None = None,
        options: SigOptions | None = None,
        detached_payload: bytes | None = None,
        **kwargs: dict[str, Any],
    ) -> Any:
        if kwargs:
            warnings.warn(
                "passing additional kwargs to decode() is deprecated "
                "and will be removed in pyjwt version 3. "
                f"Unsupported kwargs: {tuple(kwargs.keys())}",
                RemovedInPyjwt3Warning,
                stacklevel=2,
            )
        decoded = self.decode_complete(
            jwt, key, algorithms, options, detached_payload=detached_payload
        )
        return decoded["payload"]

    def get_unverified_header(self, jwt: str | bytes) -> dict[str, Any]:
        """Returns back the JWT header parameters as a `dict`

        Note: The signature is not verified so the header parameters
        should not be fully trusted until signature verification is complete
        """
        headers = self._load(jwt)[2]
        self._validate_headers(headers)

        return headers

    @staticmethod
    def _decode_base64url_segment(segment: bytes, name: str) -> bytes:
        # Accept trailing '=' used by some issuers (e.g. AWS ALB). Still
        # reject non-alphabet junk such as '!!!!' (GHSA-hxm8-2xgr-2p9m).
        padding = 0
        stripped = segment
        while stripped.endswith(b"="):
            stripped = stripped[:-1]
            padding += 1
            if padding > 2:
                raise DecodeError(f"Invalid {name} padding")

        if padding and len(segment) % 4 != 0:
            raise DecodeError(f"Invalid {name} padding")

        if len(stripped) % 4 == 1 or any(
            character not in _BASE64URL_ALPHABET for character in stripped
        ):
            raise DecodeError(f"Invalid {name} padding")

        try:
            decoded = base64url_decode(stripped)
        except (TypeError, binascii.Error) as err:
            raise DecodeError(f"Invalid {name} padding") from err

        if base64url_encode(decoded) != stripped:
            raise DecodeError(f"Invalid {name} padding")

        return decoded

    def _load(self, jwt: str | bytes) -> tuple[bytes, bytes, dict[str, Any], bytes]:
        if isinstance(jwt, str):
            jwt = jwt.encode("utf-8")

        if not isinstance(jwt, bytes):
            raise DecodeError(f"Invalid token type. Token must be a {bytes}")

        try:
            signing_input, crypto_segment = jwt.rsplit(b".", 1)
            header_segment, payload_segment = signing_input.split(b".", 1)
        except ValueError as err:
            raise DecodeError("Not enough segments") from err

        header_data = self._decode_base64url_segment(header_segment, "header")

        try:
            header: dict[str, Any] = json.loads(
                header_data, object_pairs_hook=_reject_duplicate_header_members
            )
        except (ValueError, RecursionError) as e:
            raise DecodeError(f"Invalid header string: {e}") from e

        if not isinstance(header, dict):
            raise DecodeError("Invalid header string: must be a json object")

        if header.get("b64", True) is False:
            # Detached payload form (RFC 7515 Appendix F): the compact-form
            # payload segment must be empty; the caller supplies the actual
            # payload via the `detached_payload` argument in decode_complete.
            # Skipping the base64 decode here removes an unauthenticated work
            # amplifier — otherwise an attacker can inflate the unused
            # segment to force CPU + memory cost before the signature is
            # even checked.
            if payload_segment:
                raise DecodeError("Payload segment must be empty when 'b64' is false.")
            payload = b""
        else:
            payload = self._decode_base64url_segment(payload_segment, "payload")

        signature = self._decode_base64url_segment(crypto_segment, "crypto")

        return (payload, signing_input, header, signature)

    def _verify_signature(
        self,
        signing_input: bytes,
        header: dict[str, Any],
        signature: bytes,
        key: AllowedPublicKeys | PyJWK | str | bytes = "",
        algorithms: Sequence[str] | None = None,
        options: SigOptions | None = None,
    ) -> None:
        effective_options = options if options is not None else self.options

        if algorithms is None and isinstance(key, PyJWK):
            algorithms = [key.algorithm_name]
        try:
            alg = header["alg"]
        except KeyError:
            raise InvalidAlgorithmError("Algorithm not specified") from None

        if not alg or (algorithms is not None and alg not in algorithms):
            raise InvalidAlgorithmError("The specified alg value is not allowed")

        if isinstance(key, PyJWK):
            # The PyJWK has a fixed algorithm bound at construction time.
            # Verification must use that algorithm, not whatever the token
            # header advertises, otherwise the caller's allow-list check
            # above degenerates into a string compare with no behavioural
            # effect on which algorithm actually verifies the signature.
            if alg != key.algorithm_name:
                raise InvalidAlgorithmError(
                    f"Token algorithm {alg!r} does not match the key's "
                    f"algorithm {key.algorithm_name!r}"
                )
            alg_obj = key.Algorithm
            prepared_key = alg_obj.prepare_key(key.key)
        else:
            try:
                alg_obj = self.get_algorithm_by_name(alg)
            except NotImplementedError as e:
                raise InvalidAlgorithmError("Algorithm not supported") from e
            prepared_key = alg_obj.prepare_key(key)

        key_length_msg = alg_obj.check_key_length(prepared_key)
        if key_length_msg:
            if effective_options.get("enforce_minimum_key_length", False):
                raise InvalidKeyError(key_length_msg)
            else:
                warnings.warn(key_length_msg, InsecureKeyLengthWarning, stacklevel=4)

        if not alg_obj.verify(signing_input, prepared_key, signature):
            raise InvalidSignatureError("Signature verification failed")

    # Extensions that PyJWT actually understands and supports
    _supported_crit: set[str] = {"b64"}

    def _validate_headers(
        self, headers: dict[str, Any], *, encoding: bool = False
    ) -> None:
        if "kid" in headers:
            self._validate_kid(headers["kid"])
        if "b64" in headers and not isinstance(headers["b64"], bool):
            # Same fail-closed rule as the decode path: the b64 type decides
            # whether the payload is detached, and non-boolean JSON values
            # are interpreted differently across JOSE implementations.
            raise InvalidTokenError("The 'b64' header parameter must be a JSON boolean")
        if "crit" in headers and not encoding:
            self._validate_crit(headers)

    def _validate_kid(self, kid: Any) -> None:
        if not isinstance(kid, str):
            raise InvalidTokenError("Key ID header parameter must be a string")

    def _validate_crit_shape(self, crit: Any) -> None:
        if not isinstance(crit, list):
            raise InvalidTokenError("Invalid 'crit' header: must be a non-empty list")
        for ext in crit:
            if not isinstance(ext, str):
                raise InvalidTokenError("Invalid 'crit' header: values must be strings")
        # RFC 7515 §4.1.11: the "crit" list MUST NOT contain duplicate header
        # parameter names. A duplicated entry lets processors diverge on which
        # occurrence governs processing of the payload.
        if len(set(crit)) != len(crit):
            raise InvalidTokenError(
                "Invalid 'crit' header: duplicate header parameter names are not allowed"
            )

    def _validate_crit_structure(self, crit: Any) -> None:
        self._validate_crit_shape(crit)
        if len(crit) == 0:
            raise InvalidTokenError("Invalid 'crit' header: must be a non-empty list")

    def _validate_crit(self, headers: dict[str, Any]) -> None:
        crit = headers["crit"]
        # Runs on the decode/get_unverified_header path only. Every rule
        # here is fail-closed: shape (list of unique strings), no standard
        # parameter names, every extension must be implemented and present,
        # and "b64" in crit requires an actual b64=false header.
        self._validate_crit_structure(crit)
        for ext in crit:
            if ext in _STANDARD_HEADER_PARAMETERS and ext != "b64":
                # RFC 7515 §4.1.11: "crit" names extension header parameters;
                # standard parameters have defined semantics already, and
                # listing them makes compliant implementations disagree.
                raise InvalidTokenError(
                    f"Invalid 'crit' header: standard header parameter {ext!r} must not be listed as critical"
                )
            if ext not in self._supported_crit:
                raise InvalidTokenError(f"Unsupported critical extension: {ext}")
            if ext not in headers:
                raise InvalidTokenError(
                    f"Critical extension '{ext}' is missing from headers"
                )
            if ext == "b64":
                # RFC 7797 §3 explicitly registers "b64" as the one
                # extension that may (and must) appear in "crit".
                if headers.get("b64") is not False:
                    raise InvalidTokenError(
                        "The 'b64' header parameter requires 'b64' to be listed in 'crit'."
                    )


_jws_global_obj = PyJWS()
encode = _jws_global_obj.encode
decode_complete = _jws_global_obj.decode_complete
decode = _jws_global_obj.decode
register_algorithm = _jws_global_obj.register_algorithm
unregister_algorithm = _jws_global_obj.unregister_algorithm
get_algorithm_by_name = _jws_global_obj.get_algorithm_by_name
get_unverified_header = _jws_global_obj.get_unverified_header
