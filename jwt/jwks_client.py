from __future__ import annotations

import http.client
import json
import math
import threading
import time
import urllib.request
from functools import lru_cache
from ssl import SSLContext
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse

from .api_jwk import PyJWK, PyJWKSet
from .api_jwt import decode_complete as decode_token
from .exceptions import PyJWKClientConnectionError, PyJWKClientError
from .jwk_set_cache import JWKSetCache

#: Default upper bound, in bytes, on a JWKS response body. JWKS documents
#: are small JSON objects; a response larger than this is treated as a
#: misbehaving (or compromised) endpoint rather than being buffered without
#: limit.
DEFAULT_MAX_RESPONSE_SIZE = 64 * 1024

#: Media types that legitimately carry a JWKS payload. RFC 7517 section 5
#: registers ``application/jwk-set+json``; plain ``application/json`` is
#: what virtually every deployed endpoint actually serves.
_JSON_CONTENT_TYPES = frozenset(("application/json", "application/jwk-set+json"))


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        return None


class PyJWKClient:
    def __init__(
        self,
        uri: str,
        cache_keys: bool = False,
        max_cached_keys: int = 16,
        cache_jwk_set: bool = True,
        lifespan: float = 300,
        headers: dict[str, Any] | None = None,
        timeout: float = 30,
        ssl_context: SSLContext | None = None,
        cooldown_duration: float = 30,
        max_response_size: int = DEFAULT_MAX_RESPONSE_SIZE,
    ):
        """A client for retrieving signing keys from a JWKS endpoint.

        ``PyJWKClient`` uses a two-tier caching system to avoid unnecessary
        network requests:

        **Tier 1 — JWK Set cache** (enabled by default):
        Caches the entire JSON Web Key Set response from the endpoint.
        Controlled by:

        - ``cache_jwk_set``: Set to ``True`` (the default) to enable this
          cache. When enabled, the JWK Set is fetched from the network only
          when the cache is empty or expired.
        - ``lifespan``: Time in seconds before the cached JWK Set expires.
          Defaults to ``300`` (5 minutes). Must be greater than 0.

        Unknown key IDs can trigger one forced refresh after the cooldown
        period configured by ``cooldown_duration``. Every successful fetch
        starts this cooldown, including the initial fetch and cache-expiry
        fetches. A newly rotated key may therefore wait for the cooldown
        period before it is fetched; set ``cooldown_duration`` to ``0`` to
        disable this behavior. The cooldown is bypassed when
        ``cache_jwk_set`` is ``False``.

        **Tier 2 — Signing key cache** (disabled by default):
        Caches individual signing keys (looked up by ``kid``) using an LRU
        cache with **no time-based expiration**. Keys are evicted only when
        the cache reaches its maximum size. Controlled by:

        - ``cache_keys``: Set to ``True`` to enable this cache.
          Defaults to ``False``.
        - ``max_cached_keys``: Maximum number of signing keys to keep in
          the LRU cache. Defaults to ``16``.

        :param uri: The URL of the JWKS endpoint.
        :type uri: str
        :param cache_keys: Enable the per-key LRU cache (Tier 2).
        :type cache_keys: bool
        :param max_cached_keys: Max entries in the signing key LRU cache.
        :type max_cached_keys: int
        :param cache_jwk_set: Enable the JWK Set response cache (Tier 1).
        :type cache_jwk_set: bool
        :param lifespan: TTL in seconds for the JWK Set cache.
        :type lifespan: float
        :param headers: Optional HTTP headers to include in requests.
        :type headers: dict or None
        :param timeout: HTTP request timeout in seconds.
        :type timeout: float
        :param ssl_context: Optional SSL context for the request.
        :type ssl_context: ssl.SSLContext or None
        :param cooldown_duration: Minimum time in seconds between forced
            refreshes after an unknown key ID. Defaults to ``30``.
        :type cooldown_duration: float
        :param max_response_size: Maximum size, in bytes, of a JWKS
            response body. Larger responses are rejected without touching
            the cache. Defaults to 64 KiB. Must be a positive integer.
        :type max_response_size: int
        """
        if headers is None:
            headers = {}
        # urllib's default OpenerDirector also handles file://, ftp://, and
        # data: URIs. Reject anything that isn't http(s) eagerly so a caller
        # passing an attacker-influenced URL (e.g. taken from a `jku` token
        # header) can't read local files or reach other unintended schemes.
        scheme = urlparse(uri).scheme.lower()
        if scheme not in ("http", "https"):
            raise PyJWKClientError(
                f"Invalid JWKS URI scheme {scheme!r}: only 'http' and 'https' "
                f"are supported."
            )
        self.uri = uri
        self.jwk_set_cache: JWKSetCache | None = None
        self.headers = headers
        self.timeout = timeout
        self.ssl_context = ssl_context
        if cooldown_duration < 0:
            raise PyJWKClientError(
                "Cooldown duration must be greater than or equal to 0, "
                f'the input is "{cooldown_duration}"'
            )
        if not math.isfinite(cooldown_duration):
            raise PyJWKClientError(
                f'Cooldown duration must be finite, the input is "{cooldown_duration}"'
            )
        self.cooldown_duration = cooldown_duration
        if not isinstance(max_response_size, int) or max_response_size <= 0:
            raise PyJWKClientError(
                "max_response_size must be a positive integer, the input is "
                f'"{max_response_size}"'
            )
        self.max_response_size = max_response_size
        self._last_successful_fetch: float | None = None
        self._client_lock = threading.RLock()

        if cache_jwk_set:
            # Init jwt set cache with default or given lifespan.
            # Default lifespan is 300 seconds (5 minutes).
            if lifespan <= 0:
                raise PyJWKClientError(
                    f'Lifespan must be greater than 0, the input is "{lifespan}"'
                )
            self.jwk_set_cache = JWKSetCache(lifespan)
        else:
            self.jwk_set_cache = None

        if cache_keys:
            # Cache signing keys
            get_signing_key = lru_cache(maxsize=max_cached_keys)(self.get_signing_key)
            # Ignore mypy (https://github.com/python/mypy/issues/2427)
            self.get_signing_key = get_signing_key  # type: ignore[method-assign]

    def fetch_data(self) -> Any:
        """Fetch the JWK Set from the JWKS endpoint.

        Makes an HTTP request to the configured ``uri`` and returns the
        parsed JSON payload. The response is accepted only when all of the
        following hold:

        - it is a direct response with no redirect;
        - its ``Content-Type`` is JSON (``application/json`` or
          ``application/jwk-set+json``);
        - its body fits within ``max_response_size`` bytes;
        - the body parses as a JSON object holding a usable JWK Set.

        The JWK Set cache, including the timestamp used by the
        unknown-kid cooldown, is updated only after every check passes, so
        a redirect, an HTML error page, an oversized or truncated body, or
        a payload without usable keys can never replace or wipe a
        previously cached key set.

        :returns: The parsed JWK Set as a dictionary.
        :raises PyJWKClientConnectionError: If the HTTP request fails.
        :raises PyJWKClientError: If the response fails any of the
            validation checks above.
        """
        try:
            r = urllib.request.Request(url=self.uri, headers=self.headers)
            handlers: list[Any] = [_NoRedirectHandler()]
            if self.ssl_context is not None:
                handlers.append(urllib.request.HTTPSHandler(context=self.ssl_context))
            opener = urllib.request.build_opener(*handlers)
            with opener.open(r, timeout=self.timeout) as response:
                headers = response.headers
                read = response.read
                # Reading inside the transport try keeps dropped
                # connections (e.g. http.client.IncompleteRead) classified
                # as connection errors. Byte-budget enforcement raises a
                # PyJWKClientError, which is not caught here and therefore
                # surfaces as a validation failure rather than a transport
                # one.
                body = self._read_bounded_body(read)
        except (URLError, TimeoutError, http.client.HTTPException) as e:
            if isinstance(e, HTTPError):
                e.close()
            if isinstance(e, PyJWKClientError):
                # Validation failures raised while reading (byte budget)
                # are not transport errors; propagate them unchanged.
                raise
            raise PyJWKClientConnectionError(
                f'Fail to fetch data from the url, err: "{e}"'
            ) from e

        self._require_json_content_type(headers)

        try:
            payload = json.loads(body)
        except json.JSONDecodeError as e:
            # Includes bodies truncated mid-document: the partial bytes
            # must not be merged with the previously cached set.
            raise PyJWKClientError("The JWKS endpoint did not return valid JSON") from e

        payload = self._as_jwk_set_payload(payload)

        # Fully parse the key set before committing anything to the cache.
        # An empty set or a document whose keys are all unusable raises
        # here while the previously cached set stays untouched.
        parsed_jwk_set = PyJWKSet.from_dict(payload)
        self._commit_jwk_set(parsed_jwk_set)
        return payload

    def _commit_jwk_set(self, jwk_set: PyJWKSet) -> None:
        """Store *jwk_set* and its fetch timestamp as one state change.

        The cache entry and ``_last_successful_fetch`` always describe the
        same response, so a failure can never leave the cooldown clock
        advanced while the cache still holds the old key set (or vice
        versa).
        """
        if self.jwk_set_cache is not None:
            self.jwk_set_cache.put(jwk_set)
        self._last_successful_fetch = time.monotonic()

    def _require_json_content_type(self, headers: Any) -> None:
        content_type_getter = getattr(headers, "get_content_type", None)
        if callable(content_type_getter):
            content_type = headers.get_content_type()
        else:
            content_type = self._parse_content_type(headers.get("Content-Type", ""))
        if not isinstance(content_type, str):
            content_type = self._parse_content_type(headers.get("Content-Type", ""))
        if content_type not in _JSON_CONTENT_TYPES:
            raise PyJWKClientError(
                "The JWKS endpoint returned an unexpected Content-Type: "
                f"{content_type!r}"
            )

    @staticmethod
    def _parse_content_type(header_value: str) -> str:
        return header_value.split(";", 1)[0].strip().lower()

    def _read_bounded_body(self, read: Any) -> bytes:
        """Read the response body while enforcing the byte budget.

        Reading in chunks keeps the memory footprint at
        ``max_response_size`` plus one chunk instead of buffering an
        arbitrarily large body before its size is known.
        """
        chunks: list[bytes] = []
        total_size = 0
        while True:
            chunk = read(8192)
            if not chunk:
                break
            chunks.append(chunk)
            total_size += len(chunk)
            if total_size > self.max_response_size:
                raise PyJWKClientError(
                    "The JWKS endpoint response exceeded the maximum size "
                    f"of {self.max_response_size} bytes"
                )
        return b"".join(chunks)

    def get_jwk_set(self, refresh: bool = False) -> PyJWKSet:
        """Return the JWK Set, using the cache when available.

        :param refresh: Force a fresh fetch from the endpoint, bypassing
            the cache.
        :type refresh: bool
        :returns: The JWK Set.
        :rtype: PyJWKSet
        :raises PyJWKClientError: If the endpoint does not return a JSON
            object.
        """
        data: Any = None
        fetched = False
        if self.jwk_set_cache is not None and not refresh:
            data = self.jwk_set_cache.get()

        if data is None:
            data = self.fetch_data()
            fetched = True

        if isinstance(data, PyJWKSet):
            # Cache hit, or a successful base `fetch_data()`, which now
            # commits the fully parsed key set atomically.
            return data

        # Only an overridden `fetch_data()` in a subclass can reach here,
        # since the base implementation always commits a parsed PyJWKSet.
        jwk_set = PyJWKSet.from_dict(self._as_jwk_set_payload(data))

        # The subclass may filter or transform the payload before
        # returning. Cache the value actually being returned so later cache
        # hits serve the same key set rather than the pre-transform one.
        if fetched and self.jwk_set_cache is not None:
            self.jwk_set_cache.put(jwk_set)

        return jwk_set

    @staticmethod
    def _as_jwk_set_payload(data: Any) -> dict[str, Any]:
        if not isinstance(data, dict):
            raise PyJWKClientError("The JWKS endpoint did not return a JSON object")

        return data

    def get_signing_keys(self, refresh: bool = False) -> list[PyJWK]:
        """Return all signing keys from the JWK Set.

        Filters the JWK Set to keys whose ``use`` is ``"sig"`` (or
        unspecified) and that have a ``kid``.

        :param refresh: Force a fresh fetch from the endpoint, bypassing
            the cache.
        :type refresh: bool
        :returns: A list of signing keys.
        :rtype: list[PyJWK]
        :raises PyJWKClientError: If no signing keys are found.
        """
        jwk_set = self.get_jwk_set(refresh)
        return self._get_signing_keys_from_jwk_set(jwk_set)

    @staticmethod
    def _get_signing_keys_from_jwk_set(jwk_set: PyJWKSet) -> list[PyJWK]:
        signing_keys = [
            jwk_set_key
            for jwk_set_key in jwk_set.keys
            if jwk_set_key.public_key_use in ["sig", None] and jwk_set_key.key_id
        ]

        if not signing_keys:
            raise PyJWKClientError("The JWKS endpoint did not contain any signing keys")

        return signing_keys

    def get_signing_key(self, kid: str) -> PyJWK:
        """Return the signing key matching the given ``kid``.

        If no match is found in the current JWK Set, the set is refreshed
        from the endpoint and the lookup is retried once when the refresh
        cooldown permits it.

        :param kid: The key ID to look up.
        :type kid: str
        :returns: The matching signing key.
        :rtype: PyJWK
        :raises PyJWKClientError: If no matching key is found after
            refreshing.
        """
        with self._client_lock:
            signing_keys = self.get_signing_keys()
            signing_key = self.match_kid(signing_keys, kid)

            if not signing_key:
                cooling_down = (
                    self.jwk_set_cache is not None
                    and self._last_successful_fetch is not None
                    and time.monotonic() - self._last_successful_fetch
                    < self.cooldown_duration
                )
                if not cooling_down:
                    signing_keys = self.get_signing_keys(refresh=True)
                    # `fetch_data()` already advanced
                    # `_last_successful_fetch` atomically with the cache;
                    # touching it here would desynchronize the cooldown
                    # clock from the cached key set.
                    signing_key = self.match_kid(signing_keys, kid)

                if not signing_key:
                    raise PyJWKClientError(
                        f'Unable to find a signing key that matches: "{kid}"'
                    )

            return signing_key

    def get_signing_key_from_jwt(self, token: str | bytes) -> PyJWK:
        """Return the signing key for a JWT by reading its ``kid`` header.

        Extracts the ``kid`` from the token's unverified header and
        delegates to :meth:`get_signing_key`.

        :param token: The encoded JWT.
        :type token: str or bytes
        :returns: The matching signing key.
        :rtype: PyJWK
        """
        unverified = decode_token(token, options={"verify_signature": False})
        header = unverified["header"]
        return self.get_signing_key(header.get("kid"))

    @staticmethod
    def match_kid(signing_keys: list[PyJWK], kid: str) -> PyJWK | None:
        """Find a key in *signing_keys* that matches *kid*.

        :param signing_keys: The list of keys to search.
        :type signing_keys: list[PyJWK]
        :param kid: The key ID to match.
        :type kid: str
        :returns: The matching key, or ``None`` if not found.
        :rtype: PyJWK or None
        """
        signing_key = None

        for key in signing_keys:
            if key.key_id == kid:
                signing_key = key
                break

        return signing_key
