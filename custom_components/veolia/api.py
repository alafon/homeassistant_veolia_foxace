"""Cognito authentication variants for portals behind adaptive authentication.

Some portals -- Eau de Toulouse Métropole in particular -- put password
sign-ins behind Cognito's adaptive authentication, which answers a challenge
instead of tokens whenever it does not recognise the caller's context. On
accounts migrated to those portals the pool's ``phone_number`` is an unverified
placeholder, so the SMS code never arrives and the challenge can never be
answered.

Two consequences are handled here:

* a challenge is reported as :class:`VeoliaChallengeError` rather than the
  library's generic "Authentication failed", so the config flow can tell the
  user what happened and where to go next;
* :class:`VeoliaRefreshTokenAPI` authenticates with ``REFRESH_TOKEN_AUTH``,
  which is not a sign-in flow and is therefore never risk-scored. A token
  obtained once from a context Cognito already trusts authenticates from any
  address -- the way to bootstrap an address it has never seen.

Cognito's risk score warms up: an address that keeps presenting valid tokens
eventually stops being challenged, at which point the password method works
again. The refresh token is the cold-start tool, not the steady state -- it is
capped at one hour on this pool and ``REFRESH_TOKEN_AUTH`` returns no new one.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from typing import TYPE_CHECKING, Any

import aiohttp
from veolia_api import VeoliaAPI
from veolia_api.constants import LOGIN_URL, POST
from veolia_api.exceptions import (
    VeoliaAPIError,
    VeoliaAPIInvalidCredentialsError,
    VeoliaAPITokenError,
)

from .const import LOGGER

if TYPE_CHECKING:
    from collections.abc import Mapping

    from veolia_api.model import VeoliaAccountData

DEFAULT_TOKEN_LIFETIME = 3600


class VeoliaChallengeError(VeoliaAPIError):
    """Cognito answered a sign-in with a challenge instead of tokens."""

    def __init__(self, challenge_name: str) -> None:
        """Record which challenge was demanded."""
        self.challenge_name = challenge_name
        super().__init__(
            f"Cognito demanded the {challenge_name} challenge, "
            "which this integration cannot answer",
        )


class _CognitoAuthMixin:
    """Shared Cognito exchange, mirroring the library's own error handling.

    The library reads ``AuthenticationResult`` and raises a bare
    "Authentication failed" when it is absent -- which is exactly what a
    challenge response looks like. This mixin keeps every other branch
    identical and only tells that case apart.

    MIRRORS ``VeoliaAPI._get_access_token`` of veolia-api-foxace 2.4.4,
    ``_auth_generation`` bookkeeping included. Re-read that method when
    bumping the requirement: this is the one place that drifts silently.
    The proper home for all of this is the library itself -- see
    ``alafon/veolia-api``, kept for that contribution.
    """

    if TYPE_CHECKING:
        # Supplied by VeoliaAPI, which this mixin is always combined with.
        account_data: VeoliaAccountData
        _client_id: str
        _auth_generation: int

        async def _send_request(  # noqa: PLR0913
            self,
            url: str,
            method: str,
            params: dict[str, Any] | None = None,
            json_data: dict[str, Any] | None = None,
            login_json: dict[str, Any] | None = None,
            *,
            allow_reauth: bool = True,
        ) -> aiohttp.ClientResponse: ...

    async def _exchange(self, payload: Mapping[str, Any]) -> None:
        """Run one Cognito call and store the resulting access token."""
        response = await self._send_request(
            url=LOGIN_URL,
            method=POST,
            login_json=dict(payload),
        )

        try:
            token_data = await response.json(content_type="json")
        except (aiohttp.ContentTypeError, ValueError) as err:
            response.release()
            raise VeoliaAPITokenError(
                f"Unexpected Cognito response (HTTP {response.status})",
            ) from err

        if not isinstance(token_data, dict):
            raise VeoliaAPITokenError(
                f"Empty Cognito response (HTTP {response.status})",
            )

        if response.status != HTTPStatus.OK:
            error_type = token_data.get("__type", "")
            if error_type in ("NotAuthorizedException", "UserNotFoundException"):
                raise VeoliaAPIInvalidCredentialsError(
                    token_data.get("message", "Invalid credentials"),
                )
            raise VeoliaAPITokenError(
                "Token API call error: " + token_data.get("message", "Unknown error"),
            )

        if challenge := token_data.get("ChallengeName"):
            raise VeoliaChallengeError(challenge)

        authentication_result = token_data.get("AuthenticationResult")
        if not authentication_result:
            raise VeoliaAPITokenError("Authentication failed")

        self.account_data.access_token = authentication_result.get("AccessToken")
        if not self.account_data.access_token:
            raise VeoliaAPITokenError("Access token not found")

        expires_in = authentication_result.get("ExpiresIn")
        if not expires_in:
            LOGGER.warning("Cognito response has no ExpiresIn, assuming 3600 seconds")
            expires_in = DEFAULT_TOKEN_LIFETIME
        self.account_data.token_expiration = (
            datetime.now(UTC) + timedelta(seconds=expires_in)
        ).timestamp()
        self._auth_generation += 1

    def _logged_in(self) -> bool:
        """Return whether the account data is complete, as the library does."""
        return bool(
            self.account_data.access_token
            and self.account_data.id_abonnement
            and self.account_data.numero_pds
            and self.account_data.contact_id
            and self.account_data.tiers_id
            and self.account_data.numero_compteur
            and self.account_data.date_debut_abonnement,
        )


class VeoliaCredentialsAPI(_CognitoAuthMixin, VeoliaAPI):
    """Password client that reports a Cognito challenge as such."""

    async def _get_access_token(self) -> None:
        """Sign in, telling a challenge apart from a plain failure."""
        await self._exchange(
            {
                "ClientId": self._client_id,
                "AuthFlow": "USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "USERNAME": self.username,
                    "PASSWORD": self.password,
                },
            },
        )
        LOGGER.debug("Access token retrieved through USER_PASSWORD_AUTH")


class VeoliaRefreshTokenAPI(_CognitoAuthMixin, VeoliaAPI):
    """Client authenticating with a Cognito refresh token."""

    def __init__(
        self,
        refresh_token: str,
        session: aiohttp.ClientSession | None = None,
        portal_url: str | None = None,
    ) -> None:
        """Initialize the client. No username or password is needed."""
        super().__init__(
            username="",
            password="",
            session=session,
            portal_url=portal_url,
        )
        self._refresh_token = refresh_token

    async def login(self) -> bool:
        """Open a session without credentials.

        Mirrors the library's sequence, skipping its e-mail format validation
        which has no meaning here.
        """
        LOGGER.debug("Logging in with a refresh token")
        await self._get_access_token()
        await self._get_client_data()
        return self._logged_in()

    async def _get_access_token(self) -> None:
        """Exchange the refresh token for a fresh access token."""
        # _send_request adds an Authorization header as soon as an access token
        # is set: presenting the expired one to Cognito makes no sense.
        self.account_data.access_token = None
        await self._exchange(
            {
                "ClientId": self._client_id,
                "AuthFlow": "REFRESH_TOKEN_AUTH",
                "AuthParameters": {"REFRESH_TOKEN": self._refresh_token},
            },
        )
        LOGGER.debug("Access token renewed through REFRESH_TOKEN_AUTH")
