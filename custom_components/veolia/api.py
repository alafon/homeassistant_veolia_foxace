"""Veolia API client authenticating with a Cognito refresh token.

Some portals -- Eau de Toulouse Métropole in particular -- put password
sign-ins behind Cognito's adaptive authentication, which answers `SMS_MFA`
instead of tokens whenever it does not recognise the caller's context. On
accounts migrated to those portals the pool's `phone_number` attribute is an
unverified placeholder, so the SMS code never arrives and the challenge can
never be answered.

`REFRESH_TOKEN_AUTH` is not a sign-in flow: Cognito does not risk-score it and
never challenges it. A refresh token obtained once from a trusted context
therefore authenticates from any address, which also makes the setup immune to
the caller's IP changing.
"""

from datetime import datetime, timedelta
from http import HTTPStatus

import aiohttp
from veolia_api import VeoliaAPI
from veolia_api.constants import LOGIN_URL, POST
from veolia_api.exceptions import VeoliaAPITokenError

from .const import LOGGER


class VeoliaRefreshTokenAPI(VeoliaAPI):
    """VeoliaAPI variant that authenticates with a refresh token."""

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

        Mirrors the upstream sequence, skipping its e-mail format validation
        which has no meaning here.
        """
        await self._get_access_token()
        await self._get_client_data()
        return bool(
            self.account_data.access_token
            and self.account_data.id_abonnement
            and self.account_data.numero_pds,
        )

    async def _get_access_token(self) -> None:
        """Exchange the refresh token for a fresh access token."""
        # _send_request adds an Authorization header as soon as an access token
        # is set: presenting the expired one to Cognito makes no sense.
        self.account_data.access_token = None

        response = await self._send_request(
            url=LOGIN_URL,
            method=POST,
            json_data={
                "ClientId": self._client_id,
                "AuthFlow": "REFRESH_TOKEN_AUTH",
                "AuthParameters": {"REFRESH_TOKEN": self._refresh_token},
            },
            is_login=True,
        )
        token_data = await response.json(content_type="json")

        if response.status != HTTPStatus.OK:
            raise VeoliaAPITokenError(
                f"Refresh rejected: {token_data.get('__type')} - "
                f"{token_data.get('message')}",
            )

        result = token_data.get("AuthenticationResult") or {}
        access_token = result.get("AccessToken")
        if not access_token:
            raise VeoliaAPITokenError(
                f"No access token in response (keys: {sorted(token_data)})",
            )

        self.account_data.access_token = access_token
        self.account_data.token_expiration = (
            datetime.now() + timedelta(seconds=result.get("ExpiresIn", 0))
        ).timestamp()
        LOGGER.debug("Access token renewed through REFRESH_TOKEN_AUTH")
