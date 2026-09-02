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

from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from typing import Any

import aiohttp
from veolia_api import VeoliaAPI
from veolia_api.constants import BACKEND_ISTEFR, GET, LOGIN_URL, POST, ConsumptionType
from veolia_api.exceptions import (
    VeoliaAPIError,
    VeoliaAPIGetDataError,
    VeoliaAPIInvalidCredentialsError,
    VeoliaAPITokenError,
)

from .const import LOGGER


class VeoliaChallengeError(VeoliaAPIError):
    """Cognito answered a sign-in with a challenge instead of tokens.

    Its adaptive authentication demands a second factor whenever it does not
    recognise the caller's context. On accounts migrated to a delegated portal
    the pool's phone number is often an unverified placeholder, so the SMS code
    never arrives and the challenge cannot be answered at all -- which is why
    this is reported as its own error rather than a generic failure.
    """

    def __init__(self, challenge_name: str) -> None:
        """Record which challenge was demanded."""
        self.challenge_name = challenge_name
        super().__init__(
            f"Cognito demanded the {challenge_name} challenge, "
            "which this integration cannot answer",
        )


class SubscriptionWindowMixin:
    """Fix which periods are considered covered by the subscription.

    Upstream aborts any request whose period *starts* before the subscription
    does, and takes January 1st as the start of a yearly request. A
    subscription opened during the current year therefore loses its entire
    monthly breakdown until the next January, and the very month it started in
    is dropped whole even though most of it is covered.

    A period is worth requesting as soon as it *ends* on or after the
    subscription start, which for whole months and years reduces to comparing
    year and month.
    """

    async def _get_consumption_data(
        self,
        data_type: ConsumptionType,
        year: int,
        month: int | None = None,
    ) -> list[dict[str, Any]]:
        """Get consumption data, skipping only periods fully before the start."""
        start = datetime.strptime(
            self.account_data.date_debut_abonnement,
            "%Y-%m-%d",
        ).replace(tzinfo=UTC)

        covered = (
            (year, month) >= (start.year, start.month)
            if month is not None
            else year >= start.year
        )
        if not covered:
            LOGGER.debug(
                "Period %s-%s ends before subscription start %s, skipped",
                year,
                month,
                self.account_data.date_debut_abonnement,
            )
            return []

        params: dict[str, Any] = {
            "annee": year,
            "numero-pds": self.account_data.numero_pds,
            "date-debut-abonnement": self.account_data.date_debut_abonnement,
        }
        if data_type == ConsumptionType.MONTHLY and month is not None:
            params["mois"] = month
            endpoint = "journalieres"
        elif data_type == ConsumptionType.YEARLY:
            endpoint = "mensuelles"
        else:
            raise ValueError("Invalid data type or missing month for monthly data")

        response = await self._send_request(
            url=(
                f"{BACKEND_ISTEFR}/consommations/"
                f"{self.account_data.id_abonnement}/{endpoint}"
            ),
            method=GET,
            params=params,
        )
        if response.status != HTTPStatus.OK:
            raise VeoliaAPIGetDataError(
                f"call to= consommations failed with http status= {response.status}",
            )
        return await response.json()


class VeoliaCredentialsAPI(SubscriptionWindowMixin, VeoliaAPI):
    """Username/password client that reports why a sign-in failed."""

    async def _get_access_token(self) -> None:
        """Sign in, telling a challenge apart from a plain failure.

        Upstream reads AuthenticationResult and raises a bare "Authentication
        failed" when it is absent, which is exactly what a challenge response
        looks like. Rejected credentials are likewise reported as a generic
        token error. Both cases deserve their own diagnosis.
        """
        self.account_data.access_token = None

        response = await self._send_request(
            url=LOGIN_URL,
            method=POST,
            json_data={
                "ClientId": self._client_id,
                "AuthFlow": "USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "USERNAME": self.username,
                    "PASSWORD": self.password,
                },
            },
            is_login=True,
        )
        token_data = await response.json(content_type="json")

        if response.status != HTTPStatus.OK:
            error_type = token_data.get("__type", "")
            message = token_data.get("message", "")
            if error_type in ("NotAuthorizedException", "UserNotFoundException"):
                raise VeoliaAPIInvalidCredentialsError(message or error_type)
            raise VeoliaAPITokenError(f"{error_type} - {message}")

        if challenge := token_data.get("ChallengeName"):
            raise VeoliaChallengeError(challenge)

        result = token_data.get("AuthenticationResult") or {}
        access_token = result.get("AccessToken")
        if not access_token:
            raise VeoliaAPITokenError(
                f"No access token and no challenge (keys: {sorted(token_data)})",
            )

        self.account_data.access_token = access_token
        self.account_data.token_expiration = (
            datetime.now() + timedelta(seconds=result.get("ExpiresIn", 0))
        ).timestamp()
        LOGGER.debug("Access token retrieved through USER_PASSWORD_AUTH")


class VeoliaRefreshTokenAPI(SubscriptionWindowMixin, VeoliaAPI):
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
