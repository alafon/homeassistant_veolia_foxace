"""Config flow for veolia integration."""

from urllib.parse import urlparse

import aiohttp
from veolia_api.exceptions import (
    VeoliaAPIInvalidCredentialsError,
    VeoliaAPITokenError,
)
from veolia_api.portals import VEOLIA_PORTAL_CLIENTS
import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import (
    VeoliaChallengeError,
    VeoliaCredentialsAPI,
    VeoliaRefreshTokenAPI,
)
from .const import (
    COMMUNE_LOOKUP_URL,
    CONF_PORTAL_URL,
    CONF_REFRESH_TOKEN,
    DOMAIN,
    LOGGER,
)


class VeoliaFlowHandler(config_entries.ConfigFlow, domain=DOMAIN):
    """Config flow for veolia."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialize."""
        self._errors = {}
        self._postal_code = None
        self._communes = []
        self._portal_url: str | None = None

    async def async_step_user(self, user_input=None) -> dict:
        """Handle a flow initialized by the user."""
        self._errors = {}

        if user_input is not None:
            self._postal_code = user_input["postal_code"]
            return await self.async_step_select_commune()

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema({vol.Required("postal_code"): str}),
            errors=self._errors,
        )

    async def async_step_select_commune(self, user_input=None) -> dict:
        """Handle the selection of a commune."""
        LOGGER.debug("Check city postal to for integration compatibility")
        if user_input is not None:
            selected_commune = next(
                (
                    commune
                    for commune in self._communes
                    if commune["libelle"] == user_input["commune"]
                ),
                None,
            )
            if (
                selected_commune
                and selected_commune.get("type_commune") == "NON_REDIRIGE"
            ):
                self._portal_url = None
                return await self.async_step_auth_method()

            if selected_commune and selected_commune.get("type_commune") == "REDIRIGE":
                url_redirection = selected_commune.get("url_redirection", "")
                hostname = urlparse(url_redirection).hostname or ""
                if hostname in VEOLIA_PORTAL_CLIENTS:
                    self._portal_url = hostname
                    return await self.async_step_auth_method()
                self._errors["base"] = "commune_not_supported"
            elif (
                selected_commune
                and selected_commune.get("type_commune") == "NON_DESSERVIE"
            ):
                self._errors["base"] = "commune_not_veolia"
            else:
                self._errors["base"] = "commune_not_supported"

        LOGGER.debug("Fetching communes for postal code %s", self._postal_code)
        session = async_get_clientsession(self.hass)
        try:
            response = await session.get(f"{COMMUNE_LOOKUP_URL}{self._postal_code}")
            response.raise_for_status()
            self._communes = await response.json()
        except aiohttp.ClientError:
            LOGGER.exception("Failed to fetch communes")
            self._errors["base"] = "unknown"
            self._communes = []
        else:
            LOGGER.debug("Communes found: %s", self._communes)

        if not self._communes:
            self._errors["base"] = self._errors.get("base") or "no_communes_found"

        commune_options = {
            commune["libelle"]: commune["libelle"] for commune in self._communes
        }

        return self.async_show_form(
            step_id="select_commune",
            data_schema=vol.Schema({vol.Required("commune"): vol.In(commune_options)}),
            errors=self._errors,
        )

    async def async_step_auth_method(self, user_input=None) -> dict:
        """Let the user pick how to authenticate against the portal."""
        return self.async_show_menu(
            step_id="auth_method",
            menu_options=["credentials", "refresh_token"],
        )

    async def async_step_refresh_token(self, user_input=None) -> dict:
        """Authenticate with a Cognito refresh token.

        Portals behind adaptive authentication answer a password sign-in with
        an SMS challenge; on migrated accounts the pool holds an unverified
        placeholder number, so that code never arrives. A refresh token
        obtained from a trusted context sidesteps the challenge entirely.
        """
        self._errors = {}

        if user_input is not None:
            api = VeoliaRefreshTokenAPI(
                user_input[CONF_REFRESH_TOKEN],
                async_get_clientsession(self.hass),
                portal_url=self._portal_url,
            )
            if await self._async_validate(api, "invalid_refresh_token"):
                return self.async_create_entry(
                    title=self._entry_title(api),
                    data={
                        CONF_REFRESH_TOKEN: user_input[CONF_REFRESH_TOKEN],
                        CONF_PORTAL_URL: self._portal_url,
                    },
                )

        return self.async_show_form(
            step_id="refresh_token",
            data_schema=vol.Schema({vol.Required(CONF_REFRESH_TOKEN): str}),
            errors=self._errors,
        )

    async def async_step_reauth(self, entry_data) -> dict:
        """Start reauthentication, after a rejected token or a challenge."""
        self._portal_url = entry_data.get(CONF_PORTAL_URL)
        return await self.async_step_reauth_method()

    async def async_step_reconfigure(self, user_input=None) -> dict:
        """Let the user switch authentication method whenever they want."""
        self._portal_url = self._get_reconfigure_entry().data.get(CONF_PORTAL_URL)
        return await self.async_step_reauth_method()

    async def async_step_reauth_method(self, user_input=None) -> dict:
        """Offer both authentication methods on an existing entry."""
        return self.async_show_menu(
            step_id="reauth_method",
            menu_options=["reauth_credentials", "reauth_token"],
        )

    async def async_step_reauth_credentials(self, user_input=None) -> dict:
        """Switch the entry to a username and password."""
        self._errors = {}

        if user_input is not None:
            api = VeoliaCredentialsAPI(
                username=user_input[CONF_USERNAME],
                password=user_input[CONF_PASSWORD],
                session=async_get_clientsession(self.hass),
                portal_url=self._portal_url,
            )
            if await self._async_validate(api, "invalid_credentials"):
                return self._async_replace_entry_data(
                    {
                        CONF_USERNAME: user_input[CONF_USERNAME],
                        CONF_PASSWORD: user_input[CONF_PASSWORD],
                        CONF_PORTAL_URL: self._portal_url,
                    },
                )

        return self.async_show_form(
            step_id="reauth_credentials",
            data_schema=vol.Schema(
                {vol.Required(CONF_USERNAME): str, vol.Required(CONF_PASSWORD): str},
            ),
            errors=self._errors,
        )

    async def async_step_reauth_token(self, user_input=None) -> dict:
        """Switch the entry to a refresh token."""
        self._errors = {}

        if user_input is not None:
            api = VeoliaRefreshTokenAPI(
                user_input[CONF_REFRESH_TOKEN],
                async_get_clientsession(self.hass),
                portal_url=self._portal_url,
            )
            if await self._async_validate(api, "invalid_refresh_token"):
                return self._async_replace_entry_data(
                    {
                        CONF_REFRESH_TOKEN: user_input[CONF_REFRESH_TOKEN],
                        CONF_PORTAL_URL: self._portal_url,
                    },
                )

        return self.async_show_form(
            step_id="reauth_token",
            data_schema=vol.Schema({vol.Required(CONF_REFRESH_TOKEN): str}),
            errors=self._errors,
        )

    def _async_replace_entry_data(self, data: dict) -> dict:
        """Replace the entry data wholesale, then reload.

        Merging would leave the previous method's secrets behind -- a stale
        password beside a fresh token, or the reverse -- and the coordinator
        prefers a refresh token whenever the entry carries one. Switching
        method therefore has to drop what it replaces.
        """
        entry = (
            self._get_reconfigure_entry()
            if self.source == config_entries.SOURCE_RECONFIGURE
            else self._get_reauth_entry()
        )
        return self.async_update_reload_and_abort(entry, data=data)

    async def _async_validate(self, api, token_error: str) -> bool:
        """Try to log in, recording why it failed in self._errors."""
        try:
            if await api.login():
                return True
            self._errors["base"] = "unknown"
        except VeoliaChallengeError as err:
            LOGGER.error(
                "Veolia demanded the %s challenge (portal=%s)",
                err.challenge_name,
                self._portal_url or "eau.veolia.fr",
            )
            self._errors["base"] = "mfa_challenge"
        except VeoliaAPIInvalidCredentialsError:
            self._errors["base"] = "invalid_credentials"
        except VeoliaAPITokenError:
            LOGGER.exception("Veolia rejected the credentials or the token")
            self._errors["base"] = token_error
        except Exception:  # noqa: BLE001
            LOGGER.exception(
                "Unexpected error while authenticating to Veolia (portal=%s)",
                self._portal_url or "eau.veolia.fr",
            )
            self._errors["base"] = "unknown"
        return False

    @staticmethod
    def _entry_title(api) -> str:
        """Name the entry after the meter, no username being available."""
        meter = api.account_data.numero_compteur
        return f"Veolia {meter}" if meter else "Veolia"

    async def async_step_credentials(self, user_input=None) -> dict:
        """Handle the initial input of credentials."""
        self._errors = {}

        if user_input is not None:
            api = VeoliaCredentialsAPI(
                username=user_input[CONF_USERNAME],
                password=user_input[CONF_PASSWORD],
                session=async_get_clientsession(self.hass),
                portal_url=self._portal_url,
            )
            if await self._async_validate(api, "invalid_credentials"):
                return self.async_create_entry(
                    title=user_input[CONF_USERNAME],
                    data={**user_input, CONF_PORTAL_URL: self._portal_url},
                )

        return self.async_show_form(
            step_id="credentials",
            data_schema=vol.Schema(
                {vol.Required(CONF_USERNAME): str, vol.Required(CONF_PASSWORD): str},
            ),
            errors=self._errors,
        )
