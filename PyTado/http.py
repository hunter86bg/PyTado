# PyTado/http.py (Corrected Full Version - Added final debug log in device_activation)
"""
Do all the API HTTP heavy lifting in this file
"""

import enum
import json
import logging
import os
import pprint
import time
from datetime import datetime, timedelta, timezone
from json import dump as json_dump
from json import load as json_load
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import requests

# Make sure const and exceptions are correctly referenced from PyTado package
from PyTado.const import CLIENT_ID_DEVICE
from PyTado.exceptions import TadoException, TadoCredentialsException, TadoWrongCredentialsException
from PyTado.logger import Logger # Using the custom logger

_LOGGER = Logger(__name__) # Instantiate the custom logger


class Endpoint(enum.StrEnum):
    """Endpoint URL Enum"""
    MY_API = "https://my.tado.com/api/v2/"
    HOPS_API = "https://hops.tado.com/"
    MOBILE = "https://my.tado.com/mobile/1.9/"
    EIQ = "https://energy-insights.tado.com/api/"
    TARIFF = "https://tariff-experience.tado.com/api/"
    GENIE = "https://genie.tado.com/api/v2/"
    MINDER = "https://minder.tado.com/v1/"


class Domain(enum.StrEnum):
    """API Request Domain Enum"""
    HOME = "homes"
    DEVICES = "devices"
    ME = "me"
    HOME_BY_BRIDGE = "homeByBridge"


class Action(enum.StrEnum):
    """API Request Action Enum"""
    GET = "GET"
    SET = "POST"
    RESET = "DELETE"
    CHANGE = "PUT"


class Mode(enum.Enum):
    """API Response Format Enum"""
    OBJECT = 1
    PLAIN = 2


class DeviceActivationStatus(enum.StrEnum):
    """Device Activation Status Enum"""
    NOT_STARTED = "NOT_STARTED"
    PENDING = "PENDING"
    COMPLETED = "COMPLETED"


class TadoRequest:
    """Data Container for my.tado.com API Requests"""
    def __init__(
        self,
        endpoint: Endpoint = Endpoint.MY_API,
        command: str | None = None,
        action: Action | str = Action.GET,
        payload: dict[str, Any] | None = None,
        domain: Domain = Domain.HOME,
        device: int | str | None = None,
        mode: Mode = Mode.OBJECT,
        params: dict[str, Any] | None = None,
    ) -> None:
        self.endpoint = endpoint
        self.command = command
        self.action = action
        self.payload = payload
        self.domain = domain
        self.device = device
        self.mode = mode
        self.params = params


class TadoXRequest(TadoRequest):
    """Data Container for hops.tado.com (Tado X) API Requests"""
    def __init__(
        self,
        endpoint: Endpoint = Endpoint.HOPS_API,
        command: str | None = None,
        action: Action | str = Action.GET,
        payload: dict[str, Any] | None = None,
        domain: Domain = Domain.HOME,
        device: int | str | None = None,
        mode: Mode = Mode.OBJECT,
        params: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            endpoint=endpoint,
            command=command,
            action=action,
            payload=payload,
            domain=domain,
            device=device,
            mode=mode,
            params=params,
        )
        self._action = action

    @property
    def action(self) -> Action | str:
        """Get request action for Tado X"""
        if self._action == Action.CHANGE:
            return "PATCH"
        return self._action

    @action.setter
    def action(self, value: Action | str) -> None:
        """Set request action"""
        self._action = value


class TadoResponse:
    """Unimplemented Response Container"""
    pass


_DEFAULT_TIMEOUT = 10 # Timeout for requests in seconds
_DEFAULT_RETRIES = 3 # Number of retries for connection errors


class Http:
    """API Request Class"""

    def __init__(
        self,
        token_file_path: str | None = None,
        saved_refresh_token: str | None = None,
        http_session: requests.Session | None = None,
        debug: bool = False,
    ) -> None:
        """Initializes the HTTP client and handles authentication."""
        if debug:
            _LOGGER.setLevel(logging.DEBUG)
        else:
            _LOGGER.setLevel(logging.INFO)

        self._refresh_at = datetime.now(timezone.utc) + timedelta(days=1)
        self._session = http_session or self._create_session()
        self._headers = {"Referer": "https://app.tado.com/"}

        self._user_code: str | None = None
        self._device_verification_url: str | None = None
        self._device_activation_status = DeviceActivationStatus.NOT_STARTED
        self._expires_at: datetime | None = None
        self._device_flow_data: dict[str, Any] = {}

        self._id: int | None = None
        self._token_refresh: str | None = None
        self._x_api: bool | None = None
        self._token_file_path = token_file_path

        loaded_token = self._load_token(); effective_refresh_token = saved_refresh_token or self._token_refresh
        if effective_refresh_token:
            _LOGGER.info("Found saved refresh token, attempting initial refresh...")
            try:
                if self._refresh_token(refresh_token=effective_refresh_token, force_refresh=True):
                    _LOGGER.info("Initial token refresh successful."); self._device_ready()
                else:
                    _LOGGER.warning("Initial token refresh failed."); self._token_refresh = None; self._clear_saved_token()
                    _LOGGER.info("Proceeding with device flow."); self._device_activation_status = self._login_device_flow()
            except (TadoException, TadoCredentialsException) as e:
                _LOGGER.warning(f"Error during initial refresh: {e}. Proceeding with device flow.")
                self._token_refresh = None; self._clear_saved_token(); self._device_activation_status = self._login_device_flow()
        else:
            _LOGGER.info("No saved token. Starting device flow."); self._device_activation_status = self._login_device_flow()

    @property
    def is_x_line(self) -> bool | None: return self._x_api
    @property
    def user_code(self) -> str | None: return self._user_code
    @property
    def device_activation_status(self) -> DeviceActivationStatus: return self._device_activation_status
    @property
    def device_verification_url(self) -> str | None: return self._device_verification_url
    @property
    def refresh_token(self) -> str | None: return self._token_refresh

    def _create_session(self) -> requests.Session: return requests.Session()

    def _log_response(self, response: requests.Response, *args, **kwargs) -> None:
        og_req = response.request; status = response.status_code
        try: data = response.json()
        except: data = response.text
        _LOGGER.debug(f"\n--- Req: {og_req.method} {og_req.url}\nHeaders: {pprint.pformat(og_req.headers)}\n--- Res: {status}\nData: {pprint.pformat(data)}\n---")

    def _configure_url(self, req: TadoRequest) -> str:
        base = req.endpoint; parts = [str(req.domain)]
        if req.domain == Domain.ME: parts = [str(Domain.ME)]
        elif req.domain in [Domain.DEVICES, Domain.HOME_BY_BRIDGE]:
            if req.device is None: raise ValueError(f"Device ID needed for {req.domain}")
            parts.append(str(req.device));
            if req.command: parts.append(req.command)
        else:
            if self._id is None:
                 if self.device_activation_status == DeviceActivationStatus.COMPLETED:
                     try: self._id = self._get_id()
                     except Exception as e: raise TadoException(f"Home ID missing: {e}")
                 else: raise TadoException("Home ID missing (auth not complete).")
            parts.append(str(self._id));
            if req.command: parts.append(req.command)
        url = f"{base}{'/'.join(parts)}"
        if req.params: url += f"?{urlencode(req.params)}"
        return url

    def _configure_payload(self, headers: dict[str, str], req: TadoRequest) -> bytes | None:
        if req.payload is None: headers.pop("Content-Type", None); headers.pop("Mime-Type", None); return None
        headers["Content-Type"] = "application/json;charset=UTF-8"; return json.dumps(req.payload).encode("utf8")

    def _set_oauth_header(self, data: dict[str, Any]) -> str:
        try:
            access=data["access_token"]; expires=float(data["expires_in"]); refresh=data.get("refresh_token", self._token_refresh)
            if not refresh: _LOGGER.warning("OAuth response missing refresh_token!")
            self._token_refresh = refresh; now = datetime.now(timezone.utc); self._refresh_at = now + timedelta(seconds=expires) - timedelta(seconds=60)
            _LOGGER.debug(f"Token expires {now + timedelta(seconds=expires)}, refresh after {self._refresh_at}")
            auth = f"Bearer {access}"; self._headers["Authorization"] = auth; self._session.headers.update({'Authorization': auth})
            self._save_token(); return refresh or ""
        except KeyError as e: raise TadoException(f"OAuth response missing key: {e}")
        except (ValueError, TypeError) as e: raise TadoException(f"OAuth response invalid expires_in: {e}")

    def _load_token(self) -> bool:
        if not self._token_file_path or not os.path.exists(self._token_file_path): return False
        try:
            with open(self._token_file_path,"r", encoding="utf-8") as f: data=json_load(f)
            token = data.get("refresh_token")
            if token: self._token_refresh = token; _LOGGER.debug("Token loaded."); return True
            _LOGGER.warning(f"Token file empty: {self._token_file_path}"); return False
        except Exception as e: _LOGGER.error(f"Failed load token: {e}"); return False

    def _save_token(self):
        if not self._token_file_path or not self._token_refresh: return
        try:
            Path(os.path.dirname(self._token_file_path)).mkdir(parents=True, exist_ok=True)
            with open(self._token_file_path, "w", encoding="utf-8") as f: json_dump({"refresh_token": self._token_refresh}, f, indent=4)
            _LOGGER.debug("Token saved.")
        except Exception as e: _LOGGER.error(f"Failed save token: {e}", exc_info=True)

    def _clear_saved_token(self):
         if self._token_file_path and os.path.exists(self._token_file_path):
             try: os.remove(self._token_file_path); _LOGGER.info(f"Removed token file: {self._token_file_path}")
             except OSError as e: _LOGGER.warning(f"Could not remove token file: {e}")

    def _login_device_flow(self) -> DeviceActivationStatus:
        if self._device_activation_status != DeviceActivationStatus.NOT_STARTED:
             _LOGGER.warning(f"Device flow requested, status {self._device_activation_status}. Resetting."); self._device_activation_status = DeviceActivationStatus.NOT_STARTED
        _LOGGER.info("Initiating Tado Device Authentication Flow...")
        url = "https://login.tado.com/oauth2/device_authorize"; data = {"client_id": CLIENT_ID_DEVICE, "scope": "home.user offline_access"}
        try:
            resp = self._session.post(url, data=data, timeout=_DEFAULT_TIMEOUT, headers=self._headers); resp.raise_for_status()
            self._device_flow_data = resp.json(); _LOGGER.debug("Device flow response: %s", self._device_flow_data)
            self._user_code = self._device_flow_data["user_code"]; self._device_verification_url = self._device_flow_data.get("verification_uri_complete", self._device_flow_data["verification_uri"])
            self._expires_at = datetime.now(timezone.utc) + timedelta(seconds=int(self._device_flow_data["expires_in"]))
            _LOGGER.warning(f"!!! USER ACTION: Go to {self._device_verification_url} (Code: {self._user_code}) (~{int(self._device_flow_data['expires_in']) // 60} min)")
            return DeviceActivationStatus.PENDING
        except requests.exceptions.RequestException as e: raise TadoException(f"Conn error init device auth: {e}") from e
        except Exception as e: raise TadoException(f"Invalid device auth response: {e}") from e

    def _check_device_activation(self) -> bool:
        if self._expires_at is not None and datetime.now(timezone.utc) > self._expires_at: raise TadoCredentialsException("Device code expired.")
        interval = self._device_flow_data.get("interval", 5); _LOGGER.debug(f"Polling token endpoint after {interval}s."); time.sleep(interval)
        try:
            resp = self._session.post(url="https://login.tado.com/oauth2/token", data={"client_id": CLIENT_ID_DEVICE, "device_code": self._device_flow_data["device_code"], "grant_type": "urn:ietf:params:oauth:grant-type:device_code", "scope": "home.user offline_access"}, timeout=_DEFAULT_TIMEOUT, headers=self._headers)
            if resp.status_code == 200:
                data = resp.json()
                if 'access_token' in data: _LOGGER.info("Auth successful!"); self._set_oauth_header(data); return True
                else: raise TadoException(f"Login failed: Invalid 200 OK token response.")
            resp.raise_for_status(); raise TadoException(f"Unexpected status {resp.status_code} polling.")
        except requests.exceptions.HTTPError as e:
            if e.response is not None:
                status = e.response.status_code
                try: err_data = e.response.json(); err_code = err_data.get("error"); err_desc = err_data.get("error_description", e.response.reason)
                except: raise TadoException(f"Login failed. Status {status}, Non-JSON error: {e.response.text}")
                if status == 400:
                    if err_code == 'authorization_pending': _LOGGER.info("Auth pending..."); return False
                    elif err_code == 'slow_down': _LOGGER.warning("Polling too fast, increasing interval."); self._device_flow_data["interval"]=interval + 5; return False
                    elif err_code == 'access_denied': raise TadoCredentialsException(f"Auth denied: {err_desc}")
                    elif err_code == 'expired_token': raise TadoCredentialsException(f"Device code expired: {err_desc}")
                    else: raise TadoException(f"Login failed ({err_code}): {err_desc}")
                else: raise TadoException(f"Login failed. Status {status}, Reason: {e.response.reason}")
            else: raise TadoException(f"Login HTTP error: {e}")
        except requests.exceptions.RequestException as e: raise TadoException(f"Conn error polling: {e}") from e
        except Exception as e: raise TadoException(f"Error processing token data: {e}") from e

    def _refresh_token(self, refresh_token: str | None = None, force_refresh: bool = False) -> bool:
        if not force_refresh and self._refresh_at > datetime.now(timezone.utc): return True
        token = refresh_token or self._token_refresh
        if not token: _LOGGER.error("No refresh token."); self._device_activation_status = DeviceActivationStatus.NOT_STARTED; return False
        _LOGGER.info("Refreshing token..."); url = "https://login.tado.com/oauth2/token"; data = {"client_id": CLIENT_ID_DEVICE, "grant_type": "refresh_token", "scope": "home.user offline_access", "refresh_token": token}
        try:
            resp = self._session.post(url, data=data, timeout=_DEFAULT_TIMEOUT, headers=self._headers); resp.raise_for_status()
            self._set_oauth_header(resp.json()); _LOGGER.info("Token refreshed."); return True
        except requests.exceptions.HTTPError as e:
            status = e.response.status_code if e.response else None
            _LOGGER.error(f"Refresh token failed. Status: {status}. Resp: {e.response.text if e.response else 'N/A'}")
            if status in [400, 401]: self._device_activation_status=DeviceActivationStatus.NOT_STARTED; self._token_refresh=None; self._headers.pop("Authorization", None); self._clear_saved_token(); raise TadoCredentialsException(f"Refresh token failed (status {status}), token invalid.") from e
            else: raise TadoException(f"HTTP error refreshing token: {e}") from e
        except requests.exceptions.RequestException as e: raise TadoException(f"Conn error refreshing token: {e}") from e
        except Exception as e: raise TadoException(f"Invalid token refresh response: {e}") from e

    # --- CORRECTED device_activation method structure ---
    def device_activation(self) -> bool:
        """Handles the polling loop for device activation. Returns True/False."""
        if self._device_activation_status != DeviceActivationStatus.PENDING:
            _LOGGER.error(f"Device activation called but status is {self._device_activation_status} (expected PENDING).")
            return False

        _LOGGER.info("Starting polling for device authorization...")
        activation_succeeded = False # Flag to track success
        try:
            while True: # Loop indefinitely until success or error
                if self._expires_at is not None and datetime.now(timezone.utc) > self._expires_at:
                    raise TadoCredentialsException("Device authorization code expired.")

                check_result = self._check_device_activation() # Polls and handles internal logic

                if check_result is True: # Explicit check for True from _check_device_activation
                    _LOGGER.info("Device activation successful (polling check returned True).")
                    activation_succeeded = True # Set success flag
                    break # Exit the while loop successfully

        except (TadoCredentialsException, TadoException) as e:
             _LOGGER.error(f"Device activation failed: {e}")
             self._device_activation_status = DeviceActivationStatus.NOT_STARTED
             if isinstance(e, TadoCredentialsException):
                  self._user_code = None; self._device_verification_url = None
             # activation_succeeded remains False
        except Exception as e:
             _LOGGER.exception(f"An unexpected error occurred during device activation loop: {e}")
             self._device_activation_status = DeviceActivationStatus.NOT_STARTED
             # activation_succeeded remains False

        # --- After loop finishes ---
        if activation_succeeded: # Only call _device_ready if polling was successful
            try:
                self._device_ready() # Finalize setup
            except Exception as ready_e:
                 _LOGGER.error(f"Error during _device_ready after successful polling: {ready_e}")
                 activation_succeeded = False # Mark overall activation as failed if ready step fails

        # --- ADDED DEBUG LOG ---
        _LOGGER.debug(f"device_activation end: Returning {activation_succeeded}")
        # --- ----------------- ---
        return activation_succeeded # Return the final success status
    # --- End of corrected device_activation method ---

    def _device_ready(self):
        """Called after successful authentication to get initial data."""
        _LOGGER.debug("Device authenticated, finalizing setup...")
        try:
             self._id = self._get_id(); self._x_api = self._check_x_line_generation()
             _LOGGER.info(f"Home ID: {self._id}, Is Tado X: {self._x_api}")
        except Exception as e:
             _LOGGER.error(f"Failed post-auth setup: {e}"); self._device_activation_status = DeviceActivationStatus.NOT_STARTED
             raise TadoException("Auth succeeded but failed initial home data retrieval.") from e
        self._user_code = None; self._device_verification_url = None; self._expires_at = None; self._device_flow_data = {}
        self._device_activation_status = DeviceActivationStatus.COMPLETED; _LOGGER.info("Device setup complete.")

    def _get_id(self) -> int:
        """Gets the user's primary home ID."""
        _LOGGER.debug("Getting home ID..."); headers=self._headers.copy(); url=f"{Endpoint.MY_API}{Domain.ME}"
        try:
            resp=self._session.get(url, headers=headers, timeout=_DEFAULT_TIMEOUT); resp.raise_for_status(); data=resp.json()
            if not data.get("homes"): raise TadoException("'/me' response missing 'homes'.")
            home_id = data["homes"][0].get("id");
            if not home_id: raise TadoException("Home ID missing in '/me'.")
            _LOGGER.debug(f"Found home ID: {home_id}"); return int(home_id)
        except Exception as e: raise TadoException(f"Failed get home ID: {e}") from e

    def _check_x_line_generation(self):
        """Checks if the home is Tado X generation."""
        _LOGGER.debug("Checking generation...");
        if self._id is None: raise TadoException("Home ID not set for generation check.")
        headers=self._headers.copy(); url=f"{Endpoint.MY_API}{Domain.HOME}/{self._id}"
        try:
            resp=self._session.get(url, headers=headers, timeout=_DEFAULT_TIMEOUT); resp.raise_for_status(); data=resp.json()
            is_x = data.get("generation") == "LINE_X"; _LOGGER.debug(f"Is X Line = {is_x}"); return is_x
        except Exception as e: raise TadoException(f"Failed check generation: {e}") from e

    def request(self, req: TadoRequest) -> dict[str, Any]:
        """Makes an authenticated API request."""
        if self.device_activation_status != DeviceActivationStatus.COMPLETED: raise TadoException("Auth not completed.")
        try:
            if not self._refresh_token(force_refresh=False): raise TadoCredentialsException("Token refresh failed.")
        except Exception as e: raise
        headers=self._headers.copy(); data=self._configure_payload(headers, req); url=self._configure_url(req)
        prepped=self._session.prepare_request(requests.Request(method=req.action, url=url, headers=headers, data=data)); prepped.hooks={'response': [self._log_response]}
        retries=_DEFAULT_RETRIES
        while retries >= 0:
            try:
                resp = self._session.send(prepped, timeout=_DEFAULT_TIMEOUT); resp.raise_for_status()
                if resp.status_code == 204 or not resp.content: return {}
                try: return resp.json()
                except json.JSONDecodeError as e: raise TadoException(f"Invalid JSON response from {url}: {e}") from e
            except requests.exceptions.HTTPError as e:
                 if e.response is not None and e.response.status_code == 401: self._device_activation_status=DeviceActivationStatus.NOT_STARTED; self._token_refresh=None; self._clear_saved_token(); raise TadoCredentialsException("Unauthorized (401).") from e
                 _LOGGER.error(f"HTTP error calling {url}: {e.response.status_code if e.response else 'N/A'}"); raise TadoException(f"API call HTTP error") from e
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                if retries > 0: _LOGGER.warning(f"{e.__class__.__name__} calling {url}. Retrying ({retries})..."); time.sleep(1); retries -= 1
                else: raise TadoException(f"API call failed retries: {e}") from e
            except requests.exceptions.RequestException as e: raise TadoException(f"API call failed: {e}") from e
        raise TadoException("API request failed retries.")
