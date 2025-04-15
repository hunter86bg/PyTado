# PyTado/http.py (Corrected Full Version - Strictly Following Tado Docs for Refresh)
"""
Do all the API HTTP heavy lifting in this file
"""

import enum
import json
import logging
import os
import pprint
import time
import base64 # Keep import just in case needed later, but not used now
from datetime import datetime, timedelta, timezone
from json import dump as json_dump
from json import load as json_load
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import requests

from PyTado.const import CLIENT_ID_DEVICE
from PyTado.exceptions import TadoException, TadoCredentialsException, TadoWrongCredentialsException
from PyTado.logger import Logger

_LOGGER = Logger(__name__)

# --- Enums and Data Classes remain the same ---
class Endpoint(enum.StrEnum):
    MY_API = "https://my.tado.com/api/v2/"
    HOPS_API = "https://hops.tado.com/"
    MOBILE = "https://my.tado.com/mobile/1.9/"
    EIQ = "https://energy-insights.tado.com/api/"
    TARIFF = "https://tariff-experience.tado.com/api/"
    GENIE = "https://genie.tado.com/api/v2/"
    MINDER = "https://minder.tado.com/v1/"

class Domain(enum.StrEnum):
    HOME = "homes"; DEVICES = "devices"; ME = "me"; HOME_BY_BRIDGE = "homeByBridge"

class Action(enum.StrEnum):
    GET = "GET"; SET = "POST"; RESET = "DELETE"; CHANGE = "PUT"

class Mode(enum.Enum):
    OBJECT = 1; PLAIN = 2

class DeviceActivationStatus(enum.StrEnum):
    NOT_STARTED="NOT_STARTED"; PENDING="PENDING"; COMPLETED="COMPLETED"

class TadoRequest:
    def __init__(self, endpoint: Endpoint = Endpoint.MY_API, command: str | None = None, action: Action | str = Action.GET, payload: dict[str, Any] | None = None, domain: Domain = Domain.HOME, device: int | str | None = None, mode: Mode = Mode.OBJECT, params: dict[str, Any] | None = None) -> None:
        self.endpoint=endpoint; self.command=command; self.action=action; self.payload=payload; self.domain=domain; self.device=device; self.mode=mode; self.params=params

class TadoXRequest(TadoRequest):
    def __init__(self, endpoint: Endpoint = Endpoint.HOPS_API, command: str | None = None, action: Action | str = Action.GET, payload: dict[str, Any] | None = None, domain: Domain = Domain.HOME, device: int | str | None = None, mode: Mode = Mode.OBJECT, params: dict[str, Any] | None = None) -> None:
        super().__init__(endpoint=endpoint, command=command, action=action, payload=payload, domain=domain, device=device, mode=mode, params=params); self._action = action
    @property
    def action(self) -> Action | str: return "PATCH" if self._action == Action.CHANGE else self._action
    @action.setter
    def action(self, value: Action | str) -> None: self._action = value

class TadoResponse: pass

_DEFAULT_TIMEOUT = 10; _DEFAULT_RETRIES = 3

class Http:
    # --- __init__ and Properties remain the same ---
    def __init__(self, token_file_path: str | None = None, saved_refresh_token: str | None = None, http_session: requests.Session | None = None, debug: bool = False) -> None:
        if debug: _LOGGER.setLevel(logging.DEBUG)
        else: _LOGGER.setLevel(logging.INFO)
        self._refresh_at = datetime.now(timezone.utc) + timedelta(days=1); self._session = http_session or self._create_session(); self._headers = {"Referer": "https://app.tado.com/"}
        self._user_code: str|None = None; self._device_verification_url: str|None = None; self._device_activation_status = DeviceActivationStatus.NOT_STARTED
        self._expires_at: datetime|None = None; self._device_flow_data: dict[str, Any] = {}
        self._id: int|None = None; self._token_refresh: str|None = None; self._x_api: bool|None = None; self._token_file_path = token_file_path
        loaded_token = self._load_token(); effective_refresh_token = saved_refresh_token or self._token_refresh
        if effective_refresh_token:
            _LOGGER.info("Token found, trying initial refresh...");
            try:
                if self._refresh_token(refresh_token=effective_refresh_token, force_refresh=True): _LOGGER.info("Initial refresh OK."); self._device_ready()
                else: _LOGGER.warning("Initial refresh failed."); self._token_refresh = None; self._clear_saved_token(); _LOGGER.info("Starting device flow."); self._device_activation_status = self._login_device_flow()
            except (TadoException, TadoCredentialsException) as e: _LOGGER.warning(f"Initial refresh error: {e}. Starting device flow."); self._token_refresh = None; self._clear_saved_token(); self._device_activation_status = self._login_device_flow()
        else: _LOGGER.info("No saved token. Starting device flow."); self._device_activation_status = self._login_device_flow()
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

    # --- Internal Helpers (_create_session, _log_response, _configure_url, _configure_payload, _set_oauth_header, _load_token, _save_token, _clear_saved_token) remain the same ---
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


    # --- Auth Flow Methods (_login_device_flow, _check_device_activation) remain the same ---
    # Note: Tado docs show params= for these too, but data= works. Keep data= for now unless polling fails.
    def _login_device_flow(self) -> DeviceActivationStatus:
        if self._device_activation_status != DeviceActivationStatus.NOT_STARTED:
             _LOGGER.warning(f"Device flow requested, status {self._device_activation_status}. Resetting."); self._device_activation_status = DeviceActivationStatus.NOT_STARTED
        _LOGGER.info("Initiating Tado Device Authentication Flow...")
        url = "https://login.tado.com/oauth2/device_authorize"; 
        # Send as data= (body) which is known to work based on logs
        data = {"client_id": CLIENT_ID_DEVICE, "scope": "home.user offline_access"} 
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
            # Send as data= (body) which is known to work based on logs
            resp = self._session.post(
                url="https://login.tado.com/oauth2/token", 
                data={"client_id": CLIENT_ID_DEVICE, "device_code": self._device_flow_data["device_code"], "grant_type": "urn:ietf:params:oauth:grant-type:device_code", "scope": "home.user offline_access"}, 
                timeout=_DEFAULT_TIMEOUT, 
                headers=self._headers # Send default headers (likely no Bearer token yet)
            )
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

    # --- !!! CORRECTED _refresh_token method !!! ---
    def _refresh_token(self, refresh_token: str | None = None, force_refresh: bool = False) -> bool:
        """Refreshes the OAuth token using URL params per Tado docs."""
        if not force_refresh and self._refresh_at > datetime.now(timezone.utc):
            _LOGGER.debug("Token still valid, refresh not needed.")
            return True

        token_to_use = refresh_token or self._token_refresh
        if not token_to_use:
            _LOGGER.error("Cannot refresh token: No refresh token available.")
            self._device_activation_status = DeviceActivationStatus.NOT_STARTED
            return False

        _LOGGER.info("Attempting to refresh OAuth token (using URL params per docs)...")
        url = "https://login.tado.com/oauth2/token" 
        
        # --- Modification: Send as params, remove scope ---
        refresh_params = { 
            "client_id": CLIENT_ID_DEVICE,
            "grant_type": "refresh_token",
            # "scope": "home.user offline_access", # Scope NOT included per docs example
            "refresh_token": token_to_use,
        }
        
        # Use headers without Authorization for this specific call
        refresh_headers = {
             'Referer': self._headers.get('Referer', 'https://app.tado.com/')
        }
        _LOGGER.debug(f"Sending refresh request with params: {refresh_params}")
        # --- End Modification ---

        try:
            # Send POST request with data in URL parameters (params=)
            response = self._session.post(
                 url, 
                 params=refresh_params, # Use params= instead of data=
                 headers=refresh_headers, # Use headers without Auth
                 timeout=_DEFAULT_TIMEOUT
            )

            # Check response status explicitly
            if response.status_code != 200:
                 status_code = response.status_code
                 response_text = response.text 
                 _LOGGER.error(f"Refresh token failed. Status: {status_code}. Response: {response_text}")
                 if status_code in [400, 401]:
                     try: 
                         error_data = response.json()
                         error_code = error_data.get("error", "Unknown")
                         error_desc = error_data.get("error_description", "No Description")
                         # Check for invalid_grant now, as reported by other user
                         if error_code == "invalid_grant":
                              _LOGGER.critical(f"Refresh failed: invalid_grant. Tado rejected the refresh token. Desc: {error_desc}")
                         elif error_code == "invalid_client":
                              _LOGGER.critical(f"Refresh failed: invalid_client (unexpected with params). Desc: {error_desc}")
                         raise TadoCredentialsException(f"Refresh token failed ({error_code}): {error_desc}. Status {status_code}.")
                     except json.JSONDecodeError: 
                         raise TadoCredentialsException(f"Refresh token failed (status {status_code}), token invalid. Response: {response_text}")
                     finally: 
                          self._device_activation_status = DeviceActivationStatus.NOT_STARTED
                          self._token_refresh = None; self._headers.pop("Authorization", None); self._session.headers.pop("Authorization", None)
                          self._clear_saved_token()
                 else:
                     raise TadoException(f"HTTP error {status_code} refreshing token. Response: {response_text}")

            # Process successful response (Status Code is 200)
            response_data = response.json()
            self._set_oauth_header(response_data) # Updates self._headers and self._session.headers
            _LOGGER.info("OAuth token refreshed successfully.")
            return True
        
        except requests.exceptions.RequestException as e: _LOGGER.error(f"Connection error refreshing token: {e}"); raise TadoException(f"Connection error refreshing token: {e}") from e
        except (KeyError, ValueError, TypeError, json.JSONDecodeError) as e: _LOGGER.error(f"Error processing token refresh response: {e}"); raise TadoException(f"Invalid token refresh response: {e}") from e
        except TadoCredentialsException: raise 
        except TadoException: raise 
        except Exception as e: _LOGGER.exception(f"Unexpected error during token refresh: {e}"); raise TadoException(f"Unexpected error refreshing token: {e}") from e
    # --- End of corrected _refresh_token method ---

    # --- device_activation and subsequent methods remain the same ---
    def device_activation(self) -> bool:
        if self._device_activation_status != DeviceActivationStatus.PENDING: _LOGGER.error(f"Device activation called status {self._device_activation_status} != PENDING."); return False
        _LOGGER.info("Starting polling for device authorization..."); activation_succeeded = False
        try:
            while True:
                if self._expires_at is not None and datetime.now(timezone.utc) > self._expires_at: raise TadoCredentialsException("Device code expired.")
                check_result = self._check_device_activation()
                if check_result is True: _LOGGER.info("Device activation successful (polling check OK)."); activation_succeeded = True; break
        except (TadoCredentialsException, TadoException) as e:
             _LOGGER.error(f"Device activation failed: {e}"); self._device_activation_status = DeviceActivationStatus.NOT_STARTED
             if isinstance(e, TadoCredentialsException): self._user_code = None; self._device_verification_url = None
        except Exception as e: _LOGGER.exception(f"Unexpected error in activation loop: {e}"); self._device_activation_status = DeviceActivationStatus.NOT_STARTED
        if activation_succeeded:
            try: self._device_ready()
            except Exception as ready_e: _LOGGER.error(f"Error in _device_ready: {ready_e}"); activation_succeeded = False
        _LOGGER.debug(f"device_activation end: Returning {activation_succeeded}"); return activation_succeeded

    def _device_ready(self):
        _LOGGER.debug("Device authenticated, finalizing setup...")
        try:
             self._id = self._get_id(); self._x_api = self._check_x_line_generation()
             _LOGGER.info(f"Home ID: {self._id}, Is Tado X: {self._x_api}")
        except Exception as e: _LOGGER.error(f"Failed post-auth setup: {e}"); self._device_activation_status = DeviceActivationStatus.NOT_STARTED; raise TadoException("Auth OK but failed initial data retrieval.") from e
        self._user_code = None; self._device_verification_url = None; self._expires_at = None; self._device_flow_data = {}
        self._device_activation_status = DeviceActivationStatus.COMPLETED; _LOGGER.info("Device setup complete.")

    def _get_id(self) -> int:
        _LOGGER.debug("Getting home ID..."); headers=self._headers.copy(); url=f"{Endpoint.MY_API}{Domain.ME}"
        try:
            resp=self._session.get(url, headers=headers, timeout=_DEFAULT_TIMEOUT); resp.raise_for_status(); data=resp.json()
            if not data.get("homes"): raise TadoException("'/me' response missing 'homes'.")
            home_id = data["homes"][0].get("id");
            if not home_id: raise TadoException("Home ID missing in '/me'.")
            _LOGGER.debug(f"Found home ID: {home_id}"); return int(home_id)
        except Exception as e: raise TadoException(f"Failed get home ID: {e}") from e

    def _check_x_line_generation(self):
        _LOGGER.debug("Checking generation...");
        if self._id is None: raise TadoException("Home ID not set for generation check.")
        headers=self._headers.copy(); url=f"{Endpoint.MY_API}{Domain.HOME}/{self._id}"
        try:
            resp=self._session.get(url, headers=headers, timeout=_DEFAULT_TIMEOUT); resp.raise_for_status(); data=resp.json()
            is_x = data.get("generation") == "LINE_X"; _LOGGER.debug(f"Is X Line = {is_x}"); return is_x
        except Exception as e: raise TadoException(f"Failed check generation: {e}") from e

    def request(self, req: TadoRequest) -> dict[str, Any]:
        if self.device_activation_status != DeviceActivationStatus.COMPLETED: raise TadoException("Auth not completed.")
        try:
            # Refresh is attempted *before* the request if needed
            if not self._refresh_token(force_refresh=False): 
                 # If refresh fails here (returns False or raises TadoCredentialsException caught below)
                 # we cannot proceed with the original request.
                 raise TadoCredentialsException("Token refresh required but failed.") 
        except TadoCredentialsException as e:
             _LOGGER.error(f"Credential error before request {req.command or req.domain}: {e}")
             raise # Re-raise to be caught by the calling script (e.g., engine loop)
        except TadoException as e:
             _LOGGER.error(f"Tado error before request {req.command or req.domain}: {e}")
             raise # Re-raise other Tado errors
        except Exception as e:
             _LOGGER.error(f"Unexpected error before request {req.command or req.domain}: {e}")
             raise # Re-raise unexpected errors
             
        # If refresh check passed, proceed with the actual request
        headers=self._headers.copy(); data=self._configure_payload(headers, req); url=self._configure_url(req)
        prepped=self._session.prepare_request(requests.Request(method=req.action, url=url, headers=headers, data=data)); prepped.hooks={'response': [self._log_response]}
        retries=_DEFAULT_RETRIES
        while retries >= 0:
            try:
                resp = self._session.send(prepped, timeout=_DEFAULT_TIMEOUT); resp.raise_for_status()
                if resp.status_code == 204 or not resp.content: return {}
                try: return resp.json()
                except json.JSONDecodeError as e: raise TadoException(f"Invalid JSON from {url}: {e}") from e
            except requests.exceptions.HTTPError as e:
                 # 401 here *after* refresh check suggests token expired *very* quickly
                 if e.response is not None and e.response.status_code == 401: 
                      _LOGGER.warning(f"Unauthorized (401) on API call to {url} *after* refresh check."); 
                      self._device_activation_status=DeviceActivationStatus.NOT_STARTED; self._token_refresh=None; self._clear_saved_token(); 
                      raise TadoCredentialsException("Unauthorized (401) on API call.") from e
                 _LOGGER.error(f"HTTP error {e.response.status_code if e.response else 'N/A'} calling {url}"); 
                 raise TadoException(f"API call HTTP error") from e
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                if retries > 0: _LOGGER.warning(f"{e.__class__.__name__} calling {url}. Retrying ({retries})..."); time.sleep(1); retries -= 1
                else: raise TadoException(f"API call failed retries: {e}") from e
            except requests.exceptions.RequestException as e: raise TadoException(f"API call failed: {e}") from e
        raise TadoException("API request failed retries.")
