"""
PyTado interface abstraction to use app.tado.com or hops.tado.com
"""

import datetime
import functools
import warnings

import requests

# Adjust import path if api module is structured differently
import PyTado.interface.api as API 
from PyTado.exceptions import TadoException
from PyTado.http import DeviceActivationStatus, Http


# Keep the deprecated decorator as is
def deprecated(new_func_name):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            warnings.warn(
                f"'{func.__name__}' deprecated, use '{new_func_name}'. Remove >= 1.0.0.",
                DeprecationWarning, stacklevel=2)
            # Assuming the first arg is 'self' for instance methods
            return getattr(args[0], new_func_name)(*args[1:], **kwargs) 
        return wrapper
    return decorator

class Tado:
    """Interacts with a Tado thermostat via public API."""

    def __init__(
        self,
        token_file_path: str | None = None,
        saved_refresh_token: str | None = None,
        http_session: requests.Session | None = None,
        debug: bool = False,
    ):
        """Initializes the interface class."""
        self._http = Http(
            token_file_path=token_file_path,
            saved_refresh_token=saved_refresh_token,
            http_session=http_session,
            debug=debug,
        )
        self._api: API.Tado | API.TadoX | None = None
        self._debug = debug # Store debug flag if needed by API implementations

    def __getattr__(self, name):
        """Delegate the called method to api implementation."""
        # Ensure API is initialized before delegating
        self._ensure_api_initialized() 
        
        # Get the method from the underlying API implementation
        if self._api is None: # Should not happen if _ensure_api_initialized works
            raise TadoException("API implementation not loaded after ensuring initialization.")
        
        api_method = getattr(self._api, name)
        
        if not callable(api_method):
            # If it's not callable, maybe it's a property - handle if needed
            # For now, assume we only delegate callable methods
            raise AttributeError(f"'{type(self._api).__name__}' object has no callable attribute '{name}'")
            
        return api_method


    # --- Methods interacting with Http layer ---
    
    def device_verification_url(self) -> str | None:
        """Returns the URL for device verification (call method from http)."""
        # Ensure the underlying property access is correct
        return self._http.device_verification_url

    def device_activation_status(self) -> DeviceActivationStatus:
        """Returns the status of the device activation (call method from http)."""
        # Ensure the underlying property access is correct
        return self._http.device_activation_status

    # --- !!! CORRECTED METHOD !!! ---
    def device_activation(self) -> bool: # Changed type hint from None to bool
        """
        Activates the device by calling the underlying http method 
        and returns its success status.
        """
        # Call the http method and store the result
        success = self._http.device_activation() 
        # Ensure API is initialized *after* activation attempt potentially completes
        if success:
            try:
                self._ensure_api_initialized()
            except Exception as e:
                 # If API init fails even after http layer reported success
                 # maybe return False or log error?
                 _LOGGER.error(f"API initialization failed after successful http activation: {e}")
                 # Decide if this should still be considered success
                 # return False # Or let the original success stand? For now, let it stand.
                 pass 
        return success # Return the boolean result
    # --- !!! END CORRECTION !!! ---

    def get_refresh_token(self) -> str | None:
        """Retrieve the refresh token from the http layer."""
        return self._http.refresh_token

    def _ensure_api_initialized(self):
        """Ensures the correct API client (Tado or TadoX) is initialized."""
        # Only initialize if not already done AND http layer is COMPLETED
        if self._api is None:
            # Check status by calling the method
            current_status = self._http.device_activation_status 
            if current_status == DeviceActivationStatus.COMPLETED:
                if self._http.is_x_line is None:
                    # is_x_line might not be set yet if _device_ready had issues initially
                    # Let's assume it was checked correctly in _device_ready
                     _LOGGER.warning("Could not determine Tado generation (is_x_line is None). Assuming standard API.")
                     self._api = API.Tado(http=self._http, debug=self._debug) # Default to standard
                elif self._http.is_x_line:
                    self._api = API.TadoX(http=self._http, debug=self._debug)
                else:
                    self._api = API.Tado(http=self._http, debug=self._debug)
            else:
                # Don't raise exception here, just means API isn't ready yet.
                # Let callers handle the state if needed.
                # raise TadoException(f"API cannot be initialized. Authentication status: {current_status}")
                pass

    # --- Deprecated Methods remain the same ---
    # region Deprecated Methods
    # pylint: disable=invalid-name
    @deprecated("get_me")
    def getMe(self): return self.get_me()
    @deprecated("get_devices")
    def getDevices(self): return self.get_devices()
    @deprecated("get_zones")
    def getZones(self): return self.get_zones()
    @deprecated("set_child_lock")
    def setChildLock(self, device_id, enabled): return self.set_child_lock(device_id, enabled)
    @deprecated("get_zone_state")
    def getZoneState(self, zone): return self.get_zone_state(zone)
    @deprecated("get_zone_states")
    def getZoneStates(self): return self.get_zone_states()
    @deprecated("get_state")
    def getState(self, zone): return self.get_state(zone)
    @deprecated("get_home_state")
    def getHomeState(self): return self.get_home_state()
    @deprecated("get_auto_geofencing_supported")
    def getAutoGeofencingSupported(self): return self.get_auto_geofencing_supported()
    @deprecated("get_capabilities")
    def getCapabilities(self, zone): return self.get_capabilities(zone)
    @deprecated("get_climate")
    def getClimate(self, zone): return self.get_climate(zone)
    @deprecated("get_timetable")
    def getTimetable(self, zone): return self.get_timetable(zone)
    @deprecated("get_historic")
    def getHistoric(self, zone, date): return self.get_historic(zone, date)
    @deprecated("set_timetable")
    def setTimetable(self, zone, _id): return self.set_timetable(zone, _id)
    @deprecated("get_schedule")
    def getSchedule(self, zone, _id, day=None): return self.get_schedule(zone, _id, day)
    @deprecated("set_schedule")
    def setSchedule(self, zone, _id, day, data): return self.set_schedule(zone, _id, day, data)
    @deprecated("get_weather")
    def getWeather(self): return self.get_weather()
    @deprecated("get_air_comfort")
    def getAirComfort(self): return self.get_air_comfort()
    @deprecated("get_users")
    def getAppUsers(self): return self.get_app_user() # Corrected name? Assuming get_app_user exists
    @deprecated("get_mobile_devices")
    def getMobileDevices(self): return self.get_mobile_devices()
    @deprecated("reset_zone_overlay")
    def resetZoneOverlay(self, zone): return self.reset_zone_overlay(zone)
    @deprecated("set_zone_overlay")
    def setZoneOverlay(self, zone, overlayMode, setTemp=None, duration=None, deviceType="HEATING", power="ON", mode=None, fanSpeed=None, swing=None, fanLevel=None, verticalSwing=None, horizontalSwing=None):
        return self.set_zone_overlay(zone, overlayMode, setTemp, duration, deviceType, power, mode, fanSpeed, swing, fanLevel, verticalSwing, horizontalSwing)
    @deprecated("get_zone_overlay_default")
    def getZoneOverlayDefault(self, zone): return self.get_zone_overlay_default(zone)
    @deprecated("set_home")
    def setHome(self): return self.set_home()
    @deprecated("set_away")
    def setAway(self): return self.set_away()
    @deprecated("change_presence")
    def changePresence(self, presence): return self.change_presence(presence=presence)
    @deprecated("set_auto")
    def setAuto(self): return self.set_auto()
    @deprecated("get_window_state")
    def getWindowState(self, zone): return self.get_window_state(zone=zone)
    @deprecated("get_open_window_detected")
    def getOpenWindowDetected(self, zone): return self.get_open_window_detected(zone=zone)
    @deprecated("set_open_window")
    def setOpenWindow(self, zone): return self.set_open_window(zone=zone)
    @deprecated("reset_open_window")
    def resetOpenWindow(self, zone): return self.reset_open_window(zone=zone)
    @deprecated("get_device_info")
    def getDeviceInfo(self, device_id, cmd=""): return self.get_device_info(device_id=device_id, cmd=cmd)
    @deprecated("set_temp_offset")
    def setTempOffset(self, device_id, offset=0, measure="celsius"): return self.set_temp_offset(device_id=device_id, offset=offset, measure=measure)
    @deprecated("get_eiq_tariffs")
    def getEIQTariffs(self): return self.get_eiq_tariffs()
    @deprecated("get_eiq_meter_readings")
    def getEIQMeterReadings(self): return self.get_eiq_meter_readings()
    @deprecated("set_eiq_meter_readings")
    def setEIQMeterReadings(self, date=datetime.datetime.now().strftime("%Y-%m-%d"), reading=0): return self.set_eiq_meter_readings(date=date, reading=reading)
    @deprecated("set_eiq_tariff")
    def setEIQTariff(self, from_date=datetime.datetime.now().strftime("%Y-%m-%d"), to_date=datetime.datetime.now().strftime("%Y-%m-%d"), tariff=0, unit="m3", is_period=False):
        return self.set_eiq_tariff(from_date=from_date, to_date=to_date, tariff=tariff, unit=unit, is_period=is_period)
    # pylint: enable=invalid-name
    # endregion
