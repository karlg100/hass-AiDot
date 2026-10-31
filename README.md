# ha-AiDot

Download and copy `custom_components/aidot` folder to `custom_components` folder in your HomeAssistant config folder

HACS Support

## BLE hub recovery (1.1.4-beta.9)

An invalid cloud session is retried once using the saved account credentials.
Successful login details are saved, and refreshed hub addresses and credentials
are applied to the shared local connection. Repeated hub connection failures
request fresh cloud data at most once every five minutes.

BLE lights become unavailable when their hub connection drops and recover when
the connection returns. The passive listener reconnects after 90 seconds without
any incoming hub data; it does not poll battery-powered lights. Downloaded
diagnostics include connection attempts, the last successful login and the phase
and exception type of the last failure, without including exception messages or
credentials.
