# owl24-py

Python SDK for [owl24](https://owl24.dev) — one line of code to send logs, traces, and metrics to your owl24 dashboard, built on OpenTelemetry.

## Install

```bash
pip install owl24-py
```

## Usage

```python
import os
from owl24_py import Owl24

Owl24.init(os.getenv("OWL24_API_KEY"), "my-service-name")
```

That's it — `Owl24.init(...)` wires up an OpenTelemetry tracer/meter/logger provider pointed at your owl24 ingest endpoint, and patches Python's `logging` module so `logging.info(...)`, `logging.error(...)`, etc. are automatically sent to your dashboard alongside the current trace/span ID.

### Options

```python
Owl24.init(
    api_key=None,                     # or set OWL24_API_KEY / OBSERVE_API_KEY env var
    service_name="dice-server",
    export_interval_millis=3000,
    disable_console_bridge=False,     # set True to stop auto-forwarding logging.* calls
    disable_crash_capture=False,      # set True to disable uncaught-exception capture
    export_timeout_millis=5000,
    disable_auto_instrumentation=False, # set True to skip Flask/Django/FastAPI/requests auto-tracing
)
```

Telemetry is always sent to `https://ingest.owl24.dev` — owl24's ingest endpoint isn't configurable, since it's a fixed part of the hosted service (only the API key is per-customer).

## What it does

- **Logs**: patches the root `logging` logger — every `logging.*` call is forwarded as a structured log, tagged with the active trace/span ID if one exists.
- **Traces**: sets up an OpenTelemetry `TracerProvider` exporting via OTLP/HTTP. Spans you create manually, or automatically via Flask/Django/FastAPI/`requests` (see below), are masked and exported.
- **Host metrics**: CPU, memory, and network metrics are collected and exported automatically via `opentelemetry-instrumentation-system-metrics` — no setup required.
- **Crash capture**: installs a `sys.excepthook` and `threading.excepthook` so uncaught exceptions (main thread and background threads) are captured as FATAL-severity log events and flushed before the process exits.
- **PII masking**: emails, credit-card-shaped numbers, phone numbers, and bearer tokens are scrubbed from span attributes and log bodies before they ever leave your process.

## Automatic HTTP tracing

Install the extra for whichever framework/library you use, and `Owl24.init()` will automatically create spans for incoming requests (Flask/Django/FastAPI) or outgoing calls (`requests`) — no other code changes needed:

```bash
pip install "owl24-py[flask]"      # Flask
pip install "owl24-py[django]"     # Django
pip install "owl24-py[fastapi]"    # FastAPI
pip install "owl24-py[requests]"   # outgoing requests via the `requests` library
```

None of these are installed by default — `pip install owl24-py` alone still gives you logs, host metrics, crash capture, and manually-created spans, with zero extra framework dependencies pulled in.

### Flask and FastAPI: call `Owl24.init()` before importing the framework

For Flask and FastAPI specifically (not Django - see below), `Owl24.init()` must run **before your own code does `from flask import Flask` or `from fastapi import FastAPI`**:

```python
from owl24_py import Owl24
Owl24.init(api_key, "my-service")

from flask import Flask   # import AFTER init() - this is the part that matters
app = Flask(__name__)
```

Getting this backwards doesn't raise an error or a warning - it just silently produces zero traces, ever, for that service. Why: Flask/FastAPI's instrumentation works by reassigning the framework's own `Flask`/`FastAPI` class in its module (e.g. `flask.Flask = _InstrumentedFlask`) - if your code already did `from flask import Flask` and bound that name to the original class before `Owl24.init()` runs, that name keeps pointing at the unpatched original forever; reassigning `flask.Flask` afterward can't reach back and fix an already-bound reference. (Using `import flask` and calling `flask.Flask(...)` instead of `from flask import Flask` sidesteps this entirely, since that always resolves the class fresh - but `Owl24.init()` first is the simpler rule to just always follow.)

**Django doesn't have this restriction** - its instrumentation works by inserting into Django's `settings.MIDDLEWARE`, which Django resolves lazily when it actually starts handling requests, not by reassigning a class. Import order doesn't matter for Django.

## License

MIT — see [LICENSE](https://github.com/Madnands5/owl24/blob/main/packages/owl24-py/LICENSE).
