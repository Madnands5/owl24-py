import os
import re
import sys
import json
import logging
import random
import signal
import threading
import time
import traceback
import urllib.request
import urllib.error
from importlib.metadata import version as _pkg_version, PackageNotFoundError
from typing import Any
from types import MappingProxyType

# This module's own print statements use emoji (see below) - on Windows,
# the console's default codepage (cp1252) can't encode them, which throws
# a UnicodeEncodeError right on the *success* print at the end of init()'s
# try-block - meaning init() silently reported "Init failed" even when
# everything actually succeeded. Forcing UTF-8 here (guarded: reconfigure()
# doesn't exist on every stream type, and this must never itself crash the
# import) fixes that instead of stripping the emoji.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from opentelemetry import trace, metrics
from opentelemetry.sdk.resources import Resource, SERVICE_NAME, SERVICE_VERSION
from opentelemetry.sdk.trace import TracerProvider, SpanProcessor
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SpanExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.http import Compression
from opentelemetry._logs import SeverityNumber, set_logger_provider
from opentelemetry.sdk._logs import LoggerProvider
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
from opentelemetry.instrumentation.system_metrics import SystemMetricsInstrumentor

# Auto-tracing for whichever of these the host app already has installed -
# mirrors owl24-js's getNodeAutoInstrumentations() "instrument whatever's
# present" behavior. Every one of these OTel instrumentor packages is now a
# hard dependency of owl24-py itself (pyproject.toml) - the try/except here
# is defensive only (a broken/partial install), not a gate on whether the
# consumer remembered to opt into an extra. The actual framework/driver
# library (Flask/Django/psycopg2/etc.) is still the host app's own
# dependency, not owl24-py's - a host app that doesn't use a given one still
# gets logs + manual spans + host metrics + every OTHER instrumentor,
# exactly as before.
#
# FastAPI is NOT special-cased/unconditional here despite 0.1.2-0.1.6 saying
# otherwise (a real bug, found via a live soak test against every clientserver
# demo, 2026-09-12): opentelemetry-instrumentation-fastapi's own __init__.py
# does its own unconditional `import fastapi` at module load - a Flask/Django
# consumer that has never installed the real fastapi package (most of them
# haven't; it's not one of THEIR framework's own dependencies) got a hard
# ModuleNotFoundError crash at import time, every time, not a graceful
# degradation - worse than the original 0.1.1 bug this was meant to fix
# (silently-empty traces), since it took the whole process down instead.
# try/except here fixes both at once: a FastAPI consumer's own app always has
# real fastapi installed (it's what makes their app a FastAPI app), so this
# import succeeds for them with zero extra config, same as before - a
# Flask/Django/plain consumer's app doesn't, so it's skipped gracefully
# instead of crashing, exactly like every other instrumentor below.
_AUTO_INSTRUMENTORS = []
try:
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    _AUTO_INSTRUMENTORS.append(("fastapi", FastAPIInstrumentor))
except ImportError:
    pass
try:
    from opentelemetry.instrumentation.flask import FlaskInstrumentor
    _AUTO_INSTRUMENTORS.append(("flask", FlaskInstrumentor))
except ImportError:
    pass
try:
    from opentelemetry.instrumentation.django import DjangoInstrumentor
    _AUTO_INSTRUMENTORS.append(("django", DjangoInstrumentor))
except ImportError:
    pass
try:
    from opentelemetry.instrumentation.requests import RequestsInstrumentor
    _AUTO_INSTRUMENTORS.append(("requests", RequestsInstrumentor))
except ImportError:
    pass
# DB drivers - each tags its spans with the `db.system`/`db.name` OTel
# semantic-convention attributes that DbMetricsSpanProcessor below watches
# for, exactly like the framework instrumentors above but for database
# calls instead of HTTP. Same hard-dependency treatment as those: a host
# app that doesn't use a given driver still gets everything else, just no
# `db.query.*` metrics for that one (nothing ever produces a
# `db.system`-tagged span to derive them from).
try:
    from opentelemetry.instrumentation.psycopg2 import Psycopg2Instrumentor
    _AUTO_INSTRUMENTORS.append(("psycopg2", Psycopg2Instrumentor))
except ImportError:
    pass
try:
    from opentelemetry.instrumentation.pymongo import PymongoInstrumentor
    _AUTO_INSTRUMENTORS.append(("pymongo", PymongoInstrumentor))
except ImportError:
    pass
try:
    from opentelemetry.instrumentation.pymysql import PyMySQLInstrumentor
    _AUTO_INSTRUMENTORS.append(("pymysql", PyMySQLInstrumentor))
except ImportError:
    pass
try:
    from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
    _AUTO_INSTRUMENTORS.append(("sqlalchemy", SQLAlchemyInstrumentor))
except ImportError:
    pass

# Maps Python's stdlib level names to the OTLP SeverityNumber enum - the log
# bridge previously stored logging._levelToName's raw string here (wrong
# type for this field, and a private stdlib internal besides).
_PYTHON_TO_OTEL_SEVERITY = {
    "DEBUG": SeverityNumber.DEBUG,
    "INFO": SeverityNumber.INFO,
    "WARNING": SeverityNumber.WARN,
    "ERROR": SeverityNumber.ERROR,
    "CRITICAL": SeverityNumber.FATAL,
}


# Task 8 (todolist.md), expanded 2026-08-23 - see masking.py for the full
# detection categories (PCI-DSS cards with Luhn validation, gitleaks-derived
# secret prefixes, IBAN/MOD-97, US routing numbers, IP truncation, RFC1918
# detection, internal hostname suffixes) and the customer-configurable
# field-name mechanism (is_sensitive_field_name/configure_masking) that
# backs proprietary/business-sensitive data, which has no pattern of its own.
from .masking import mask_sensitive_data, is_sensitive_field_name, configure_masking

# Task H (competitive-roadmap.md) - same field-name/value-pattern masking
# rule as MaskingSpanExporter below, reused by track_event() for event
# attributes: customers will inevitably put arbitrary key-value data in
# events, same risk profile as span/log attributes.
def _mask_attributes(attributes):
    masked = {}
    for key, value in (attributes or {}).items():
        if is_sensitive_field_name(key):
            masked[key] = "[FIELD_MASKED]"
        elif isinstance(value, str):
            masked[key] = mask_sensitive_data(value)
        else:
            masked[key] = value
    return masked


def safe_serialize(obj: Any) -> str:
    try:
        return json.dumps(obj, default=lambda o: "[Unserializable Object]")
    except ValueError:
        return "[Circular]"
    except Exception:
        return "[Unserializable Object]"

class _MaskedReadableSpan:
    """Duck-typed proxy around a real ReadableSpan: delegates every
    attribute except `.attributes` to the wrapped span unchanged, and
    returns a masked copy for `.attributes`. The OTLP exporter's encoder
    only ever reads `sdk_span.attributes` (type-hinted as ReadableSpan, but
    never isinstance-checked), so this duck typing is enough for it to
    treat this exactly like a real span.
    """

    def __init__(self, wrapped, masked_attributes):
        self._wrapped = wrapped
        self._masked_attributes = masked_attributes

    def __getattr__(self, name):
        return getattr(self._wrapped, name)

    @property
    def attributes(self):
        return self._masked_attributes


class MaskingSpanExporter(SpanExporter):
    """Wraps a SpanExporter and masks string span attributes before they
    reach the real exporter - closes the masking gap for auto-instrumented
    spans (http.url query strings, db.statement literals, etc.), which
    never went through mask_sensitive_data before (only the logging bridge
    above did).

    This masks into a *copy* rather than mutating the original span's
    attributes in place (the approach used by owl24-js's equivalent
    MaskingSpanProcessor, and originally attempted here too) because the
    current OTel Python SDK makes a span's attributes hard-immutable the
    moment end() is called (`self._attributes._immutable = True`, set
    before any processor's on_end() even runs) - verified live: mutating
    either the public `.attributes` property (a fresh MappingProxyType each
    time) or the private `._attributes` BoundedAttributes both raise
    TypeError, unconditionally, for every span. There's no supported way to
    mutate a span after it ends in this SDK version, so masking has to
    happen at the exporter boundary instead, the same place owl24-java's
    equivalent gap gets closed (its ReadOnlySpan is sealed against external
    implementations too, for a different underlying reason).
    """

    def __init__(self, wrapped):
        self._wrapped = wrapped

    def export(self, spans):
        masked_spans = []
        for span in spans:
            try:
                original_attrs = dict(span.attributes or {})
                masked_attrs = {
                    key: (
                        "[FIELD_MASKED]" if is_sensitive_field_name(key)
                        else mask_sensitive_data(value) if isinstance(value, str)
                        else value
                    )
                    for key, value in original_attrs.items()
                }
                masked_spans.append(_MaskedReadableSpan(span, MappingProxyType(masked_attrs)))
            except Exception as e:
                print(f"[Owl24] Masking Error: {e}", file=sys.stderr)
                masked_spans.append(span)
        return self._wrapped.export(masked_spans)

    def shutdown(self):
        return self._wrapped.shutdown()

    def force_flush(self, timeout_millis=30000):
        force_flush_fn = getattr(self._wrapped, "force_flush", None)
        return force_flush_fn(timeout_millis) if force_flush_fn else True


class DbMetricsSpanProcessor(SpanProcessor):
    """Derives DB query metrics (count, duration, errors) from spans that
    the driver instrumentors above already tag with `db.system` (psycopg2,
    pymongo, pymysql, sqlalchemy, etc.) - no separate per-driver hooking
    needed, and it's the same shape as owl24-js's DbMetricsSpanProcessor
    since these are OTel semantic conventions, not something owl24-py
    invented. Instruments are created lazily on first matching span (not in
    __init__) since the global MeterProvider isn't set until later in
    init() - this processor is registered on the tracer provider before
    that happens, but no real span ends before init() itself returns.
    Feeds the same metric_readers as SystemMetricsInstrumentor above, so
    these ride the existing OTLP metrics export pipeline into the same
    `metrics` table dashboard-api.js already reads CPU/memory from - no
    separate ingestion path needed.
    """

    def __init__(self):
        self._query_count = None
        self._query_duration = None
        self._query_errors = None

    def _ensure_instruments(self):
        if self._query_count is not None:
            return
        meter = metrics.get_meter("owl24-db-metrics")
        self._query_count = meter.create_counter(
            "db.query.count",
            description="Number of database queries observed via auto-instrumented spans",
        )
        self._query_duration = meter.create_histogram(
            "db.query.duration_ms",
            description="Database query duration in milliseconds",
            unit="ms",
        )
        self._query_errors = meter.create_counter(
            "db.query.error_count",
            description="Number of database queries that ended in an error",
        )

    def on_start(self, span, parent_context=None):
        pass

    def on_end(self, span):
        attrs = span.attributes or {}
        db_system = attrs.get("db.system")
        if not db_system:
            return

        self._ensure_instruments()
        attributes = {"db.system": db_system}
        db_name = attrs.get("db.name")
        if db_name:
            attributes["db.name"] = db_name

        duration_ms = (span.end_time - span.start_time) / 1e6
        self._query_count.add(1, attributes)
        self._query_duration.record(duration_ms, attributes)
        if span.status is not None and span.status.status_code == trace.StatusCode.ERROR:
            self._query_errors.add(1, attributes)

    def shutdown(self):
        pass

    def force_flush(self, timeout_millis=30000):
        return True


class _StatusTracker:
    """Tracks working/not-working status per signal ("traces"/"metrics"/
    "logs") for the life of the process, and confirms a state transition
    with a bounded retry before declaring a pipeline down, instead of
    reacting to a single failed flush - collector hiccups are common and
    shouldn't cause a false "not working" the moment a scheduled export
    overlaps a blip.

    Retries only fire at the two points that matter: the very first export
    attempt for a signal ("initiating"), and the first failure after a
    signal was previously confirmed working ("stopped working midway") -
    NOT on every routine flush while a signal is in a known-good or
    known-bad steady state. The installed OTLP exporters already
    retry/bound themselves internally up to their own configured `timeout`
    (verified live: OTLPSpanExporter.export() retries internally up to
    `_MAX_RETRYS = 6`, bounded by an overall deadline, and swallows the
    underlying request exception itself rather than raising it) - wrapping
    every flush in another round of retries here could make one flush take
    far longer than the scheduled export interval and pile up during a
    real outage.
    """

    _MAX_ATTEMPTS = 3
    _BACKOFF_SECONDS = (0.3, 0.8)

    def __init__(self):
        self._lock = threading.Lock()
        self._states = {"traces": "PENDING", "metrics": "PENDING", "logs": "PENDING"}
        self._last_aggregate = None

    def track(self, signal, attempt):
        """Wraps one export attempt for `signal` with the transition-
        confirming retry described above. `attempt` is a zero-arg callable
        that performs one real export call and returns its result (or
        raises) - safe to call more than once, since a retry re-sends the
        same batch rather than fetching fresh data.
        """
        state = self._states.get(signal)

        if state == "NOT_WORKING":
            # Known-down steady state: single attempt, no retry, no repeat
            # log/report - avoids spamming during a known outage.
            result, reason = self._attempt_once(attempt)
            if reason is None:
                self._transition(signal, "WORKING", None)
            return result

        # PENDING (initiating) or WORKING (confirming a possible "stopped
        # working midway"): retry the same payload up to _MAX_ATTEMPTS
        # total before declaring the signal not-working.
        result = None
        reason = None
        for attempt_num in range(1, self._MAX_ATTEMPTS + 1):
            result, reason = self._attempt_once(attempt)
            if reason is None:
                self._transition(signal, "WORKING", None)
                return result
            if attempt_num < self._MAX_ATTEMPTS:
                time.sleep(self._BACKOFF_SECONDS[attempt_num - 1])

        self._transition(signal, "NOT_WORKING", reason)
        return result

    @staticmethod
    def _attempt_once(attempt):
        try:
            result = attempt()
        except Exception as e:
            return None, f"{type(e).__name__}: {e}"
        if getattr(result, "name", None) == "SUCCESS":
            return result, None
        # The installed OTLP exporters swallow their own request exceptions
        # internally and just return a FAILURE enum with no attached detail
        # - an honest generic fallback is the best we can report here.
        return result, "export failed (no additional detail available)"

    def _transition(self, signal, new_state, reason):
        with self._lock:
            previous = self._states.get(signal)
            self._states[signal] = new_state
            if previous == new_state:
                return

            if new_state == "WORKING":
                print(f"[Owl24] {signal} working")
            elif new_state == "NOT_WORKING":
                print(f"[Owl24] {signal} not working because: {reason}", file=sys.stderr)

            self._reevaluate_aggregate()

    def _reevaluate_aggregate(self):
        # Caller already holds self._lock.
        if any(s == "PENDING" for s in self._states.values()):
            return  # wait until all 3 signals have resolved at least once

        working_count = sum(1 for s in self._states.values() if s == "WORKING")
        if working_count == len(self._states):
            aggregate = "[Owl24] engaged fully"
        elif working_count == 0:
            aggregate = "[Owl24] failed to engage"
        else:
            aggregate = "[Owl24] partially engaged"

        if aggregate != self._last_aggregate:
            self._last_aggregate = aggregate
            print(aggregate)


class _StatusTrackingExporter:
    """Thin wrapper around a real exporter (or another wrapper, e.g. a
    MaskingSpanExporter) that routes only export() through
    `_StatusTracker.track()` for `signal`; every other attribute (shutdown,
    force_flush, the metric exporter's private `_preferred_temporality` /
    `_preferred_aggregation` read directly by PeriodicExportingMetricReader,
    etc.) is forwarded straight through to the wrapped object unchanged via
    __getattr__. One class covers all three signals since, unlike Java,
    SpanExporter/MetricExporter/LogRecordExporter share no common
    supertype here to justify separate wrapper classes for what's
    otherwise identical logic.
    """

    def __init__(self, delegate, signal, tracker):
        self._delegate = delegate
        self._signal = signal
        self._tracker = tracker

    def export(self, data, *args, **kwargs):
        return self._tracker.track(
            self._signal, lambda: self._delegate.export(data, *args, **kwargs)
        )

    def __getattr__(self, name):
        return getattr(self._delegate, name)


# Logger name prefixes excluded from the console bridge - the exporters
# themselves (and the HTTP libraries they use) log through this same root
# logger when a request fails/retries. Without this exclusion, a failed
# export logs a warning through `logging`, the bridge captures that warning
# and tries to export IT too, which can itself fail and log another
# warning, recursively - verified live: this hung a real crash-capture
# flush indefinitely (no bound at all, worse than just being slow) once the
# ingest endpoint was unreachable, which is exactly the moment a crash
# handler needs to be reliable.
_EXCLUDED_LOGGER_PREFIXES = ("opentelemetry", "urllib3", "requests")


class MaskingAndOtelHandler(logging.Handler):
    def __init__(self, otel_logger):
        super().__init__()
        self.otel_logger = otel_logger

    def emit(self, record):
        if record.name.startswith(_EXCLUDED_LOGGER_PREFIXES):
            return
        try:
            msg = record.getMessage()
            body = safe_serialize(msg) if isinstance(msg, (dict, list)) else str(msg)
            masked_body = mask_sensitive_data(body)
            
            current_span = trace.get_current_span()
            span_context = current_span.get_span_context() if current_span else None
            
            trace_id = format(span_context.trace_id, '032x') if span_context and span_context.trace_id else None
            span_id = format(span_context.span_id, '016x') if span_context and span_context.span_id else None

            level_name = logging.getLevelName(record.levelno)
            # Passed as kwargs directly (not a constructed LogRecord - that
            # class was removed from opentelemetry-sdk in 1.39, which
            # `Logger.emit()` builds internally from these same kwargs).
            self.otel_logger.emit(
                timestamp=int(record.created * 1e9),
                body=masked_body,
                severity_number=_PYTHON_TO_OTEL_SEVERITY.get(level_name, SeverityNumber.INFO),
                severity_text=level_name,
                attributes={
                    "manual.trace_id": trace_id,
                    "manual.span_id": span_id,
                    "is_winston": "false"
                }
            )
        except Exception as e:
            print(f"[Owl24] Bridge Error: {e}", file=sys.stderr)


def _installed_version() -> str:
    try:
        return _pkg_version("owl24-py")
    except PackageNotFoundError:
        # Editable/dev install without proper package metadata registered -
        # not a real version to report, but init() must never crash over
        # this, so fall back to something clearly not a real release.
        return "0.0.0"


# Called once, synchronously, at the very start of init() - separate from
# the OTLP exporters below because they never expose their underlying HTTP
# response back to caller code (SpanExporter.export() just returns a
# SUCCESS/FAILURE enum), so there's no way to detect ingestor.js's 426
# Upgrade Required from inside a normal export call. A short timeout and a
# blanket try/except mean a slow/unreachable server here degrades to
# "assume fine, proceed" rather than delaying or breaking the host app's
# own startup - the same non-blocking-failure philosophy as the rest of
# init().
def _check_sdk_version(ingest_base_url, headers, timeout_seconds):
    try:
        request = urllib.request.Request(
            f"{ingest_base_url}/v1/sdk-check",
            method="POST",
            headers=headers,
        )
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            body = json.loads(response.read().decode("utf-8"))
        if body.get("update_required"):
            print("[Owl24] Please Update package. telemetry shutting down", file=sys.stderr)
            return True
        return False
    except Exception:
        # Unreachable/unexpected response: fail open (assume the version is
        # fine) rather than blocking a customer's app startup on an ingest
        # endpoint being temporarily unavailable.
        return False


class Owl24:
    _tracer_provider = None
    _meter_provider = None
    _logger_provider = None
    _crash_capture_registered = False
    _original_excepthook = None
    _original_threading_excepthook = None
    _system_metrics_instrumentor = None
    _active_auto_instrumentors = []
    _status_tracker = None
    _event_ingest_config = None

    @classmethod
    def _record_fatal(cls, origin, exc_type, exc_value, exc_tb):
        """Logs a FATAL-severity event for an uncaught exception and forces
        a bounded-time flush - without this, a crash on the main thread
        (which Python will exit right after, once the excepthook returns)
        could exit before the batch processor's own timer ever fires, and
        the crash telemetry would never actually be sent.
        """
        try:
            message = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
            if cls._logger_provider:
                otel_logger = cls._logger_provider.get_logger("crash-capture")
                otel_logger.emit(
                    body=mask_sensitive_data(f"[{origin}] {message}"),
                    severity_number=SeverityNumber.FATAL,
                    severity_text="FATAL",
                    attributes={"error.type": origin},
                )
                cls._logger_provider.force_flush(timeout_millis=5000)
            if cls._tracer_provider:
                cls._tracer_provider.force_flush(timeout_millis=5000)
        except Exception as e:
            print(f"[Owl24] Failed to record crash event: {e}", file=sys.stderr)

    @classmethod
    def _setup_crash_capture(cls):
        if cls._crash_capture_registered:
            return
        cls._crash_capture_registered = True

        cls._original_excepthook = sys.excepthook

        def excepthook(exc_type, exc_value, exc_tb):
            cls._record_fatal("uncaught_exception", exc_type, exc_value, exc_tb)
            # Chain to the previous hook (Python's default one, unless
            # something else already replaced it) so the normal traceback
            # still prints and the interpreter still exits as it always
            # would - this only adds capture+flush, it doesn't change
            # whether/how the process exits.
            (cls._original_excepthook or sys.__excepthook__)(exc_type, exc_value, exc_tb)

        sys.excepthook = excepthook

        # An uncaught exception in a background thread only kills that
        # thread by default, not the process - still worth capturing since
        # it's telemetry the app would otherwise lose entirely.
        if hasattr(threading, "excepthook"):
            cls._original_threading_excepthook = threading.excepthook

            def threading_excepthook(args):
                cls._record_fatal("uncaught_exception_thread", args.exc_type, args.exc_value, args.exc_traceback)
                (cls._original_threading_excepthook or threading.__excepthook__)(args)

            threading.excepthook = threading_excepthook

    @classmethod
    def init(cls, api_key=None, service_name="dice-server", export_interval_millis=10000,
             disable_console_bridge=False, disable_crash_capture=False, export_timeout_millis=5000,
             disable_auto_instrumentation=False, metrics_export_interval_millis=30000,
             mask_fields=None, internal_hostname_suffixes=None, ingest_base_url=None):
        """
        mask_fields: field names (attribute/log keys) to mask wholesale on
            top of the built-in default list - exact names or '*'-wildcard
            patterns, e.g. ['*api_key*', 'pricing.*', 'internal_customer_id'].
            Additive, not a replacement (Task 8, todolist.md).
        internal_hostname_suffixes: additional hostname suffixes to mask
            (default: .internal, .svc.cluster.local, .corp), also additive.
        ingest_base_url: overrides the ingest endpoint (default:
            https://ingest.owl24.dev) - for self-hosted customers pointing
            this SDK at their own collector instead of owl24's hosted
            endpoint.
        """
        configure_masking(mask_fields, internal_hostname_suffixes)
        resolved_api_key = api_key or os.getenv("owl24_API_KEY") or os.getenv("OBSERVE_API_KEY")
        user_email = os.getenv("owl24_USER_EMAIL") or os.getenv("OBSERVE_USER_EMAIL") or "unknown@local.dev"
        # Defaults to owl24's hosted ingest endpoint, same as
        # owl24-web's ingestBaseUrl option - overridable via ingest_base_url
        # for self-hosted customers running their own collector.
        ingest_base_url = ingest_base_url or "https://ingest.owl24.dev"

        if not resolved_api_key:
            print("[Owl24] API Key required.", file=sys.stderr)
            return

        # Any failure below (bad ingest URL, exporter/provider construction
        # error) must not crash the host application - an observability
        # SDK failing to initialize should degrade to a no-op, not take the
        # customer's app down with it.
        try:
            sdk_version = _installed_version()
            headers = {
                "x-api-key": resolved_api_key,
                "x-user-email": user_email,
                "x-sdk-language": "python",
                "x-sdk-version": sdk_version,
            }
            resource = Resource.create({
                SERVICE_NAME: service_name,
                SERVICE_VERSION: "0.1.0",
            })

            # Explicit per-attempt timeout on every exporter - without this,
            # each export attempt falls back to the OTel SDK's own default
            # (10s), and a single unreachable-endpoint retry can then run
            # well past force_flush()'s own timeout_millis (that timeout
            # only bounds "wait for the worker to report back", not an
            # export call already in flight). This is what makes
            # _record_fatal's crash-time flush actually bounded - verified
            # live: without this, a crash-capture flush against an
            # unreachable endpoint hung past 12s despite a 5s force_flush
            # timeout.
            export_timeout_seconds = export_timeout_millis / 1000

            # Server-side version gate (ingestor.js) refuses actual
            # telemetry ingestion from a version this far behind anyway -
            # checking here first means a customer running a known-bad old
            # release (like the pre-0.1.4 metrics blowup) finds out via a
            # clear log line at startup, instead of every export silently
            # failing with no explanation.
            if _check_sdk_version(ingest_base_url, headers, export_timeout_seconds):
                return

            # Task H (competitive-roadmap.md) - track_event() reads this
            # once init() has resolved the same headers/service_name every
            # other exporter above already uses.
            cls._event_ingest_config = {
                "ingest_base_url": ingest_base_url,
                "headers": headers,
                "service_name": service_name,
            }

            # Tracks whether each of traces/metrics/logs is actually getting
            # through (not just whether it was built without error) - logs
            # "<signal> working" / "<signal> not working because: ..." on
            # each transition and the "engaged fully/partially/failed to
            # engage" aggregate once all 3 have resolved at least once. See
            # _StatusTracker's docstring for why this doesn't just wrap
            # every routine flush in a retry.
            cls._status_tracker = _StatusTracker()

            cls._tracer_provider = TracerProvider(resource=resource)
            trace_exporter = OTLPSpanExporter(
                endpoint=f"{ingest_base_url}/v1/traces", headers=headers,
                timeout=export_timeout_seconds, compression=Compression.Gzip,
            )
            status_tracked_trace_exporter = _StatusTrackingExporter(
                MaskingSpanExporter(trace_exporter), "traces", cls._status_tracker
            )
            cls._tracer_provider.add_span_processor(
                BatchSpanProcessor(
                    status_tracked_trace_exporter, schedule_delay_millis=export_interval_millis,
                    max_export_batch_size=2048, max_queue_size=8192,
                )
            )
            cls._tracer_provider.add_span_processor(DbMetricsSpanProcessor())
            trace.set_tracer_provider(cls._tracer_provider)

            # Deliberately NOT export_interval_millis (traces/logs' 3s
            # default) - host/DB metrics are slow-changing aggregates, not
            # per-event data, so flushing them every 3s was pure overhead.
            # Confirmed live: SystemMetricsInstrumentor's default config below
            # (unset = every metric it knows, several exploded per-core/
            # per-disk/per-interface) at a 3s interval produced 4.3M metric
            # rows/day from ONE service - 99% of total DB size. A 30s default
            # cuts that ~10x on its own, on top of the config restriction.
            metric_exporter = OTLPMetricExporter(
                endpoint=f"{ingest_base_url}/v1/metrics", headers=headers,
                timeout=export_timeout_seconds, compression=Compression.Gzip,
            )
            status_tracked_metric_exporter = _StatusTrackingExporter(metric_exporter, "metrics", cls._status_tracker)
            reader = PeriodicExportingMetricReader(status_tracked_metric_exporter, export_interval_millis=metrics_export_interval_millis)
            cls._meter_provider = MeterProvider(resource=resource, metric_readers=[reader])
            metrics.set_meter_provider(cls._meter_provider)

            # Host metrics (CPU/memory/network) - the Python equivalent of
            # owl24-js's HostMetrics and owl24-java's runtime-telemetry-java8
            # observers. Explicit config (not SystemMetricsInstrumentor's
            # default) - the default's _DEFAULT_CONFIG covers ~30 metric
            # names, many broken down per CPU core/disk/network interface,
            # which is what produced the runaway volume above. This is a
            # deliberately small, still-useful subset: overall CPU/memory
            # utilization (not per-core/per-state-and-core breakdowns), this
            # process's own CPU/memory, plus GC/thread/swap health (added for
            # parity with owl24-java's runtime-telemetry, which already
            # reports GC and thread count) - none of these five explode
            # per-core/per-disk/per-interface the way system.disk.*/
            # system.network.* do, so they stay cheap even though the count
            # of metric names grew.
            cls._system_metrics_instrumentor = SystemMetricsInstrumentor(config={
                "system.cpu.utilization": ["idle", "user", "system"],
                "system.memory.utilization": ["used", "free"],
                "system.swap.utilization": ["used", "free"],
                "process.runtime.cpu.utilization": None,
                "process.runtime.memory": ["rss"],
                "process.runtime.thread_count": None,
                "process.runtime.gc_count": None,
                "cpython.gc.collected_objects": None,
                "cpython.gc.uncollectable_objects": None,
            })
            cls._system_metrics_instrumentor.instrument()

            if not disable_auto_instrumentation:
                for name, instrumentor_cls in _AUTO_INSTRUMENTORS:
                    try:
                        instance = instrumentor_cls()
                        instance.instrument()
                        cls._active_auto_instrumentors.append(instance)
                    except Exception as auto_instrument_error:
                        print(f"[Owl24] Auto-instrumentation for '{name}' failed: {auto_instrument_error}", file=sys.stderr)

            cls._logger_provider = LoggerProvider(resource=resource)
            log_exporter = OTLPLogExporter(
                endpoint=f"{ingest_base_url}/v1/logs", headers=headers,
                timeout=export_timeout_seconds, compression=Compression.Gzip,
            )
            status_tracked_log_exporter = _StatusTrackingExporter(log_exporter, "logs", cls._status_tracker)
            cls._logger_provider.add_log_record_processor(
                BatchLogRecordProcessor(
                    status_tracked_log_exporter, schedule_delay_millis=export_interval_millis,
                    max_export_batch_size=2048, max_queue_size=8192,
                )
            )
            set_logger_provider(cls._logger_provider)

            # Startup jitter (best-effort): if a whole fleet of instances
            # starts at the same moment (a rollout, a scale-up), they'd
            # otherwise all schedule their first batch flush
            # export_interval_millis later in lockstep, producing a
            # synchronized request spike at the ingestor instead of smoothed
            # traffic. This must NOT delay init() itself (spans have to be
            # captured from t=0, and a blocking sleep here would regress k8s
            # readiness probes) - so it's a one-shot daemon Timer, scheduled
            # after both providers are already built/registered above, that
            # fires once at a random point within one export interval and
            # force-flushes whatever's queued so far. daemon=True means a
            # still-pending timer can never block process exit; any failure
            # is logged, not raised, since this is a traffic-smoothing nicety
            # and must never be the reason telemetry (or the host app) breaks.
            def _startup_jitter_flush():
                try:
                    cls._tracer_provider.force_flush()
                    cls._logger_provider.force_flush()
                except Exception as e:
                    print(f"[Owl24] Startup jitter flush failed: {e}", file=sys.stderr)

            jitter_seconds = random.uniform(0, export_interval_millis / 1000)
            jitter_timer = threading.Timer(jitter_seconds, _startup_jitter_flush)
            jitter_timer.daemon = True
            jitter_timer.start()

            if not disable_console_bridge:
                otel_logger = cls._logger_provider.get_logger("console-bridge")
                root_logger = logging.getLogger()
                root_logger.setLevel(logging.INFO)
                root_logger.addHandler(MaskingAndOtelHandler(otel_logger))

            if not disable_crash_capture:
                cls._setup_crash_capture()

            # No synchronous "APM active" print here anymore: init() itself
            # stays non-blocking, and per-signal + aggregate status (above)
            # now reports real pipeline health asynchronously as each
            # signal's first flush actually resolves, which is a more
            # honest signal than "init() didn't throw".
        except Exception as e:
            print(f"[Owl24] Init failed: {e}", file=sys.stderr)

    @classmethod
    def shutdown(cls):
        print("Shutting down telemetry...")
        if cls._tracer_provider: cls._tracer_provider.shutdown()
        if cls._logger_provider: cls._logger_provider.shutdown()
        if cls._meter_provider: cls._meter_provider.shutdown()
        if cls._system_metrics_instrumentor:
            try:
                cls._system_metrics_instrumentor.uninstrument()
            except Exception as e:
                print(f"[Owl24] Failed to uninstrument system metrics: {e}", file=sys.stderr)
        for instrumentor in cls._active_auto_instrumentors:
            try:
                instrumentor.uninstrument()
            except Exception as e:
                print(f"[Owl24] Failed to uninstrument {instrumentor}: {e}", file=sys.stderr)
        cls._active_auto_instrumentors = []

    @classmethod
    def track_event(cls, name, attributes=None):
        """Task H (competitive-roadmap.md) - marks a discrete event (a
        deploy, a feature-flag flip, a customer-defined business event) so
        it shows up as a marker on the dashboard's time-series charts.
        Fire-and-forget via a background daemon thread (matching owl24-js's
        non-awaited fetch) so a slow/unreachable ingest endpoint never
        blocks the caller's own request path. `attributes` is masked the
        same way span/log attributes are before it ever leaves this process.
        """
        if not cls._event_ingest_config:
            print("[Owl24] track_event() called before init().", file=sys.stderr)
            return
        if not name or not isinstance(name, str):
            print("[Owl24] track_event() requires a non-empty name.", file=sys.stderr)
            return

        config = cls._event_ingest_config
        body = json.dumps({
            "name": name,
            "serviceName": config["service_name"],
            "attributes": _mask_attributes(attributes),
        }).encode("utf-8")

        def _send():
            try:
                request = urllib.request.Request(
                    f"{config['ingest_base_url']}/v1/events",
                    data=body,
                    method="POST",
                    headers={**config["headers"], "Content-Type": "application/json"},
                )
                urllib.request.urlopen(request, timeout=5)
            except Exception as e:
                print(f"[Owl24] track_event() failed: {e}", file=sys.stderr)

        threading.Thread(target=_send, daemon=True).start()

def handle_sigterm(signum, frame):
    Owl24.shutdown()
    sys.exit(0)

signal.signal(signal.SIGTERM, handle_sigterm)