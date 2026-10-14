"""Logging: human-readable text locally, one JSON object per line in production
(Container Apps ships stdout to Log Analytics, where JSON fields are queryable).

Also used by gunicorn (see gunicorn.conf.py) so server and access logs share
the format.
"""
from __future__ import annotations

import json
import logging
import logging.config
from datetime import UTC, datetime
from typing import Any

TEXT_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"

# Attributes every LogRecord has; anything else was passed via `extra=` and is
# included in the JSON output.
_STANDARD_ATTRS = set(vars(logging.LogRecord("", 0, "", 0, "", None, None))) | {
    "message", "asctime", "taskName", "color_message"}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in vars(record).items():
            if key not in _STANDARD_ATTRS and not key.startswith("_"):
                out[key] = value if isinstance(value, str | int | float | bool | type(None)) else str(value)
        if record.exc_info:
            out["exception"] = self.formatException(record.exc_info)
        if record.stack_info:
            out["stack"] = self.formatStack(record.stack_info)
        return json.dumps(out, ensure_ascii=False)


def dict_config(fmt: str = "text", level: str = "INFO") -> dict[str, Any]:
    formatter = {"()": JsonFormatter} if fmt == "json" else {"format": TEXT_FORMAT}
    handler = {"class": "logging.StreamHandler", "formatter": "default", "stream": "ext://sys.stdout"}
    return {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {"default": formatter},
        "handlers": {"default": handler},
        "root": {"handlers": ["default"], "level": level},
        "loggers": {
            # Let server loggers propagate to the root handler (single format).
            name: {"handlers": [], "propagate": True, "level": level}
            for name in ("uvicorn", "uvicorn.error", "uvicorn.access", "gunicorn.error", "gunicorn.access")
        } | {
            # Azure SDK HTTP logging is very chatty at INFO.
            "azure": {"handlers": [], "propagate": True, "level": "WARNING"},
        },
    }


def configure(fmt: str = "text", level: str = "INFO") -> None:
    logging.config.dictConfig(dict_config(fmt, level))
