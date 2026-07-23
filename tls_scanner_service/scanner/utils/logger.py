"""Structured logging for scanner modules."""

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Optional


class StructuredFormatter(logging.Formatter):
    """Outputs structured JSON log records."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, "module_name"):
            log_entry["module"] = record.module_name
        if hasattr(record, "duration_ms"):
            log_entry["duration_ms"] = record.duration_ms
        if hasattr(record, "host"):
            log_entry["host"] = record.host
        if record.exc_info and record.exc_info[0]:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)


def get_logger(name: str, level: str = "INFO") -> logging.Logger:
    """Get a structured logger instance."""
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(StructuredFormatter())
        logger.addHandler(handler)

    return logger


# Global scanner logger
scanner_log = get_logger("tls_scanner")

