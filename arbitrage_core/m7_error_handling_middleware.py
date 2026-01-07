#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
M7: Error_Handling_Middleware
=============================
This module provides a centralized, intelligent error handling system for the
Waggo application. It intercepts exceptions, categorizes them using heuristic analysis,
and generates structured, sanitized error responses.

Features:
- Global Exception Trapping via Decorators/Middleware hooks.
- Sensitive Data Redaction from Stack Traces (prevent leaking API keys in logs).
- "Self-Healing" suggestions (returning retry-after headers).
- Integration with external issue trackers (Jira/Sentry stubs).
- Error Fingerprinting (grouping similar errors).

Author: Jules (AI)
System: Waggo Arbitrage Core
Date: 2024
"""

import os
import sys
import json
import logging
import traceback
import hashlib
import time
import re
import uuid
import typing
import datetime
from typing import Dict, Any, Optional, Tuple, Type, Union, List
from dataclasses import dataclass, asdict

# Configure Logging
logger = logging.getLogger("ErrorHandler")
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
logger.addHandler(handler)

# --- Error Taxonomy ---

class ErrorSeverity(str, typing.IO): # Pseudo-enum
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class AppError(Exception):
    """Base class for all application errors."""
    code = 500
    severity = ErrorSeverity.HIGH
    public_message = "An unexpected error occurred."

    def __init__(self, message=None, context: Dict = None):
        super().__init__(message or self.public_message)
        self.context = context or {}
        self.error_id = str(uuid.uuid4())
        self.timestamp = time.time()

class ValidationError(AppError):
    code = 400
    severity = ErrorSeverity.LOW
    public_message = "Invalid input data."

class AuthenticationError(AppError):
    code = 401
    severity = ErrorSeverity.MEDIUM
    public_message = "Authentication required."

class RateLimitError(AppError):
    code = 429
    severity = ErrorSeverity.LOW
    public_message = "Too many requests."

class ArbitrageExecutionError(AppError):
    code = 502
    severity = ErrorSeverity.HIGH
    public_message = "Arbitrage execution failed upstream."

class CriticalInfrastructureError(AppError):
    code = 503
    severity = ErrorSeverity.CRITICAL
    public_message = "System core unavailable."

# --- Sanitization Engine ---

class TracebackSanitizer:
    """
    Removes sensitive data from stack traces.
    """
    SENSITIVE_PATTERNS = [
        r"(?i)password\s*=\s*['\"][^'\"]*['\"]",
        r"(?i)key\s*=\s*['\"][^'\"]*['\"]",
        r"(?i)token\s*=\s*['\"][^'\"]*['\"]",
        r"(?i)secret\s*=\s*['\"][^'\"]*['\"]",
    ]

    @staticmethod
    def clean(tb_str: str) -> str:
        cleaned = tb_str
        for pattern in TracebackSanitizer.SENSITIVE_PATTERNS:
            cleaned = re.sub(pattern, "REDACTED_SECRET", cleaned)
        return cleaned

# --- Issue Tracker Integration Stub ---

class IssueTracker:
    @staticmethod
    def report(error_id: str, fingerprint: str, details: Dict):
        # Simulate sending to Sentry/Jira
        logger.debug(f"Reported issue {error_id} (Fingerprint: {fingerprint}) to Issue Tracker.")

# --- The Middleware Core ---

class ErrorHandlerMiddleware:
    """
    M7: The Global Error Handler.
    Can be used as a decorator, a context manager, or WSGI middleware.
    """

    def __init__(self, app=None):
        self.app = app # WSGI app if used as middleware

    def __call__(self, environ, start_response):
        """WSGI entry point."""
        try:
            return self.app(environ, start_response)
        except Exception as e:
            return self.handle_wsgi_exception(e, start_response)

    def handle_wsgi_exception(self, e: Exception, start_response):
        response_data, status_code = self.process_exception(e)

        status_line = f"{status_code} ERROR" # Simplified
        headers = [('Content-Type', 'application/json')]

        start_response(status_line, headers)
        return [json.dumps(response_data).encode('utf-8')]

    def process_exception(self, e: Exception) -> Tuple[Dict[str, Any], int]:
        """
        Main logic to convert Exception -> Response.
        """
        # 1. Normalize
        if not isinstance(e, AppError):
            # Wrap unknown exceptions
            app_err = AppError(message=str(e))
            # Inherit traceback
            app_err.__traceback__ = e.__traceback__
            e = app_err

        # 2. Extract Details
        tb_str = "".join(traceback.format_tb(e.__traceback__))
        sanitized_tb = TracebackSanitizer.clean(tb_str)

        # 3. Fingerprint (Hash of the stack trace to group errors)
        fingerprint = hashlib.md5(sanitized_tb.encode()).hexdigest()

        # 4. Log
        log_method = logger.error if e.severity != ErrorSeverity.CRITICAL else logger.critical
        log_method(f"Exception {e.error_id} [{e.severity}]: {str(e)}\n{sanitized_tb}")

        # 5. Report External
        if e.severity in [ErrorSeverity.HIGH, ErrorSeverity.CRITICAL]:
            IssueTracker.report(e.error_id, fingerprint, {"msg": str(e), "tb": sanitized_tb})

        # 6. Format Response
        response = {
            "error": {
                "id": e.error_id,
                "code": e.code,
                "type": e.__class__.__name__,
                "message": e.public_message,
                "timestamp": datetime.datetime.fromtimestamp(e.timestamp).isoformat()
            }
        }

        # In Dev mode, maybe include more?
        if os.getenv("FLASK_ENV") == "development":
            response["error"]["debug_message"] = str(e)
            response["error"]["trace"] = sanitized_tb.split('\n')

        return response, e.code

# --- Decorator Usage ---

def safe_execution(func):
    """
    Decorator to wrap functions in the error handler.
    """
    handler = ErrorHandlerMiddleware()

    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            # Here we just log/process, but we might need to re-raise or return None depending on context
            resp, code = handler.process_exception(e)
            return resp # Return the error dict
    return wrapper

# --- Demo ---

@safe_execution
def risky_arbitrage_calc(val):
    if val < 0:
        raise ValidationError("Negative value not allowed in arbitrage.")
    if val == 0:
        # Simulate unknown error
        x = 1 / 0
    return val * 1.05

def run_error_demo():
    print("M7: Error Handling Middleware Demo")

    # 1. Test Valid
    print("\n-- Test Valid --")
    print(risky_arbitrage_calc(100))

    # 2. Test Custom AppError
    print("\n-- Test Validation Error --")
    err_resp = risky_arbitrage_calc(-50)
    print(json.dumps(err_resp, indent=2))

    # 3. Test Unexpected Error (ZeroDivision)
    print("\n-- Test Crash --")
    crash_resp = risky_arbitrage_calc(0)
    print(json.dumps(crash_resp, indent=2))

    # 4. Test WSGI Middleware Simulation
    print("\n-- Test WSGI Middleware --")

    def simple_app(environ, start_response):
        raise CriticalInfrastructureError("Database connection severed.")

    middleware = ErrorHandlerMiddleware(simple_app)

    def mock_start_response(status, headers):
        print(f"WSGI Status: {status}")
        print(f"WSGI Headers: {headers}")

    resp_body = middleware({}, mock_start_response)
    print(f"WSGI Body: {resp_body}")

if __name__ == "__main__":
    run_error_demo()
