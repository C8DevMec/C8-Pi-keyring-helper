from __future__ import annotations

import getpass
import logging
import logging.handlers
import os
from typing import Optional, Tuple

import keyring

# One shared name for where secrets live in the OS keyring. 
# For Windows: Windows Credential Manager
SERVICE_NAME = os.getenv("KEYRING_SERVICE", "pi-weblogger")

# Optional: allow multiple credential sets (prod/test/etc.)
DEFAULT_ACCOUNT = os.getenv("KEYRING_ACCOUNT", "prod")

ENV_USER = "PI_USER"
ENV_PASS = "PI_PASS"
ENV_LOG_FILE = "PI_SECRETS_LOG"


class MissingSecretError(RuntimeError):
    pass


def _get_logger() -> logging.Logger:
    logger = logging.getLogger("pi_weblogger.secrets")
    logger.setLevel(logging.ERROR)
    logger.propagate = False

    if any(isinstance(h, logging.FileHandler) for h in logger.handlers):
        return logger

    log_path = os.getenv(ENV_LOG_FILE, "pi-secrets-errors.log")
    try:
        handler = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=1_000_000,
            backupCount=3,
            encoding="utf-8",
        )
        handler.setLevel(logging.ERROR)
        handler.setFormatter(logging.Formatter("%(asctime)s %(name)s %(levelname)s: %(message)s"))
        logger.addHandler(handler)
    except Exception:
        logger.addHandler(logging.NullHandler())
        return logger

    return logger


def _env_credentials() -> Optional[Tuple[str, str]]:
    u = os.getenv(ENV_USER)
    p = os.getenv(ENV_PASS)
    if u and p:
        return u, p
    return None


def _key_names(account: str) -> Tuple[str, str]:
    # We store username and password under stable keys.
    # keyring uses (service, username) -> password
    user_key = f"{account}:username"
    pass_key = f"{account}:password"
    return user_key, pass_key


def set_basic_auth(account: str = DEFAULT_ACCOUNT, username: Optional[str] = None, password: Optional[str] = None) -> None:
    """
    Stores credentials into the OS keyring.
    Run once per machine/user (or service account).
    """
    user_key, pass_key = _key_names(account)

    username = username or input("PI Username: ").strip()
    password = password or getpass.getpass("PI Password: ")

    keyring.set_password(SERVICE_NAME, user_key, username)
    keyring.set_password(SERVICE_NAME, pass_key, password)


def get_basic_auth(account: str = DEFAULT_ACCOUNT, *, interactive_bootstrap: bool = False) -> Tuple[str, str]:
    """
    Returns (username, password).

    Priority:
      1) Env vars PI_USER/PI_PASS
      2) OS keyring
      3) (optional) prompt + store if interactive_bootstrap=True
    """
    env = _env_credentials()
    if env:
        return env

    user_key, pass_key = _key_names(account)
    username = keyring.get_password(SERVICE_NAME, user_key)
    password = keyring.get_password(SERVICE_NAME, pass_key)

    if username and password:
        return username, password

    if interactive_bootstrap:
        # Useful for running a script manually the first time
        set_basic_auth(account=account)
        username = keyring.get_password(SERVICE_NAME, user_key)
        password = keyring.get_password(SERVICE_NAME, pass_key)
        if username and password:
            return username, password

    _get_logger().error(
        "Missing credentials for service='%s', account='%s'.",
        SERVICE_NAME,
        account,
    )
    raise MissingSecretError(
        f"Missing credentials for service='{SERVICE_NAME}', account='{account}'."
    )


def requests_auth(account: str = DEFAULT_ACCOUNT) -> Tuple[str, str]:
    """
    Convenience for requests: requests.get(url, auth=requests_auth())
    """
    return get_basic_auth(account)


def requests_session(account: str = DEFAULT_ACCOUNT):
    """
    Convenience: a pre-authenticated requests.Session().
    Use when scripts call PI Web API multiple times.
    """
    import requests  # local import to avoid forcing requests everywhere
    s = requests.Session()
    s.auth = get_basic_auth(account)
    return s

def delete_basic_auth(account: str = DEFAULT_ACCOUNT) -> None:
    """
    Deletes credentials from keyring.
    """
    user_key, pass_key = _key_names(account)

    try:
        keyring.delete_password(SERVICE_NAME, user_key)
    except keyring.errors.PasswordDeleteError:
        pass

    try:
        keyring.delete_password(SERVICE_NAME, pass_key)
    except keyring.errors.PasswordDeleteError:
        pass
