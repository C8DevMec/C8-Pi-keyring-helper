# secrets.py
from __future__ import annotations

import getpass
import os
from typing import Optional, Tuple

import keyring

# One shared name for where secrets live in the OS keyring.
# You can change this without touching scripts.
SERVICE_NAME = os.getenv("KEYRING_SERVICE", "pi-weblogger")

# Optional: allow multiple credential sets (prod/test/etc.)
DEFAULT_ACCOUNT = os.getenv("KEYRING_ACCOUNT", "prod")

# Env override (handy for CI/emergency). If set, these win.
ENV_USER = "PI_USER"
ENV_PASS = "PI_PASS"


class MissingSecretError(RuntimeError):
    pass


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

    raise MissingSecretError(
        f"Missing credentials.\n"
        f"- Set env vars {ENV_USER}/{ENV_PASS}, OR\n"
        f"- Run: python -c \"import secrets; secrets.set_basic_auth('{account}')\"\n"
        f"(service='{SERVICE_NAME}', account='{account}')"
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