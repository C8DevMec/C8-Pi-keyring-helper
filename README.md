# PI Auth Module

Small helper for storing and retrieving PI credentials via OS keyring or env vars.

## Setup

Option A: Environment variables

- `PI_USER`
- `PI_PASS`

Option B: OS keyring (recommended for local use)

```bash
python -c "import secrets; secrets.set_basic_auth()"
```

To delete stored credentials

```python
import keyring
import secrets

user_key, pass_key = secrets._key_names(secrets.DEFAULT_ACCOUNT)
keyring.delete_password(secrets.SERVICE_NAME, user_key)
keyring.delete_password(secrets.SERVICE_NAME, pass_key)
```

## Usage

```python
import requests
import secrets

url = "https://example/pi"

# one-off request
r = requests.get(url, auth=secrets.requests_auth())
print(r.status_code)

# session (multiple calls)
s = secrets.requests_session()
r = s.get(url)
print(r.status_code)
```
