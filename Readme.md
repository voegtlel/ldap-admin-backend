# Server for ldap admin

## Development server

Run `python run.py` for a dev server.

## Deployment server

Use a WGSI server and import `server.app`.

## Docker

Run `docker build`.

## Configuration

You can override any config variable by setting the environment variable `api_config_<variable_name>`.
E.g.: `API_CONFIG_LDAP_SERVERURI=ldap://myldapserver:389` (casing of the variable is ignored).

