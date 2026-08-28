# BIND9 API Server

The BIND9 API Server provides an authenticated REST interface for managing BIND primary and secondary zones and their records. This unified edition supports either SQLite or MariaDB/MySQL from the same codebase and includes the PHP client that was previously maintained separately.

The HTTP API and existing payload shapes remain compatible with:

- `getnamingo/bind9-api-server`
- `getnamingo/bind9-api-server-sqlite`
- `getnamingo/bind9-api-client`

## Included

- SQLite and MariaDB/MySQL selected with `DB_TYPE`
- Primary and secondary zone management
- A, AAAA, CNAME, MX, NS, PTR, SOA, TXT, SPF and DS record handling
- Bearer-token authentication with hashed server-side tokens
- IPv4/IPv6-aware rate limiting and proxy handling
- Atomic zone writes plus `named-checkzone` and `named-checkconf` validation
- A bundled Guzzle client in [`src/ApiClient.php`](src/ApiClient.php)
- A hardened, non-root systemd unit

## Requirements

- Linux with BIND 9 on the same host
- PHP 8.2 or newer with CLI, PDO and Swoole
- `pdo_sqlite` for SQLite or `pdo_mysql` for MariaDB/MySQL
- Composer
- `rndc`, `named-checkconf` and `named-checkzone`
- A TLS reverse proxy such as Caddy for remote access

Follow the single [installation and client guide](install.md) for Ubuntu, Debian, Red Hat Enterprise Linux, AlmaLinux and Rocky Linux.

## Database selection

SQLite is the simplest choice for a single DNS node:

```dotenv
DB_TYPE=sqlite
DB_DATABASE=/var/lib/bind9-api/bind9_api.sqlite
```

MariaDB/MySQL is preferable when database operations, backups or existing infrastructure require it:

```dotenv
DB_TYPE=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=bind9_api
DB_USERNAME=bind9_api
DB_PASSWORD=replace-with-a-long-random-password
```

## API

All routes except `POST /login` require `Authorization: Bearer TOKEN`.

| Method | Route | Purpose |
| --- | --- | --- |
| `POST` | `/login` | Obtain a one-hour bearer token by default |
| `GET` / `POST` | `/zones` | List or create primary zones |
| `DELETE` | `/zones/{zone}` | Delete a primary zone |
| `GET` / `POST` | `/slave-zones` | List or create secondary zones |
| `DELETE` | `/slave-zones/{zone}` | Delete a secondary zone |
| `GET` / `POST` | `/zones/{zone}/records` | List or create records |
| `PUT` | `/zones/{zone}/records/update` | Update one identified record |
| `DELETE` | `/zones/{zone}/records/delete` | Delete one identified record |

Login example:

```bash
curl --fail-with-body --silent --show-error \
  --request POST https://api.example.com/login \
  --header 'Content-Type: application/json' \
  --data '{"username":"admin","password":"replace-me"}'
```

Create an A record:

```json
{
  "name": "www",
  "type": "A",
  "ttl": 3600,
  "rdata": "192.0.2.10"
}
```

MX and DS use structured RDATA:

```json
{
  "name": "@",
  "type": "MX",
  "ttl": 3600,
  "rdata": {
    "preference": 10,
    "exchange": "mail.example.com."
  }
}
```

```json
{
  "name": "@",
  "type": "DS",
  "ttl": 3600,
  "rdata": {
    "keytag": 2371,
    "algorithm": 8,
    "digestType": 2,
    "digest": "5E2B4D2C35B2EFA8F2C1D9C4A2DFF5B2904B529A3F1E9E3A56E4F4E6C7B92DF2"
  }
}
```

## Security model

The sample configuration binds the API to `127.0.0.1:7650`. Keep that port private and expose only the TLS reverse proxy. The service runs as `bind9-api`, validates every generated BIND file before activation, stores only SHA-256 hashes of active bearer tokens, defaults to rate limiting, and does not return internal exception details unless `DEBUG_MODE=true`.

`TRUSTED_PROXIES` controls which direct peers may supply `X-Forwarded-For`; never add arbitrary public networks. `SESSION_BIND_IP=true` also prevents a stolen token from being reused from another client IP.

The API rewrites static primary-zone files. Do not point it at zones maintained through dynamic DNS updates and `.jnl` journals; use one writer or a purpose-built dynamic-update workflow for those zones.

## Testing

After installing dependencies:

```bash
composer validate --strict
find . -path ./vendor -prune -o -name '*.php' -print0 | xargs -0 -n1 php -l
composer test
```

## Support and license

- Email: [help@namingo.org](mailto:help@namingo.org)
- Discord: [Namingo community](https://discord.gg/97R9VCrWgc)
- Issues: use the repository's GitHub Issues page

Licensed under the [MIT License](LICENSE).
