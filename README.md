# BIND9 API Server

[![StandWithUkraine](https://raw.githubusercontent.com/vshymanskyy/StandWithUkraine/main/badges/StandWithUkraine.svg)](https://github.com/vshymanskyy/StandWithUkraine/blob/main/docs/README.md)

[![SWUbanner](https://raw.githubusercontent.com/vshymanskyy/StandWithUkraine/main/banner2-direct.svg)](https://github.com/vshymanskyy/StandWithUkraine/blob/main/docs/README.md)

The BIND9 API Server provides an authenticated REST interface for managing BIND primary and secondary zones and their records. It supports SQLite and MariaDB/MySQL and includes a bundled PHP client with a usage example.

## Included

- SQLite and MariaDB/MySQL support
- Primary and secondary zone management
- A, AAAA, CNAME, MX, NS, PTR, SOA, TXT, SPF and DS record handling
- Bearer-token authentication with hashed server-side tokens
- IPv4/IPv6-aware rate limiting and proxy handling
- Atomic zone writes plus `named-checkzone` and `named-checkconf` validation
- A bundled Guzzle client in [`src/ApiClient.php`](src/ApiClient.php)

## Requirements

- Linux with BIND 9 on the same host
- PHP 8.2 or newer with CLI, PDO and Swoole
- `pdo_sqlite` for SQLite or `pdo_mysql` for MariaDB/MySQL
- Composer
- `rndc`, `named-checkconf` and `named-checkzone`
- A TLS reverse proxy such as Caddy for remote access

Follow the [installation guide](install.md) for Ubuntu, Debian, Red Hat Enterprise Linux, AlmaLinux and Rocky Linux.

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

## Support

Your feedback and inquiries are invaluable to Namingo's evolutionary journey. If you need support, have questions, or want to contribute your thoughts:

- **Email**: Feel free to reach out directly at [help@namingo.org](mailto:help@namingo.org).

- **Discord**: Or chat with us on our [Discord](https://discord.gg/97R9VCrWgc) channel.
  
- **GitHub Issues**: For bug reports or feature requests, please use the [Issues](https://github.com/getnamingo/bind9-api/issues) section of our GitHub repository.

We appreciate your involvement and patience as BIND9 API Server continues to grow and adapt.

## Support This Project

If you find BIND9 API Server useful, consider donating:

- [Donate via Stripe](https://donate.stripe.com/7sI2aI4jV3Offn28ww)
- BTC: `bc1q9jhxjlnzv0x4wzxfp8xzc6w289ewggtds54uqa`
- ETH: `0x330c1b148368EE4B8756B176f1766d52132f0Ea8`

## Licensing

BIND9 API Server is licensed under the MIT License.