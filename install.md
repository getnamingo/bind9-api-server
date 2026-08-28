# Installation guide

Commands assume root privileges; prefix them with `sudo` when working from an administrator account.

The API must run on the BIND 9 host because it writes zone files, updates one included BIND configuration file, validates both, and calls `rndc`. It should listen only on loopback and be exposed remotely through HTTPS.

Use it only for static file-backed primary zones. Do not mix these file rewrites with dynamic DNS updates or `.jnl`-managed zones.

## 1. Install packages

### Ubuntu

```bash
apt update
apt install -y software-properties-common
add-apt-repository -y ppa:ondrej/php
apt update
apt install -y \
  acl bind9 bind9utils composer git sqlite3 unzip \
  php8.3-cli php8.3-curl php8.3-mbstring php8.3-mysql \
  php8.3-opcache php8.3-sqlite3 php8.3-swoole php8.3-xml
```

### Debian

Use Debian's packages when they contain a recent Swoole, or configure the maintained [Sury PHP repository](https://packages.sury.org/php/) and install the same versioned PHP packages shown above:

```bash
apt update
apt install -y \
  acl bind9 bind9utils composer git sqlite3 unzip \
  php-cli php-curl php-mbstring php-mysql php-opcache \
  php-sqlite3 php-swoole php-xml
```

### RHEL, AlmaLinux or Rocky Linux 9

Enable EPEL and Remi, then select a supported PHP stream. Remi currently names the Swoole 6 package `php-pecl-swoole6`.

```bash
dnf install -y epel-release
dnf install -y https://rpms.remirepo.net/enterprise/remi-release-9.rpm
dnf module reset -y php
dnf module enable -y php:remi-8.3
dnf install -y \
  bind bind-utils composer git policycoreutils-python-utils sqlite unzip \
  php-cli php-common php-mbstring php-mysqlnd php-opcache php-pdo \
  php-pecl-swoole6 php-process php-sqlite3 php-xml
```

Red Hat's BIND packages and SELinux guidance are documented in the [RHEL 9 BIND guide](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/managing_networking_infrastructure_services/assembly_setting-up-and-configuring-a-bind-dns-server_networking-infrastructure-services).

Verify the runtime before continuing:

```bash
php --version
php --ri swoole
php -m | grep -E 'PDO|pdo_mysql|pdo_sqlite|swoole'
named-checkconf -v
```

Install only the PDO driver you intend to use if you prefer a smaller system. Keeping both makes later database switching easier.

## 2. Create the service account and install the code

```bash
git clone https://github.com/getnamingo/bind9-api-server.git /opt/bind9_api
```

Then finish the installation:

```bash
useradd --system --home-dir /nonexistent --shell "$(command -v nologin)" bind9-api
cd /opt/bind9_api
composer install --no-dev --classmap-authoritative
cp env-sample .env
chown -R root:bind9-api /opt/bind9_api
find /opt/bind9_api -type d -exec chmod 0750 {} +
find /opt/bind9_api -type f -exec chmod 0640 {} +
chmod 0750 /opt/bind9_api/create_user.php
chmod 0640 /opt/bind9_api/.env
install -d -o bind9-api -g bind9-api -m 0750 /var/lib/bind9-api
install -d -o bind9-api -g bind9-api -m 0750 /var/log/plexdns
```

Composer executables under `vendor/bin` may need execute bits restored if you use them; the production server itself does not require them.

Edit `/opt/bind9_api/.env`. At minimum, replace the example SOA email, nameservers, database credentials, and any distribution-specific BIND paths.

Keep these production defaults unless your architecture requires otherwise:

```dotenv
DEBUG_MODE=false
API_HOST=127.0.0.1
API_PORT=7650
WORKER_NUM=1
RATELY=true
SESSION_BIND_IP=true
TRUSTED_PROXIES=127.0.0.1,::1
```

`WORKER_NUM=1` intentionally serializes low-volume zone-file mutations. Do not raise it unless you provide external per-zone locking.

## 3. Grant narrowly scoped BIND access

The API does not use `sudo` and must not run as root. It needs write access only to its BIND include file and zone directory, plus read access to the local RNDC key.

### Ubuntu or Debian paths

The main `/etc/bind/named.conf` already includes `/etc/bind/named.conf.local` on a standard installation. Keep that file root-owned and add a separate API-managed include:

```bash
usermod -aG bind bind9-api
install -d -o bind9-api -g bind -m 2750 /etc/bind/zones
touch /etc/bind/bind9-api.conf
chown bind9-api:bind /etc/bind/bind9-api.conf
chmod 0640 /etc/bind/bind9-api.conf
grep -Fqx 'include "/etc/bind/bind9-api.conf";' /etc/bind/named.conf.local \
  || printf '\ninclude "/etc/bind/bind9-api.conf";\n' >> /etc/bind/named.conf.local
```

Use these `.env` values:

```dotenv
BIND9_ZONE_DIR=/etc/bind/zones
BIND9_CONF_FILE=/etc/bind/bind9-api.conf
BIND9_MAIN_CONF=/etc/bind/named.conf
BIND9_SLAVE_DIR=/var/cache/bind
RNDC_BIN=/usr/sbin/rndc
NAMED_CHECKCONF_BIN=/usr/sbin/named-checkconf
NAMED_CHECKZONE_BIN=/usr/sbin/named-checkzone
BIND9_VALIDATE=true
```

### Red Hat family paths and SELinux

Create a dedicated include and zone directory:

```bash
usermod -aG named bind9-api
install -d -o root -g named -m 0750 /etc/named
touch /etc/named/bind9-api.conf
chown bind9-api:named /etc/named/bind9-api.conf
chmod 0640 /etc/named/bind9-api.conf
install -d -o bind9-api -g named -m 2750 /var/named/bind9-api
```

Add this once, outside the `options` block, to `/etc/named.conf`:

```bind
include "/etc/named/bind9-api.conf";
```

Apply BIND SELinux labels:

```bash
semanage fcontext -a -t named_conf_t '/etc/named/bind9-api\.conf'
semanage fcontext -a -t named_zone_t '/var/named/bind9-api(/.*)?'
restorecon -RFv /etc/named/bind9-api.conf /var/named/bind9-api
```

Use these `.env` values:

```dotenv
BIND9_ZONE_DIR=/var/named/bind9-api
BIND9_CONF_FILE=/etc/named/bind9-api.conf
BIND9_MAIN_CONF=/etc/named.conf
BIND9_SLAVE_DIR=/var/named/slaves
RNDC_BIN=/usr/sbin/rndc
NAMED_CHECKCONF_BIN=/usr/sbin/named-checkconf
NAMED_CHECKZONE_BIN=/usr/sbin/named-checkzone
BIND9_VALIDATE=true
```

### Verify BIND access

Restart BIND so group membership and configuration changes are active, then test as the API account:

```bash
named-checkconf
systemctl restart bind9 2>/dev/null || systemctl restart named
runuser -u bind9-api -- /usr/sbin/rndc status
```

If RNDC reports a key permission error, find the key referenced by your `rndc.conf`/`named.conf` and make it group-readable by `bind` on Debian-family systems or `named` on Red Hat-family systems. Do not make the key world-readable.

## 4. Select and initialize a database

Choose exactly one backend.

### Option A: SQLite

Set:

```dotenv
DB_TYPE=sqlite
DB_DATABASE=/var/lib/bind9-api/bind9_api.sqlite
DB_BUSY_TIMEOUT=5000
```

Initialize it:

```bash
runuser -u bind9-api -- sqlite3 /var/lib/bind9-api/bind9_api.sqlite < /opt/bind9_api/database/sqlite.sql
chown bind9-api:bind9-api /var/lib/bind9-api/bind9_api.sqlite
chmod 0640 /var/lib/bind9-api/bind9_api.sqlite
```

WAL mode and foreign-key enforcement are enabled by both the schema and the application.

### Option B: MariaDB/MySQL

Install a local MariaDB/MySQL server if one is not already available. Then create a database and a loopback-only account from the database console:

```sql
CREATE DATABASE bind9_api CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'bind9_api'@'127.0.0.1' IDENTIFIED BY 'REPLACE_WITH_A_LONG_RANDOM_PASSWORD';
GRANT SELECT, INSERT, UPDATE, DELETE ON bind9_api.* TO 'bind9_api'@'127.0.0.1';
FLUSH PRIVILEGES;
```

Import the schema:

```bash
mysql --database=bind9_api < /opt/bind9_api/database/mysql.sql
```

Set matching values:

```dotenv
DB_TYPE=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=bind9_api
DB_USERNAME=bind9_api
DB_PASSWORD=REPLACE_WITH_A_LONG_RANDOM_PASSWORD
```

MariaDB uses the `mysql` PDO driver name; do not set `DB_TYPE=mariadb` in new configurations, although the code accepts it as an alias.

## 5. Create the first API user

The script reads the password from standard input so it is neither committed to the source nor placed in a command-line argument:

```bash
read -rsp 'API password: ' API_USER_PASSWORD
printf '%s' "$API_USER_PASSWORD" | runuser -u bind9-api -- php /opt/bind9_api/create_user.php admin
unset API_USER_PASSWORD
```

## 6. Install and start the systemd service

```bash
cp /opt/bind9_api/bind9_api.service /etc/systemd/system/bind9_api.service
systemctl daemon-reload
systemctl enable --now bind9_api.service
systemctl status bind9_api.service
```

Confirm it is listening only on loopback:

```bash
ss -lntp | grep ':7650'
journalctl -u bind9_api.service -n 50 --no-pager
```

Test login locally:

```bash
curl --fail-with-body --silent --show-error \
  --request POST http://127.0.0.1:7650/login \
  --header 'Content-Type: application/json' \
  --data '{"username":"admin","password":"YOUR_PASSWORD"}'
```

## 7. Put HTTPS in front of the API

Install Caddy using its [official distribution instructions](https://caddyserver.com/docs/install), point a DNS name to the server, and use this Caddyfile:

```caddyfile
api.example.com {
    reverse_proxy 127.0.0.1:7650
    encode zstd gzip

    header {
        -Server
        Cache-Control "no-store"
        Content-Security-Policy "default-src 'none'; frame-ancestors 'none'"
        Referrer-Policy "no-referrer"
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
    }
}
```

Validate and reload:

```bash
caddy validate --config /etc/caddy/Caddyfile
systemctl reload caddy
```

Allow only ports 80/443 at the host or provider firewall. Do not expose port 7650. If Caddy runs on another host, bind the API only to a private address, restrict the firewall to that proxy, and set `TRUSTED_PROXIES` to the proxy's exact IP/CIDR.

## 8. Use the bundled PHP client

The server's Composer install already installs Guzzle and autoloads `Namingo\Bind9Api\ApiClient`; no second repository is needed.

Run the included example:

```bash
cd /opt/bind9_api
export BIND9_API_URL='https://api.example.com'
export BIND9_API_USERNAME='admin'
read -rsp 'API password: ' BIND9_API_PASSWORD
export BIND9_API_PASSWORD
php examples/client_example.php
unset BIND9_API_PASSWORD
```

Minimal application code:

```php
<?php

require '/opt/bind9_api/vendor/autoload.php';

use Namingo\Bind9Api\ApiClient;

$api = new ApiClient('https://api.example.com');
$api->login('admin', getenv('BIND9_API_PASSWORD'));

$api->addZone('example.com');
$api->addRecord('example.com', [
    'name' => 'www',
    'type' => 'A',
    'ttl' => 3600,
    'rdata' => '192.0.2.10',
]);

print_r($api->getRecords('example.com'));
```

The client URL-encodes zone path segments, validates JSON responses, catches Guzzle transport errors correctly, and refuses authenticated API calls until `login()` succeeds.

## 9. Upgrade from either old server

1. Back up the BIND include file, zone directory, `.env`, and database.
2. Stop the old API service.
3. Deploy the unified code and run `composer install --no-dev --classmap-authoritative`.
4. Copy new variables from `env-sample` into the existing `.env`; select its current database using `DB_TYPE`. Keep the old `BIND9_CONF_FILE` value if that file already contains API-managed zone blocks, or move those blocks into the new dedicated include before changing the path.
5. For an existing MariaDB/MySQL database, run:

   ```bash
   mysql --database=bind9_api < database/migrate-mysql-ipv6.sql
   ```

   This converts stored IP columns to IPv4/IPv6-safe text and makes usernames case-sensitive. SQLite needs no destructive migration; re-run its idempotent schema to add the session-expiry index if it is missing:

   ```bash
   runuser -u bind9-api -- sqlite3 /var/lib/bind9-api/bind9_api.sqlite \
     < database/sqlite.sql
   ```

6. Install the new systemd unit and apply the non-root BIND permissions described above.
7. Start the service and test login plus one read operation before attempting changes.

Existing one-hour sessions intentionally stop working after this upgrade because new deployments store only token hashes. Log in again. API users, passwords, zones and records remain intact.

## 10. Validation and troubleshooting

Run the project checks after installation or an upgrade:

```bash
cd /opt/bind9_api
composer validate --strict
find . -path ./vendor -prune -o -name '*.php' -print0 | xargs -0 -n1 php -l
composer test
```

Useful diagnostics:

```bash
journalctl -u bind9_api.service -f
runuser -u bind9-api -- /usr/sbin/named-checkconf /etc/bind/named.conf
runuser -u bind9-api -- /usr/sbin/rndc status
```

On Red Hat-family systems, inspect SELinux denials rather than disabling SELinux:

```bash
ausearch -m AVC -ts recent
```

Common causes of startup failure are a missing database schema, an unwritable SQLite directory, incorrect MySQL credentials, an unreadable RNDC key, a BIND path that does not match `.env`, or a PHP CLI configuration that has not loaded Swoole/PDO.
