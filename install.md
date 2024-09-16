# Installation Guide (Ubuntu 22.04/Ubuntu 24.04/Debian 12)

**NB! The API server must be installed on a server where is running BIND9 as master DNS.**

## 1. Install the required packages:

```bash
apt install -y curl software-properties-common ufw
add-apt-repository ppa:ondrej/php
apt update
apt install -y bzip2 composer git net-tools php8.3 php8.3-bz2 php8.3-cli php8.3-common php8.3-curl php8.3-fpm php8.3-gd php8.3-gmp php8.3-imagick php8.3-intl php8.3-mbstring php8.3-opcache php8.3-readline php8.3-soap php8.3-swoole php8.3-xml unzip wget whois
```

### Configure PHP:

Edit the PHP Configuration Files:

```bash
nano /etc/php/8.3/cli/php.ini
nano /etc/php/8.3/fpm/php.ini
```

Locate or add these lines in ```php.ini```, also replace ```example.com``` with your registrar domain name:

```bash
opcache.enable=1
opcache.enable_cli=1
opcache.jit_buffer_size=100M
opcache.jit=1255

session.cookie_secure = 1
session.cookie_httponly = 1
session.cookie_samesite = "Strict"
session.cookie_domain = example.com
```

In ```/etc/php/8.3/mods-available/opcache.ini``` make one additional change:

```bash
opcache.jit=1255
opcache.jit_buffer_size=100M
```

After configuring PHP, restart the service to apply changes:

```bash
systemctl restart php8.3-fpm
```

## 2. Install and Configure Caddy:

1. Execute the following commands:

```bash
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' -o caddy-stable.gpg.key
gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg caddy-stable.gpg.key
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
apt update
apt install -y caddy
```

2. Edit `/etc/caddy/Caddyfile` and place the following content:

```bash
api.example.com {
    bind YOUR_IPV4_ADDRESS YOUR_IPV6_ADDRESS
    reverse_proxy localhost:7650
    encode gzip
    file_server
    tls your-email@example.com
    header -Server
    header * {
        Referrer-Policy "no-referrer"
        Strict-Transport-Security max-age=31536000;
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
        X-XSS-Protection "1; mode=block"
        Content-Security-Policy "default-src 'none'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; img-src https:; font-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'none'; form-action 'self'; worker-src 'none'; frame-src 'none';"
        Feature-Policy "accelerometer 'none'; autoplay 'none'; camera 'none'; encrypted-media 'none'; fullscreen 'self'; geolocation 'none'; gyroscope 'none'; magnetometer 'none'; microphone 'none'; midi 'none'; payment 'none'; picture-in-picture 'self'; usb 'none';"
        Permissions-Policy: accelerometer=(), autoplay=(), camera=(), encrypted-media=(), fullscreen=(self), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(self), usb=();
    }
}
```

Activate and reload Caddy:

```bash
systemctl enable caddy
systemctl restart caddy
```

## 3. Install MariaDB:

```bash
curl -o /etc/apt/keyrings/mariadb-keyring.pgp 'https://mariadb.org/mariadb_release_signing_key.pgp'
```

### 3.1. Ubuntu 22.04

Place the following in ```/etc/apt/sources.list.d/mariadb.sources```:

```bash
# MariaDB 10.11 repository list - created 2023-12-02 22:16 UTC
# https://mariadb.org/download/
X-Repolib-Name: MariaDB
Types: deb
# deb.mariadb.org is a dynamic mirror if your preferred mirror goes offline. See https://mariadb.org/mirrorbits/ for details.
# URIs: https://deb.mariadb.org/10.11/ubuntu
URIs: https://mirrors.chroot.ro/mariadb/repo/10.11/ubuntu
Suites: jammy
Components: main main/debug
Signed-By: /etc/apt/keyrings/mariadb-keyring.pgp
```

### 3.2. Ubuntu 24.04

Place the following in ```/etc/apt/sources.list.d/mariadb.list```:

```bash
# MariaDB 11.4 repository list - created 2024-07-23 18:24 UTC
# https://mariadb.org/download/
deb [signed-by=/etc/apt/keyrings/mariadb-keyring.pgp] https://fastmirror.pp.ua/mariadb/repo/11.4/ubuntu noble main
```

### 3.3. Debian 12

Place the following in ```/etc/apt/sources.list.d/mariadb.sources```:

```bash
# MariaDB 10.11 repository list - created 2024-01-05 12:23 UTC
# https://mariadb.org/download/
X-Repolib-Name: MariaDB
Types: deb
# deb.mariadb.org is a dynamic mirror if your preferred mirror goes offline. See https://mariadb.org/mirrorbits/ for details.
# URIs: https://deb.mariadb.org/10.11/debian
URIs: https://mirrors.chroot.ro/mariadb/repo/10.11/debian
Suites: bookworm
Components: main
Signed-By: /etc/apt/keyrings/mariadb-keyring.pgp
```

## 4. Configure MariaDB:

1. Execute the following commands:

```bash
apt update
apt install -y mariadb-client mariadb-server php8.3-mysql
mysql_secure_installation
```

2. Access MariaDB:

```bash
mysql -u root -p
```

3. Execute the following queries:

```bash
CREATE DATABASE bind9_api;
CREATE USER 'bind9_api_user'@'localhost' IDENTIFIED BY 'RANDOM_STRONG_PASSWORD';
GRANT ALL PRIVILEGES ON bind9_api.* TO 'bind9_api_user'@'localhost';
FLUSH PRIVILEGES;
```

Replace `bind9_api_user` with your desired username and `RANDOM_STRONG_PASSWORD` with a secure password of your choice.

[Tune your MariaDB](https://github.com/major/MySQLTuner-perl)

## 5. Set File Permissions:

```bash
chown www-data:www-data /etc/bind/named.conf.local
chmod 640 /etc/bind/named.conf.local
chown -R www-data:www-data /etc/bind/zones
chmod -R 640 /etc/bind/zones
```

## 6. Edit the sudoers file:

```bash
sudo visudo
```

Add the following line (replace www-data with the appropriate user):

```bash
www-data ALL=NOPASSWD: /usr/sbin/rndc reload
```

## 7. Download BIND9 API:

First, clone the project repository into the `/opt/bind9_api` directory:

```bash
git clone https://github.com/getnamingo/bind9-api-server /opt/bind9_api
```

Next, create the directory for logs. This directory will be used to store log files generated by the API server:

```bash
mkdir -p /var/log/namingo
chown -R www-data:www-data /var/log/namingo
```

## 8. Import Database:

```bash
mysql -u bind9_api_user -pRANDOM_STRONG_PASSWORD < /opt/bind9_api/database/bind9_api.sql
```

## 9. Setup API Service:

```bash
cd /opt/bind9_api
composer install
mv env-sample .env
```

Edit the `.env` with the appropriate database details and preferences as required.

Copy `bind9_api.service` to `/etc/systemd/system/`. Change only User and Group lines to your user and group.

```bash
systemctl daemon-reload
systemctl start bind9_api.service
systemctl enable bind9_api.service
```

After that you can manage BIND9 API via systemctl as any other service. Finally, you will need to restart Caddy server:

```bash
systemctl restart caddy
```

## (Optional) 10. Install BIND9:

If needed, here is how to install BIND9.

### 10.1. Setting your hostname

```bash
hostnamectl set-hostname your.hostname.com
```

Edit the file and add your IP and hostname as in the example below:

```bash
nano /etc/hosts
```

```bash
192.0.2.10   your.hostname.com bind
```

### 10.2. Install BIND9

Install BIND9 and related utilities:

```bash
apt install bind9 bind9utils bind9-doc dnsutils -y
```

It's good practice to back up the original BIND9 configuration files before making changes.

```bash
cp /etc/bind/named.conf.options /etc/bind/named.conf.options.backup
cp /etc/bind/named.conf.local /etc/bind/named.conf.local.backup
```

Edit the `named.conf.options` file to set up general options.

```bash
nano /etc/bind/named.conf.options
```

Replace its contents with the following:

```bash
options {
    directory "/var/cache/bind";

    // Allow queries from any IP
    allow-query { any; };

    // Listen on all interfaces
    listen-on { any; };
    listen-on-v6 { any; };

    // Enable DNSSEC validation
    dnssec-validation auto;

    auth-nxdomain no;    # conform to RFC1035
    listen-on port 53 { any; };
};
```

Create the zones directory if it doesn't exist:

```bash
mkdir -p /etc/bind/zones
```

Before restarting BIND9, verify the configuration:

```bash
sudo named-checkconf
```

If you are using UFW (Uncomplicated Firewall), execute the following commands:

```bash
ufw allow 53/tcp
ufw allow 53/udp
```

Enable BIND9 to start on boot and start the service:

```bash
systemctl enable bind9
systemctl start bind9
```