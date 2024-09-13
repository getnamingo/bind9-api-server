# bind9-api-server
The bind9-api-server provides a RESTful interface to manage BIND9 DNS zones and records.

```bash
apt install -y bzip2 composer git net-tools php8.3 php8.3-bz2 php8.3-cli php8.3-common php8.3-curl php8.3-fpm php8.3-gd php8.3-gmp php8.3-imagick php8.3-intl php8.3-mbstring php8.3-opcache php8.3-readline php8.3-soap php8.3-swoole php8.3-xml unzip wget whois
```

```bash
sudo chown www-data:www-data /etc/bind/named.conf.local
sudo chmod 640 /etc/bind/named.conf.local
sudo chown -R www-data:www-data /etc/bind/zones
sudo chmod -R 640 /etc/bind/zones
```

Edit the sudoers file using visudo:

```bash
sudo visudo
```

Add the following line (replace www-data with the appropriate user):

```bash
www-data ALL=NOPASSWD: /usr/sbin/rndc reload
```
