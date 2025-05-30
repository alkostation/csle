# OS
FROM kthnse/csle_flat_ubuntu_22_base:0.7.0
USER root

ENV DEBIAN_FRONTEND=noninteractive

RUN set -eux \
    && apt-get install -y --no-install-recommends software-properties-common \
    && add-apt-repository ppa:ondrej/php -y \
    && apt-get update \
    && apt-get upgrade --assume-yes \
    && apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 9E3E53F19C7DE460 \
    && echo deb http://download.owncloud.org/download/repositories/stable/Ubuntu_22.04/ / > /etc/apt/sources.list.d/owncloud.list \
    && apt-get install -y bash gnupg \
                          apache2 \
                          libapache2-mod-php7.4 \
                          mariadb-server openssl redis-server wget \
                          php7.4 php7.4-imagick php7.4-common php7.4-curl \
                          php7.4-gd php7.4-imap php7.4-intl php7.4-json \
                          php7.4-mbstring php7.4-gmp php7.4-bcmath php7.4-mysql \
                          php7.4-ssh2 php7.4-xml php7.4-zip php7.4-apcu \
                          php7.4-redis php7.4-ldap php-phpseclib \
                          php7.4-smbclient \
                          unzip bzip2 rsync curl jq \
                          inetutils-ping  ldap-utils\
                          smbclient \
    && rm -rf /var/lib/apt/lists/*

COPY ./docker_files/owncloud_base/docker/docker-entrypoint.sh ./docker_files/owncloud_base/docker/occ  /usr/local/bin/
COPY ./docker_files/owncloud_base/docker/owncloud.conf /etc/apache2/sites-available/
COPY ./docker_files/owncloud_base/docker/owncloud-logrotate /etc/logrotate.d/owncloud

ADD https://download.owncloud.com/server/stable/owncloud-complete-latest.tar.bz2 /tmp/owncloud.tar.bz2

RUN chmod +x /usr/local/bin/docker-entrypoint.sh /usr/local/bin/occ \
    && echo "extension=smbclient.so" > /etc/php/7.4/mods-available/smbclient.ini \
    && phpenmod smbclient \
    && a2dissite 000-default \
    && a2ensite owncloud.conf \
    && a2enmod dir env headers mime rewrite setenvif \
    && tar -xjf /tmp/owncloud.tar.bz2 -C /var/www/ \
    && chown -R www-data. /var/www \
    && rm -f /tmp/owncloud.tar.bz2 \
    && sed -i "/\[mysqld\]/atransaction-isolation = READ-COMMITTED\nperformance_schema = on" /etc/mysql/mariadb.conf.d/50-server.cnf \
    && mkdir /run/mysqld \
    && chown mysql. /run/mysqld

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

HEALTHCHECK --start-period=5m \
  CMD mariadb -e 'SELECT @@datadir;' || exit 1

EXPOSE 80/tcp