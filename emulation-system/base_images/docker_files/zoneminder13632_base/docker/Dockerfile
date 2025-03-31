# OS
FROM kthnse/csle_flat_debian_10_base:0.7.0
USER root

ENV DEBIAN_FRONTEND=noninteractive

#https://zmrepo.zoneminder.com/debian/release-1.36/
COPY ./docker_files/zoneminder13632_base/docker/zoneminder_1.36.32-buster1_amd64.deb /tmp/

RUN set -eux \
    && apt install -y /tmp/zoneminder_1.36.32-buster1_amd64.deb \
    && apt update \
    && apt upgrade --assume-yes \
    && apt install -y bash gnupg \
    && rm -rf /var/lib/apt/lists/*

COPY ./docker_files/zoneminder13632_base/docker/docker-entrypoint.sh /usr/local/bin/

RUN chmod +x /usr/local/bin/docker-entrypoint.sh \
    && a2enconf zoneminder \
    && a2enmod rewrite cgi \
    && usermod -a -G mysql www-data \
    && sudo chmod 755 /var/run/mysqld

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

EXPOSE 22/tcp 80/tcp
