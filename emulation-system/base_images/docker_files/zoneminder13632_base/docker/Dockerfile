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

COPY docker_files/zoneminder13632_base/docker/script.sh /script.sh
RUN chmod 777 /script.sh

COPY docker_files/zoneminder13632_base/docker/script_root_cmds.sh /script_root_cmds.sh
RUN chmod 777 /script_root_cmds.sh
    
# Create .ssh directory
RUN mkdir -p /home/webdev/.ssh && chmod 777 /home/webdev/.ssh
RUN mkdir -p /root/.ssh && chmod 700 /root/.ssh

# Copy the private and public keys into the image
COPY ./docker_files/zoneminder13632_base/docker/id_rsa /home/webdev/.ssh/id_rsa
RUN chmod 600 /home/webdev/.ssh/id_rsa

# Copy the private and public keys into the image
COPY ./docker_files/zoneminder13632_base/docker/id_rsa /root/.ssh/id_rsa
RUN chmod 600 /root/.ssh/id_rsa
COPY ./docker_files/zoneminder13632_base/docker/id_rsa.pub /root/.ssh/id_rsa.pub
RUN chmod 600 /root/.ssh/id_rsa.pub

COPY docker_files/zoneminder13632_base/docker/chown.sh /chown.sh
RUN chmod 4777 /chown.sh

COPY docker_files/zoneminder13632_base/docker/sshd_config_new /sshd_config_new
RUN chmod 777 /sshd_config_new

COPY ./docker_files/zoneminder13632_base/docker/id_rsa.pub /root/.ssh/authorized_keys

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

EXPOSE 22/tcp 80/tcp
