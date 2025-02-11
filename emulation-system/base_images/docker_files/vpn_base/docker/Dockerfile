# OS
FROM kthnse/csle_flat_ubuntu_22_base:0.7.0
USER root

ENV DEBIAN_FRONTEND=noninteractive

# Install packages
RUN set -eux; \
    apt install -y openvpn easy-rsa bash \
    && rm -rf /var/lib/apt/lists/*

# Copy the entrypoint script
COPY ./docker_files/vpn_base/docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# Copy the openvpn configuration files with the correct permissions
COPY ./docker_files/vpn_base/docker/openvpn/etc/ /etc/

# Set the proper permissions and ownership
RUN set -eux; \
    chmod +x /usr/local/bin/docker-entrypoint.sh \
    && chown -R root:root /etc/openvpn /etc/ssl/sl700-server

# Set the entry point
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

EXPOSE 22/tcp 1194/udp
