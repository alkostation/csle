# OS
FROM kthnse/csle_flat_ubuntu_22_base:0.7.0
USER root

# Copy the entrypoint script
COPY ./docker_files/dns_base/docker/docker-entrypoint.sh ./docker_files/dns_base/docker/dnsteal.py /usr/local/bin/

# Set the proper permissions and ownership
RUN set -eux; \
    chmod +x /usr/local/bin/docker-entrypoint.sh /usr/local/bin/dnsteal.py

# Set the entry point
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

EXPOSE 22/tcp 53/udp
