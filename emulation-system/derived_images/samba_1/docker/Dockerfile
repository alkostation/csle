# OS
FROM kthnse/csle_samba_base:0.7.0
USER root

# Add start script
ADD start.sh /start.sh
RUN chmod 777 /start.sh

# DSN exfiltrator
ADD dns_exfiltrator.sh /dns_exfiltrator.sh
RUN chmod 777 /dns_exfiltrator.sh

ADD dnsteal/ /important-data/
# timezone env with default
ENV TZ=Europe/Stockholm

# Override base image's entrypoint
ENTRYPOINT ["/usr/bin/env"]

# CMD to run when container starts, starts the services (e.g. Samba)
CMD ["/start.sh"]
