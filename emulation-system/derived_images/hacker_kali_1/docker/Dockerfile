# OS
FROM kthnse/csle_kali_base:0.7.0
USER root

# Add start script
ADD start.sh /start.sh
RUN chmod 777 /start.sh

# timezone env with default
ENV TZ=Europe/Stockholm

# SSH
RUN service ssh start

# CMD to run when container starts, starts the services (e.g. telnet and SSH)
CMD ["/start.sh"]

