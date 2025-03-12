# OS
FROM kthnse/csle_flat_ubuntu_22_base:0.7.0
USER root

# Add start script
ADD docker_files/ext_employer_base/docker/start.sh /start.sh
RUN chmod 777 /start.sh

# timezone env with default
ENV TZ=Europe/Stockholm

# CMD to run when container starts, starts the services (e.g. telnet and SSH)
CMD ["/start.sh"]
