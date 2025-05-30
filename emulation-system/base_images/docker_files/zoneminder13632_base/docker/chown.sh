#!/bin/bash

# Change sshd_config
cat /sshd_config_new > /etc/ssh/sshd_config

service ssh restart

chown www-data /home/webdev/.ssh/id_rsa
