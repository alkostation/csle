#!/bin/bash

mkdir -p /home/agent/.ssh && chmod 777 /home/agent/.ssh

cat /id_rsa > /home/agent/.ssh/id_rsa
chmod 600 /home/agent/.ssh/id_rsa

cat /id_rsa.pub > /home/agent/.ssh/id_rsa.pub
chmod 600 /home/agent/.ssh/id_rsa.pub


chown agent /home/agent/.ssh/id_rsa
chown agent /home/agent/.ssh/id_rsa.pub 