#!/bin/bash

commands=(
    "sudo -l"
    "sudo cat /etc/shadow"
    "groups"
    "ls -ld /root"
    "getent passwd"
    "cat /etc/fstab"
    "uname -ar"
    "ifconfig"
    "netstat -u"
    "ps -aux"
    "sudo ls -laR /root/"
)

for cmd in "${commands[@]}"; do
    echo "Running: $cmd"
    eval "$cmd"
    echo "-----------------------------------"
    sleep 10
done