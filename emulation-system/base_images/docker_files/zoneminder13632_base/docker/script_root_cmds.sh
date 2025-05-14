#!/bin/bash

commands=(
    "id"
    "pwd"
    "cat /etc/shadow"
    "lspci"
    "command -v lsusb"
    "date"
)

for cmd in "${commands[@]}"; do
    echo "Running: $cmd"
    eval "$cmd"
    echo "-----------------------------------"
    sleep 10
done