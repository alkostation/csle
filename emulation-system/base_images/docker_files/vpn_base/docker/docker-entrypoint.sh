#!/bin/bash

set -e

while [ -z  "$(ip a show eth0 | grep 'inet ')" ]; do
    echo "Waiting for eth0 to be available..."
    sleep 2
done

# Generate host keys if they don't exist
if [ ! -f /etc/ssh/ssh_host_rsa_key ]; then
    echo "Generating SSH host keys..."
    ssh-keygen -A
fi

# Ensure proper ownership of the SSH directory
chown -R root:root /etc/ssh

# Start the SSH daemon
echo "Starting SSH daemon..."
/usr/sbin/sshd -D &

# Check if the configuration file is provided
CONFIG_FILE=${OVPN_CONFIG:-"/etc/openvpn/server/sl700-server.conf"}

# Redirect logs to stdout
ln -sf /dev/stdout /var/log/openvpn/openvpn-sl700-server.log

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "OpenVPN configuration file not found at $CONFIG_FILE."
    echo "Please mount a valid configuration file or specify its path using the OVPN_CONFIG environment variable."
    exit 1
fi

# Update permissions of tun device if required
if [[ ! -c /dev/net/tun ]]; then
    echo "TUN device is not available. Is the container running with the --cap-add=NET_ADMIN and --device=/dev/net/tun flags?"
    exit 1
fi

# Start the OpenVPN server
echo "Starting OpenVPN server with configuration: $CONFIG_FILE"
exec openvpn --config "$CONFIG_FILE"
