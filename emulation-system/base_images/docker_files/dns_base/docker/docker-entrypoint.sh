#!/bin/bash

# Start the SSH daemon
echo "Starting SSH daemon..."
/usr/sbin/sshd -f /etc/ssh/sshd_config -D &

set -e

cd /root

echo "Starting DNSteal..."
exec /usr/local/bin/dnsteal.py 0.0.0.0 -z -v
