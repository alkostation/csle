#!/bin/bash


# to inspect:
# docker run --rm -it -p 127.0.0.1:8554:8554 --entrypoint /bin/bash image_name
# find camera at rtsp://127.0.0.1:8554/Cam1:
# ffplay rtsp://127.0.0.1:8554/Cam001

while [ -z  "$(ip a show eth0 | grep 'inet ')" ]; do
    echo "Waiting for eth0 to be available..."
    sleep 2
done

# Start the SSH daemon
echo "Starting SSH daemon..."
/usr/sbin/sshd -D &

set -e

# Start the RTSP camera server
echo "Starting RTSP camera server at port 8554"

cd /root
# by-pass conda:
/usr/bin/python3 server.py
