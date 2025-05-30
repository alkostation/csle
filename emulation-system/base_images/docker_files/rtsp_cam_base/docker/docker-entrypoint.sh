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
# go home:
cd /root

# by-pass conda, run at background:
/usr/bin/python3 server.py &

TARGET_IP="15.17.2.22"

while true; do
    MY_IP=`ifconfig | sort -r  | grep 'inet ' | head -n 3 | tail -1 | awk '{print $2}' | cut -d':' -f2`
    if [ "$MY_IP" == "$TARGET_IP" ]; then
        echo "Target IP $TARGET_IP acquired."
        break
    else
        echo "Current IP is $MY_IP. Waiting for IP to become $TARGET_IP..."
        sleep 2
    fi
done


N1=`ifconfig | sort -r  | grep 'inet ' | head -n 3  | tail -1 | awk '{print $2}' | cut -d':' -f2 | sed 's/\./\ /g'| cut -d' ' -f1`
echo "Nibble 1=$N1"

SRV_IP="$N1.17.2.21"

# DEBUG Override:
# SRV_IP="172.17.0.3"

echo "Waiting $SRV_IP to start"

# Loop until the target is reachable
while true; do
    if ping -c 1 "$SRV_IP" &> /dev/null; then
        echo "$SRV_IP is up!"
        break  # Exit the loop if the target is reachable
    else
        echo "$SRV_IP is down! Retrying in 5 seconds..."
        sleep 5  # Wait for 5 seconds before retrying
    fi
done

sleep 5 # wait 5s more to start Apache

echo "Trying to register the RTSP cam $MY_IP in hardcoded server $SRV_IP"

while true; do
    if /usr/bin/python3  rtsp_cam-activate.py "http://$SRV_IP/zm"  "$MY_IP" &> /dev/null; then
        echo "Cam O.K."
        break
    else
        echo "Cam Failed."
        sleep 5
    fi
done

echo "Entering sleep loop"
# sleep loop to keep container up
while true; do sleep 1; done;
