# Level 16 - SL001 Vulnerable WordPress Plugin Emulated Environment
ADD DESCRIPTION HERE

- Number of nodes: 15
- IDS: Yes (Snort)
- Clients: 3 
- Traffic generation: No
- Number of flags: 0
- Vulnerabilities: CVE-2020-24186 Wordpress wpDiscuz plugin

## Architecture
<p align="center">
<img src="env.png" width="600">
</p>

## How To Use The Environment
In order to work with this emulated environment you have to follow these steps:

1. change the date 

2. make install 

1. Start the emulation with the command: 
```bash
csle start csle-level16-070
```

2. Some routes between the containers will not work after the env is started, so you have to execute this command to fix them. This command will manually execute a list of action that are going to modify the iptables in the containers and that will allow the correct communication between all the containers.
```bash
python3 $PATH_TO_CSLE_FOLDER/examples/data_collection/manual_sequences/level_16/run.py
```

3. To execute the attack sequence run the command:
```bash
python3 $PATH_TO_CSLE_FOLDER/examples/data_collection/static_sequences/level_16/run.py
```

## NOTE TO ADD
- The current implementation supports only one excution







## Useful commands

```bash
make install # Install the emulation in the metastore
make uninstall # Uninstall the emulation from the metastore
make clean_config # Clean config files 
docker container ls --all # list all running containers
docker image ls --all # list all images
docker system prune # remove unused images and containers
docker container prune # remove stopped containers
sudo useradd -rm -d /home/csle_admin -s /bin/bash -g root -G sudo -p "$(openssl passwd -1 'csle@admin-pw_191')" csle_admin
docker run --name=iperf3 -d --restart=unless-stopped -p 5201:5201/tcp -p 5201:5201/udp mlabbe/iperf3 # Start the iperf server on the host
iperf3 -R -c <SERVER> # network performance, where <SERVER> is the IP where the iperf server is running e.g. the host 172.31.212.92   
```

## Author & Maintainer

Marco Campione <campione@kth.se> 

Mateus Monteiro Marinheiro <mateusma@kth.se>

## Copyright and license

[LICENSE](../../../../../LICENSE.md)

Creative Commons

(C) 2020-2024, Kim Hammar