from typing import Dict, List, Union
import argparse
import os
import multiprocessing
import csle_common.constants.constants as constants
import csle_collector.constants.constants as collector_constants
from csle_collector.client_manager.dao.constant_arrival_config import ConstantArrivalConfig
from csle_collector.client_manager.dao.workflows_config import WorkflowsConfig
from csle_collector.client_manager.dao.workflow_service import WorkflowService
from csle_collector.client_manager.dao.workflow_markov_chain import WorkflowMarkovChain
from csle_collector.client_manager.dao.client import Client
from csle_common.dao.emulation_action.attacker.emulation_attacker_nikto_actions import EmulationAttackerNIKTOActions
from csle_common.dao.emulation_action.attacker.emulation_attacker_nmap_actions import EmulationAttackerNMAPActions
from csle_common.dao.emulation_action.attacker.emulation_attacker_shell_actions import EmulationAttackerShellActions
import csle_ryu.constants.constants as ryu_constants
from csle_common.dao.emulation_config.topology_config import TopologyConfig
from csle_common.dao.emulation_config.node_firewall_config import NodeFirewallConfig
from csle_common.dao.emulation_config.default_network_firewall_config import DefaultNetworkFirewallConfig
from csle_common.dao.emulation_config.containers_config import ContainersConfig
from csle_common.dao.emulation_config.node_container_config import NodeContainerConfig
from csle_common.dao.emulation_config.container_network import ContainerNetwork
from csle_common.dao.emulation_config.flags_config import FlagsConfig
from csle_common.dao.emulation_config.resources_config import ResourcesConfig
from csle_common.dao.emulation_config.node_resources_config import NodeResourcesConfig
from csle_common.dao.emulation_config.node_network_config import NodeNetworkConfig
from csle_common.dao.emulation_config.packet_loss_type import PacketLossType
from csle_common.dao.emulation_config.packet_delay_distribution_type import PacketDelayDistributionType
from csle_common.dao.emulation_config.traffic_config import TrafficConfig
from csle_common.dao.emulation_config.node_traffic_config import NodeTrafficConfig
from csle_common.dao.emulation_config.users_config import UsersConfig
from csle_common.dao.emulation_config.node_users_config import NodeUsersConfig
from csle_common.dao.emulation_config.vulnerabilities_config import VulnerabilitiesConfig
from csle_common.dao.emulation_config.emulation_env_config import EmulationEnvConfig
from csle_common.controllers.emulation_env_controller import EmulationEnvController
from csle_common.dao.emulation_config.client_population_config import ClientPopulationConfig
from csle_common.dao.emulation_config.kafka_config import KafkaConfig
from csle_common.dao.emulation_config.kafka_topic import KafkaTopic
from csle_common.util.experiment_util import ExperimentUtil
from csle_common.dao.emulation_config.transport_protocol import TransportProtocol
from csle_common.dao.emulation_config.node_services_config import NodeServicesConfig
from csle_common.dao.emulation_config.services_config import ServicesConfig
from csle_common.dao.emulation_config.network_service import NetworkService
from csle_common.dao.emulation_config.ovs_config import OVSConfig
from csle_common.dao.emulation_config.ovs_switch_config import OvsSwitchConfig
from csle_common.dao.emulation_config.sdn_controller_config import SDNControllerConfig
from csle_common.dao.emulation_config.sdn_controller_type import SDNControllerType
from csle_common.dao.emulation_config.user import User
from csle_common.dao.emulation_action.attacker.emulation_attacker_action import EmulationAttackerAction
from csle_common.dao.emulation_config.host_manager_config import HostManagerConfig
from csle_common.dao.emulation_config.snort_ids_manager_config import SnortIDSManagerConfig
from csle_common.dao.emulation_config.ossec_ids_manager_config import OSSECIDSManagerConfig
from csle_common.dao.emulation_config.docker_stats_manager_config import DockerStatsManagerConfig
from csle_common.dao.emulation_config.elk_config import ElkConfig
from csle_common.dao.emulation_config.beats_config import BeatsConfig
from csle_common.dao.emulation_config.node_beats_config import NodeBeatsConfig
from csle_common.dao.emulation_config.node_vulnerability_config import NodeVulnerabilityConfig
from csle_common.dao.emulation_config.credential import Credential
from csle_common.dao.emulation_config.vulnerability_type import VulnType



def default_config(name: str, network_id: int = 17, level: int = 17, version: str = "0.7.0",
                   time_step_len_seconds: int = 15) -> EmulationEnvConfig:
    """
    Returns the default configuration of the emulation environment

    :param name: the name of the emulation
    :param network_id: the network id of the emulation
    :param level: the level of the emulation
    :param version: the version of the emulation
    :param time_step_len_seconds: default length of a time-step in the emulation
    :return: the emulation environment configuration
    """
    containers_cfg = default_containers_config(network_id=network_id, level=level, version=version)
    flags_cfg = default_flags_config(network_id=network_id)
    resources_cfg = default_resource_constraints_config(network_id=network_id, level=level)
    topology_cfg = default_topology_config(network_id=network_id)
    traffic_cfg = default_traffic_config(network_id=network_id, time_step_len_seconds=time_step_len_seconds)
    users_cfg = default_users_config(network_id=network_id)
    vuln_cfg = default_vulns_config(network_id=network_id)
    kafka_cfg = default_kafka_config(network_id=network_id, level=level, version=version,
                                     time_step_len_seconds=time_step_len_seconds)
    services_cfg = default_services_config(network_id=network_id)
    descr = "An emulation environment. SL700-risk mission with a set of nodes that run common networked services " \
            "such as SSH, Kafka," \
            " etc. Some of the services are vulnerable to simple dictionary attacks as " \
            "they use weak passwords." \
            "The task of an attacker agent is to identify the vulnerabilities and exploit them and " \
            "on the nodes. Conversely, the task of the defender is to harden the defense of the nodes " \
            "and to detect the" \
            "attacker."
    static_attackers_cfg = default_static_attacker_sequences(topology_cfg.subnetwork_masks)
    ovs_cfg = default_ovs_config(network_id=network_id, level=level, version=version)
    sdn_controller_cfg = default_sdn_controller_config(network_id=network_id, level=level, version=version,
                                                       time_step_len_seconds=time_step_len_seconds)
    host_manager_cfg = default_host_manager_config(network_id=network_id, level=level, version=version,
                                                   time_step_len_seconds=time_step_len_seconds)
    snort_ids_manager_cfg = default_snort_ids_manager_config(network_id=network_id, level=level, version=version,
                                                             time_step_len_seconds=time_step_len_seconds)
    ossec_ids_manager_cfg = default_ossec_ids_manager_config(network_id=network_id, level=level, version=version,
                                                             time_step_len_seconds=time_step_len_seconds)
    docker_stats_manager_cfg = default_docker_stats_manager_config(network_id=network_id, level=level, version=version,
                                                                   time_step_len_seconds=time_step_len_seconds)
    elk_cfg = default_elk_config(network_id=network_id, level=level, version=version,
                                 time_step_len_seconds=time_step_len_seconds)
    beats_cfg = default_beats_config(network_id=network_id)
    emulation_env_cfg = EmulationEnvConfig(
        name=name, containers_config=containers_cfg, users_config=users_cfg, flags_config=flags_cfg,
        vuln_config=vuln_cfg, topology_config=topology_cfg, traffic_config=traffic_cfg, resources_config=resources_cfg,
        kafka_config=kafka_cfg, services_config=services_cfg,
        descr=descr, static_attacker_sequences=static_attackers_cfg, ovs_config=ovs_cfg,
        sdn_controller_config=sdn_controller_cfg, host_manager_config=host_manager_cfg,
        snort_ids_manager_config=snort_ids_manager_cfg, ossec_ids_manager_config=ossec_ids_manager_cfg,
        docker_stats_manager_config=docker_stats_manager_cfg, elk_config=elk_cfg,
        level=level, execution_id=-1, version=version, beats_config=beats_cfg
    )
    return emulation_env_cfg


def default_containers_config(network_id: int, level: int, version: str) -> ContainersConfig:
    """
    Generates default containers config

    :param version: the version of the containers to use
    :param level: the level parameter of the emulation
    :param network_id: the network id
    :return: the ContainersConfig of the emulation
    """
    containers = [
        # ----------------- Internet [x.x.1.x] -----------------
        # Attacker IP [x.x.1.191]
        NodeContainerConfig(name=f"{constants.CONTAINER_IMAGES.HACKER_KALI_1}",
                            os=constants.CONTAINER_OS.HACKER_KALI_1_OS,
                            ips_and_networks=[
                                (f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}."
                                 f"{collector_constants.EXTERNAL_NETWORK.NETWORK_ID_THIRD_OCTET}.191",
                                 ContainerNetwork(
                                     name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_1",
                                     subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                 f"{network_id}.1{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                     subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                     interface=constants.NETWORKING.ETH0,
                                     bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                                 )),
                                (f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}."
                                 f"{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}.191",
                                 ContainerNetwork(
                                     name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_"
                                          f"{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}",
                                     subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                 f"{network_id}."
                                                 f"{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}"
                                                 f"{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                     subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                     interface=constants.NETWORKING.ETH2,
                                     bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                                 ))
                            ],
                            version=version, level=str(level),
                            restart_policy=constants.DOCKER.ON_FAILURE_3,
                            suffix="_1"),

        # Public DNS Server IP [x.x.1.12]
        NodeContainerConfig(name=f"{constants.CONTAINER_IMAGES.PUBLIC_DNS}",
                           os=constants.CONTAINER_OS.PUBLIC_DNS_OS,
                           ips_and_networks=[
                               (f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}."
                                f"{collector_constants.EXTERNAL_NETWORK.NETWORK_ID_THIRD_OCTET}.12",
                                ContainerNetwork(
                                    name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_1",
                                    subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                f"{network_id}.1{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                    subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                    interface=constants.NETWORKING.ETH0,
                                    bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                                )),
                               (f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}."
                                f"{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}.12",
                                ContainerNetwork(
                                    name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_"
                                         f"{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}",
                                    subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                f"{network_id}.{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}"
                                                f"{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                    subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                    interface=constants.NETWORKING.ETH2,
                                    bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                                ))
                           ],
                           version=version, level=str(level),
                           restart_policy=constants.DOCKER.ON_FAILURE_3,
                           suffix="_1"),

        # Corp DNS Server IP [x.x.1.13]
        NodeContainerConfig(name=f"{constants.CONTAINER_IMAGES.CORP_DNS}",
                           os=constants.CONTAINER_OS.CORP_DNS_OS,
                           ips_and_networks=[
                               (f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}."
                                f"{collector_constants.EXTERNAL_NETWORK.NETWORK_ID_THIRD_OCTET}.13",
                                ContainerNetwork(
                                    name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_1",
                                    subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                f"{network_id}.1{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                    subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                    interface=constants.NETWORKING.ETH0,
                                    bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                                )),
                               (f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}."
                                f"{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}.13",
                                ContainerNetwork(
                                    name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_"
                                         f"{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}",
                                    subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                f"{network_id}.{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}"
                                                f"{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                    subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                    interface=constants.NETWORKING.ETH2,
                                    bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                                ))
                           ],
                           version=version, level=str(level),
                           restart_policy=constants.DOCKER.ON_FAILURE_3,
                           suffix="_1"),

        # ROUTER [x.x.1.10 / x.x.4.10]
        NodeContainerConfig(name=f"{constants.CONTAINER_IMAGES.ROUTER_2}",
                            os=constants.CONTAINER_OS.ROUTER_2_OS,
                            ips_and_networks=[
                                (f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.1.10",
                                 ContainerNetwork(
                                     name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_1",
                                     subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                 f"{network_id}.1{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                     subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                     interface=constants.NETWORKING.ETH0,
                                     bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                                 )),
                                (f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.4.10",
                                 ContainerNetwork(
                                     name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_4",
                                     subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                 f"{network_id}.4{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                     subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                     interface=constants.NETWORKING.ETH2,
                                     bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                                 )),
                                (f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}."
                                 f"{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}.10",
                                 ContainerNetwork(
                                     name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_"
                                          f"{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}",
                                     subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                 f"{network_id}."
                                                 f"{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}"
                                                 f"{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                     subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                     interface=constants.NETWORKING.ETH3,
                                     bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                                 ))
                            ],
                            version=version, level=str(level),
                            restart_policy=constants.DOCKER.ON_FAILURE_3,
                            suffix="_1"),

        # ----------------- Intranet [x.x.3.x] -----------------
        # Switch IP [x.x.3.30]
        NodeContainerConfig(name=f"{constants.CONTAINER_IMAGES.OVS_1}",
                            os=constants.CONTAINER_OS.OVS_1_OS,
                            ips_and_networks=[
                                (f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.4.30",
                                 ContainerNetwork(
                                     name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_4",
                                     subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                 f"{network_id}.4{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                     subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                     interface=constants.NETWORKING.ETH0,
                                     bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                                 )),
                                (f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.3.30",
                                 ContainerNetwork(
                                     name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_3",
                                     subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                 f"{network_id}.3{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                     subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                     interface=constants.NETWORKING.ETH2,
                                     bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                                 ))
                            ],
                            version=version, level=str(level),
                            restart_policy=constants.DOCKER.ON_FAILURE_3,
                            suffix="_3"),
        
        # AdminPC IP [x.x.3.31]
        NodeContainerConfig(name=f"{constants.CONTAINER_IMAGES.CLIENT_1}",
                            os=constants.CONTAINER_OS.CLIENT_1_OS,
                            ips_and_networks=[
                                (f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.3.31",
                                 ContainerNetwork(
                                     name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_3",
                                     subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                 f"{network_id}.3{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                     subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                     interface=constants.NETWORKING.ETH0,
                                     bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                                 )),
                                (f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}."
                                 f"{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}.31",
                                 ContainerNetwork(
                                     name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_"
                                          f"{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}",
                                     subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                 f"{network_id}.{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}"
                                                 f"{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                     subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                     interface=constants.NETWORKING.ETH2,
                                     bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                                 ))
                            ],
                            version=version, level=str(level),
                            restart_policy=constants.DOCKER.ON_FAILURE_3,
                            suffix="_3"),


        # ----------------- DMZ [x.x.2.x] -----------------
        # Switch IP [x.x.2.20]
        NodeContainerConfig(name=f"{constants.CONTAINER_IMAGES.OVS_1}",
                            os=constants.CONTAINER_OS.OVS_1_OS,
                            ips_and_networks=[
                                (f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.4.20",
                                 ContainerNetwork(
                                     name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_4",
                                     subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                 f"{network_id}.4{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                     subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                     interface=constants.NETWORKING.ETH0,
                                     bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                                 )),
                                (f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.2.20",
                                 ContainerNetwork(
                                     name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_2",
                                     subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                 f"{network_id}.2{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                     subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                     interface=constants.NETWORKING.ETH2,
                                     bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                                 ))
                            ],
                            version=version, level=str(level),
                            restart_policy=constants.DOCKER.ON_FAILURE_3,
                            suffix="_2"),
        
        # Video Server IP [x.x.2.21]
        NodeContainerConfig(name=f"{constants.CONTAINER_IMAGES.ZONEMINDER}",
                   os=constants.CONTAINER_OS.ZONEMINDER_OS,
                   ips_and_networks=[
                       (f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.2.21",
                       ContainerNetwork(
                           name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_2",
                           subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                       f"{network_id}.2{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                           subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                           interface=constants.NETWORKING.ETH0,
                           bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                       )),
                       (f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}."
                       f"{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}.21",
                       ContainerNetwork(
                           name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_"
                               f"{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}",
                           subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                       f"{network_id}.{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}"
                                       f"{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                           subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                           interface=constants.NETWORKING.ETH2,
                           bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                       ))
                   ],
                   version=version, level=str(level),
                   restart_policy=constants.DOCKER.ON_FAILURE_3,
                   suffix="_2"),

        # Webcam server IP [x.x.2.22]
        NodeContainerConfig(name=f"{constants.CONTAINER_IMAGES.RTSP_CAM}",
                   os=constants.CONTAINER_OS.RTSP_CAM_OS,
                   ips_and_networks=[
                       (f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.2.22",
                       ContainerNetwork(
                           name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_2",
                           subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                       f"{network_id}.2{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                           subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                           interface=constants.NETWORKING.ETH0,
                           bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                       )),
                       (f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}."
                       f"{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}.22",
                       ContainerNetwork(
                           name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_"
                               f"{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}",
                           subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                       f"{network_id}.{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}"
                                       f"{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                           subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                           interface=constants.NETWORKING.ETH2,
                           bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                       ))
                   ],
                   version=version, level=str(level),
                   restart_policy=constants.DOCKER.ON_FAILURE_3,
                   suffix="_2"),

    ]
    containers_cfg = ContainersConfig(
        containers=containers,
        agent_ip=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}."
                 f"{collector_constants.EXTERNAL_NETWORK.NETWORK_ID_THIRD_OCTET}.191",
        router_ip=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.4.10",
        ids_enabled=False,
        vulnerable_nodes=[
            f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.2.21",
        ],
        agent_reachable_nodes=[
            f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.4.10",
            f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.4.20",
            f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.2.20",
            f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.4.30",
            f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.3.30",
            f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.3.31",
            f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.2.21",
            f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.2.22",
            f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.1.12",
            f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.1.13"
        ],
        networks=[
            ContainerNetwork(
                name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_1",
                subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                            f"{network_id}.1{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                bitmask=constants.CSLE.CSLE_EDGE_BITMASK
            ),
            ContainerNetwork(
                name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_2",
                subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                            f"{network_id}.2{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                bitmask=constants.CSLE.CSLE_EDGE_BITMASK
            ),
            ContainerNetwork(
                name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_3",
                subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                            f"{network_id}.3{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                bitmask=constants.CSLE.CSLE_EDGE_BITMASK
            ),
            ContainerNetwork(
                name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_4",
                subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                            f"{network_id}.4{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                bitmask=constants.CSLE.CSLE_EDGE_BITMASK
            ),
            ContainerNetwork(
                name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_"
                     f"{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}",
                subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                            f"{network_id}.{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}"
                            f"{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                bitmask=constants.CSLE.CSLE_EDGE_BITMASK
            )
        ]
    )
    return containers_cfg


def default_flags_config(network_id: int) -> FlagsConfig:
    """
    Generates default flags config

    :param network_id: the network id
    :return: The flags confguration
    """
    flags = []
    flags_config = FlagsConfig(node_flag_configs=flags)
    return flags_config


def default_resource_constraints_config(network_id: int, level: int) -> ResourcesConfig:
    """
    Generates default resource constraints config

    :param level: the level parameter of the emulation
    :param network_id: the network id
    :return: generates the ResourcesConfig
    """
    node_resources_configurations = [
        NodeResourcesConfig(
            container_name=f"{constants.CSLE.NAME}-"
                           f"{constants.CONTAINER_IMAGES.HACKER_KALI_1}_191-{constants.CSLE.LEVEL}{level}",
            num_cpus=4, available_memory_gb=8,
            ips_and_network_configs=[
                (f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}."
                 f"{collector_constants.EXTERNAL_NETWORK.NETWORK_ID_THIRD_OCTET}.191",
                 NodeNetworkConfig(
                     interface=constants.NETWORKING.ETH0,
                     limit_packets_queue=30000, packet_delay_ms=2,
                     packet_delay_jitter_ms=0.5, packet_delay_correlation_percentage=25,
                     packet_delay_distribution=PacketDelayDistributionType.PARETO,
                     packet_loss_type=PacketLossType.GEMODEL,
                     loss_gemodel_p=0.02, loss_gemodel_r=0.97,
                     loss_gemodel_k=0.98, loss_gemodel_h=0.0001, packet_corrupt_percentage=0.02,
                     packet_corrupt_correlation_percentage=25, packet_duplicate_percentage=0.00001,
                     packet_duplicate_correlation_percentage=25, packet_reorder_percentage=2,
                     packet_reorder_correlation_percentage=25, packet_reorder_gap=5,
                     rate_limit_mbit=1000, packet_overhead_bytes=0,
                     cell_overhead_bytes=0
                 ))]),
        NodeResourcesConfig(
            container_name=f"{constants.CSLE.NAME}-"
                           f"{constants.CONTAINER_IMAGES.PUBLIC_DNS}_12-{constants.CSLE.LEVEL}{level}",
            num_cpus=1, available_memory_gb=4,
            ips_and_network_configs=[
                (f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}."
                 f"{collector_constants.EXTERNAL_NETWORK.NETWORK_ID_THIRD_OCTET}.12",
                 NodeNetworkConfig(
                     interface=constants.NETWORKING.ETH0,
                     limit_packets_queue=30000, packet_delay_ms=2,
                     packet_delay_jitter_ms=0.5, packet_delay_correlation_percentage=25,
                     packet_delay_distribution=PacketDelayDistributionType.PARETO,
                     packet_loss_type=PacketLossType.GEMODEL,
                     loss_gemodel_p=0.02, loss_gemodel_r=0.97,
                     loss_gemodel_k=0.98, loss_gemodel_h=0.0001, packet_corrupt_percentage=0.02,
                     packet_corrupt_correlation_percentage=25, packet_duplicate_percentage=0.00001,
                     packet_duplicate_correlation_percentage=25, packet_reorder_percentage=2,
                     packet_reorder_correlation_percentage=25, packet_reorder_gap=5,
                     rate_limit_mbit=100, packet_overhead_bytes=0,
                     cell_overhead_bytes=0
                 ))]),
        NodeResourcesConfig(
            container_name=f"{constants.CSLE.NAME}-"
                           f"{constants.CONTAINER_IMAGES.CORP_DNS}_13-{constants.CSLE.LEVEL}{level}",
            num_cpus=1, available_memory_gb=4,
            ips_and_network_configs=[
                (f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}."
                 f"{collector_constants.EXTERNAL_NETWORK.NETWORK_ID_THIRD_OCTET}.13",
                 NodeNetworkConfig(
                     interface=constants.NETWORKING.ETH0,
                     limit_packets_queue=30000, packet_delay_ms=2,
                     packet_delay_jitter_ms=0.5, packet_delay_correlation_percentage=25,
                     packet_delay_distribution=PacketDelayDistributionType.PARETO,
                     packet_loss_type=PacketLossType.GEMODEL,
                     loss_gemodel_p=0.02, loss_gemodel_r=0.97,
                     loss_gemodel_k=0.98, loss_gemodel_h=0.0001, packet_corrupt_percentage=0.02,
                     packet_corrupt_correlation_percentage=25, packet_duplicate_percentage=0.00001,
                     packet_duplicate_correlation_percentage=25, packet_reorder_percentage=2,
                     packet_reorder_correlation_percentage=25, packet_reorder_gap=5,
                     rate_limit_mbit=100, packet_overhead_bytes=0,
                     cell_overhead_bytes=0
                 ))]),
        NodeResourcesConfig(
            container_name=f"{constants.CSLE.NAME}-"
                           f"{constants.CONTAINER_IMAGES.OVS_1}_20-{constants.CSLE.LEVEL}{level}",
            num_cpus=1, available_memory_gb=4,
            ips_and_network_configs=[
                (f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.4.20",
                 NodeNetworkConfig(
                     interface=constants.NETWORKING.ETH0,
                     limit_packets_queue=30000, packet_delay_ms=0.1,
                     packet_delay_jitter_ms=0.025, packet_delay_correlation_percentage=25,
                     packet_delay_distribution=PacketDelayDistributionType.PARETO,
                     packet_loss_type=PacketLossType.GEMODEL,
                     loss_gemodel_p=0.0001, loss_gemodel_r=0.999,
                     loss_gemodel_k=0.9999, loss_gemodel_h=0.0001, packet_corrupt_percentage=0.00001,
                     packet_corrupt_correlation_percentage=25, packet_duplicate_percentage=0.00001,
                     packet_duplicate_correlation_percentage=25, packet_reorder_percentage=0.0025,
                     packet_reorder_correlation_percentage=25, packet_reorder_gap=5,
                     rate_limit_mbit=1000, packet_overhead_bytes=0,
                     cell_overhead_bytes=0
                 )),
                (f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.2.20",
                 NodeNetworkConfig(
                     interface=constants.NETWORKING.ETH2,
                     limit_packets_queue=30000, packet_delay_ms=0.1,
                     packet_delay_jitter_ms=0.025, packet_delay_correlation_percentage=25,
                     packet_delay_distribution=PacketDelayDistributionType.PARETO,
                     packet_loss_type=PacketLossType.GEMODEL,
                     loss_gemodel_p=0.0001, loss_gemodel_r=0.999,
                     loss_gemodel_k=0.9999, loss_gemodel_h=0.0001, packet_corrupt_percentage=0.00001,
                     packet_corrupt_correlation_percentage=25, packet_duplicate_percentage=0.00001,
                     packet_duplicate_correlation_percentage=25, packet_reorder_percentage=0.0025,
                     packet_reorder_correlation_percentage=25, packet_reorder_gap=5,
                     rate_limit_mbit=1000, packet_overhead_bytes=0,
                     cell_overhead_bytes=0
                 ))
            ]),
        NodeResourcesConfig(
            container_name=f"{constants.CSLE.NAME}-"
                           f"{constants.CONTAINER_IMAGES.OVS_1}_30-{constants.CSLE.LEVEL}{level}",
            num_cpus=1, available_memory_gb=4,
            ips_and_network_configs=[
                (f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.4.30",
                 NodeNetworkConfig(
                     interface=constants.NETWORKING.ETH0,
                     limit_packets_queue=30000, packet_delay_ms=0.1,
                     packet_delay_jitter_ms=0.025, packet_delay_correlation_percentage=25,
                     packet_delay_distribution=PacketDelayDistributionType.PARETO,
                     packet_loss_type=PacketLossType.GEMODEL,
                     loss_gemodel_p=0.0001, loss_gemodel_r=0.999,
                     loss_gemodel_k=0.9999, loss_gemodel_h=0.0001, packet_corrupt_percentage=0.00001,
                     packet_corrupt_correlation_percentage=25, packet_duplicate_percentage=0.00001,
                     packet_duplicate_correlation_percentage=25, packet_reorder_percentage=0.0025,
                     packet_reorder_correlation_percentage=25, packet_reorder_gap=5,
                     rate_limit_mbit=1000, packet_overhead_bytes=0,
                     cell_overhead_bytes=0
                 )),
                (f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.3.30",
                 NodeNetworkConfig(
                     interface=constants.NETWORKING.ETH2,
                     limit_packets_queue=30000, packet_delay_ms=0.1,
                     packet_delay_jitter_ms=0.025, packet_delay_correlation_percentage=25,
                     packet_delay_distribution=PacketDelayDistributionType.PARETO,
                     packet_loss_type=PacketLossType.GEMODEL,
                     loss_gemodel_p=0.0001, loss_gemodel_r=0.999,
                     loss_gemodel_k=0.9999, loss_gemodel_h=0.0001, packet_corrupt_percentage=0.00001,
                     packet_corrupt_correlation_percentage=25, packet_duplicate_percentage=0.00001,
                     packet_duplicate_correlation_percentage=25, packet_reorder_percentage=0.0025,
                     packet_reorder_correlation_percentage=25, packet_reorder_gap=5,
                     rate_limit_mbit=1000, packet_overhead_bytes=0,
                     cell_overhead_bytes=0
                 ))
            ]),
        NodeResourcesConfig(
            container_name=f"{constants.CSLE.NAME}-"
                           f"{constants.CONTAINER_IMAGES.CLIENT_1}_31-{constants.CSLE.LEVEL}{level}",
            num_cpus=1, available_memory_gb=4,
            ips_and_network_configs=[
                (f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.3.31",
                 NodeNetworkConfig(
                     interface=constants.NETWORKING.ETH0,
                     limit_packets_queue=30000, packet_delay_ms=2,
                     packet_delay_jitter_ms=0.5, packet_delay_correlation_percentage=25,
                     packet_delay_distribution=PacketDelayDistributionType.PARETO,
                     packet_loss_type=PacketLossType.GEMODEL,
                     loss_gemodel_p=0.02, loss_gemodel_r=0.97,
                     loss_gemodel_k=0.98, loss_gemodel_h=0.0001, packet_corrupt_percentage=0.02,
                     packet_corrupt_correlation_percentage=25, packet_duplicate_percentage=0.00001,
                     packet_duplicate_correlation_percentage=25, packet_reorder_percentage=2,
                     packet_reorder_correlation_percentage=25, packet_reorder_gap=5,
                     rate_limit_mbit=100, packet_overhead_bytes=0,
                     cell_overhead_bytes=0
                 ))]),
        NodeResourcesConfig(
            container_name=f"{constants.CSLE.NAME}-"
                           f"{constants.CONTAINER_IMAGES.ROUTER_2}_10-{constants.CSLE.LEVEL}{level}",
            num_cpus=1, available_memory_gb=4,
            ips_and_network_configs=[
                (f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}."
                 f"{collector_constants.EXTERNAL_NETWORK.NETWORK_ID_THIRD_OCTET}.10",
                 NodeNetworkConfig(
                     interface=constants.NETWORKING.ETH0,
                     limit_packets_queue=30000, packet_delay_ms=0.1,
                     packet_delay_jitter_ms=0.025, packet_delay_correlation_percentage=25,
                     packet_delay_distribution=PacketDelayDistributionType.PARETO,
                     packet_loss_type=PacketLossType.GEMODEL,
                     loss_gemodel_p=0.0001, loss_gemodel_r=0.999,
                     loss_gemodel_k=0.9999, loss_gemodel_h=0.0001, packet_corrupt_percentage=0.00001,
                     packet_corrupt_correlation_percentage=25, packet_duplicate_percentage=0.00001,
                     packet_duplicate_correlation_percentage=25, packet_reorder_percentage=0.0025,
                     packet_reorder_correlation_percentage=25, packet_reorder_gap=5,
                     rate_limit_mbit=1000, packet_overhead_bytes=0,
                     cell_overhead_bytes=0
                 )),
                (f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.4.10",
                 NodeNetworkConfig(
                     interface=constants.NETWORKING.ETH2,
                     limit_packets_queue=30000, packet_delay_ms=0.1,
                     packet_delay_jitter_ms=0.025, packet_delay_correlation_percentage=25,
                     packet_delay_distribution=PacketDelayDistributionType.PARETO,
                     packet_loss_type=PacketLossType.GEMODEL,
                     loss_gemodel_p=0.0001, loss_gemodel_r=0.999,
                     loss_gemodel_k=0.9999, loss_gemodel_h=0.0001, packet_corrupt_percentage=0.00001,
                     packet_corrupt_correlation_percentage=25, packet_duplicate_percentage=0.00001,
                     packet_duplicate_correlation_percentage=25, packet_reorder_percentage=0.0025,
                     packet_reorder_correlation_percentage=25, packet_reorder_gap=5,
                     rate_limit_mbit=1000, packet_overhead_bytes=0,
                     cell_overhead_bytes=0
                 ))
            ]),
        NodeResourcesConfig(
            container_name=f"{constants.CSLE.NAME}-"
                           f"{constants.CONTAINER_IMAGES.RTSP_CAM}_22-{constants.CSLE.LEVEL}{level}",
            num_cpus=1, available_memory_gb=4,
            ips_and_network_configs=[
                (f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.2.22",
                 NodeNetworkConfig(
                     interface=constants.NETWORKING.ETH0,
                     limit_packets_queue=30000, packet_delay_ms=0.1,
                     packet_delay_jitter_ms=0.025, packet_delay_correlation_percentage=25,
                     packet_delay_distribution=PacketDelayDistributionType.PARETO,
                     packet_loss_type=PacketLossType.GEMODEL,
                     loss_gemodel_p=0.0001, loss_gemodel_r=0.999,
                     loss_gemodel_k=0.9999, loss_gemodel_h=0.0001, packet_corrupt_percentage=0.00001,
                     packet_corrupt_correlation_percentage=25, packet_duplicate_percentage=0.00001,
                     packet_duplicate_correlation_percentage=25, packet_reorder_percentage=0.0025,
                     packet_reorder_correlation_percentage=25, packet_reorder_gap=5,
                     rate_limit_mbit=1000, packet_overhead_bytes=0,
                     cell_overhead_bytes=0
                 ))
            ]),
        NodeResourcesConfig(
            container_name=f"{constants.CSLE.NAME}-"
                           f"{constants.CONTAINER_IMAGES.ZONEMINDER}_21-{constants.CSLE.LEVEL}{level}",
            num_cpus=1, available_memory_gb=4,
            ips_and_network_configs=[
                (f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.2.21",
                 NodeNetworkConfig(
                     interface=constants.NETWORKING.ETH0,
                     limit_packets_queue=30000, packet_delay_ms=0.1,
                     packet_delay_jitter_ms=0.025, packet_delay_correlation_percentage=25,
                     packet_delay_distribution=PacketDelayDistributionType.PARETO,
                     packet_loss_type=PacketLossType.GEMODEL,
                     loss_gemodel_p=0.0001, loss_gemodel_r=0.999,
                     loss_gemodel_k=0.9999, loss_gemodel_h=0.0001, packet_corrupt_percentage=0.00001,
                     packet_corrupt_correlation_percentage=25, packet_duplicate_percentage=0.00001,
                     packet_duplicate_correlation_percentage=25, packet_reorder_percentage=0.0025,
                     packet_reorder_correlation_percentage=25, packet_reorder_gap=5,
                     rate_limit_mbit=1000, packet_overhead_bytes=0,
                     cell_overhead_bytes=0
                 ))
            ]),
    ]
    resources_config = ResourcesConfig(node_resources_configurations=node_resources_configurations)
    return resources_config


def default_topology_config(network_id: int) -> TopologyConfig:
    """
    Generates default topology config

    :param network_id: the network id
    :return: the Topology configuration
    """
    # ----------------------- INTERNET -----------------------
    node_191 = NodeFirewallConfig(hostname=f"{constants.CONTAINER_IMAGES.HACKER_KALI_1}_191",
                                ips_gw_default_policy_networks=[
                                    DefaultNetworkFirewallConfig(
                                        ip=None,
                                        default_gw=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}."
                                                f"{collector_constants.EXTERNAL_NETWORK.NETWORK_ID_THIRD_OCTET}.10",
                                        default_input=constants.FIREWALL.ACCEPT,
                                        default_output=constants.FIREWALL.ACCEPT,
                                        default_forward=constants.FIREWALL.DROP,
                                        network=ContainerNetwork(
                                            name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_2",
                                            subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                        f"{network_id}{constants.CSLE.CSLE_LEVEL_SUBNETMASK_SUFFIX}",
                                            subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                            bitmask=constants.CSLE.CSLE_BITMASK
                                        )
                                    ),
                                    DefaultNetworkFirewallConfig(
                                        ip=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}."
                                        f"{collector_constants.EXTERNAL_NETWORK.NETWORK_ID_THIRD_OCTET}.191",
                                        default_gw=None,
                                        default_input=constants.FIREWALL.ACCEPT,
                                        default_output=constants.FIREWALL.ACCEPT,
                                        default_forward=constants.FIREWALL.DROP,
                                        network=ContainerNetwork(
                                            name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_1",
                                            subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                        f"{network_id}.1{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                            subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                            bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                                        )
                                    ),
                                    DefaultNetworkFirewallConfig(
                                        ip=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}."
                                        f"{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}.191",
                                        default_gw=None,
                                        default_input=constants.FIREWALL.ACCEPT,
                                        default_output=constants.FIREWALL.ACCEPT,
                                        default_forward=constants.FIREWALL.DROP,
                                        network=ContainerNetwork(
                                            name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_"
                                                f"{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}",
                                            subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                        f"{network_id}.{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}"
                                                        f"{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                            subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                            bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                                        )
                                    )
                                ],
                                output_accept=set([]),
                                input_accept=set([]),
                                forward_accept=set(), output_drop=set(), input_drop=set(), forward_drop=set(),
                                routes=set())

    node_10 = NodeFirewallConfig(hostname=f"{constants.CONTAINER_IMAGES.ROUTER_2}_10",
                                ips_gw_default_policy_networks=[
                                    DefaultNetworkFirewallConfig(
                                        ip=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.4.10",
                                        default_gw=None,
                                        default_input=constants.FIREWALL.ACCEPT,
                                        default_output=constants.FIREWALL.ACCEPT,
                                        default_forward=constants.FIREWALL.ACCEPT,
                                        network=ContainerNetwork(
                                            name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_4",
                                            subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                        f"{network_id}.4{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                            subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                            bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                                        )
                                    ),
                                    DefaultNetworkFirewallConfig(
                                        ip=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}."
                                        f"{collector_constants.EXTERNAL_NETWORK.NETWORK_ID_THIRD_OCTET}.10",
                                        default_gw=None,
                                        default_input=constants.FIREWALL.ACCEPT,
                                        default_output=constants.FIREWALL.ACCEPT,
                                        default_forward=constants.FIREWALL.ACCEPT,
                                        network=ContainerNetwork(
                                            name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_1",
                                            subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                        f"{network_id}.1{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                            subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                            bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                                        )
                                    ),
                                    DefaultNetworkFirewallConfig(
                                        ip=None,
                                        default_gw=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.4.30",
                                        default_input=constants.FIREWALL.ACCEPT,
                                        default_output=constants.FIREWALL.ACCEPT,
                                        default_forward=constants.FIREWALL.ACCEPT,
                                        network=ContainerNetwork(
                                            name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_4",
                                            subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                        f"{network_id}.3{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                            subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                            bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                                        )
                                    ),
                                    DefaultNetworkFirewallConfig(
                                        ip=None,
                                        default_gw=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.4.20",
                                        default_input=constants.FIREWALL.ACCEPT,
                                        default_output=constants.FIREWALL.ACCEPT,
                                        default_forward=constants.FIREWALL.ACCEPT,
                                        network=ContainerNetwork(
                                            name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_4",
                                            subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                        f"{network_id}.2{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                            subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                            bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                                        )
                                    ),
                                    DefaultNetworkFirewallConfig(
                                        ip=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}."
                                        f"{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}.10",
                                        default_gw=None,
                                        default_input=constants.FIREWALL.ACCEPT,
                                        default_output=constants.FIREWALL.ACCEPT,
                                        default_forward=constants.FIREWALL.DROP,
                                        network=ContainerNetwork(
                                            name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_"
                                                f"{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}",
                                            subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                        f"{network_id}.{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}"
                                                        f"{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                            subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                            bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                                        )
                                    )
                                ],
                                output_accept=set([]),
                                input_accept=set([]),
                                forward_accept=set([]),
                                output_drop=set(), input_drop=set(), forward_drop=set(), routes=set())

    node_12 = NodeFirewallConfig(hostname=f"{constants.CONTAINER_IMAGES.PUBLIC_DNS}_12",
                            ips_gw_default_policy_networks=[
                                DefaultNetworkFirewallConfig(
                                    ip=None,
                                    default_gw=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.1.10",
                                    default_input=constants.FIREWALL.ACCEPT,
                                    default_output=constants.FIREWALL.ACCEPT,
                                    default_forward=constants.FIREWALL.DROP,
                                    network=ContainerNetwork(
                                        name="",
                                        subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                    f"{network_id}{constants.CSLE.CSLE_LEVEL_SUBNETMASK_SUFFIX}",
                                        subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                        bitmask=constants.CSLE.CSLE_BITMASK
                                    )
                                ),
                                DefaultNetworkFirewallConfig(
                                    ip=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.1.12",
                                    default_gw=None,
                                    default_input=constants.FIREWALL.ACCEPT,
                                    default_output=constants.FIREWALL.ACCEPT,
                                    default_forward=constants.FIREWALL.DROP,
                                    network=ContainerNetwork(
                                        name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_1",
                                        subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                    f"{network_id}.1{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                        subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                        bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                                    )
                                ),
                                DefaultNetworkFirewallConfig(
                                    ip=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}."
                                    f"{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}.12",
                                    default_gw=None,
                                    default_input=constants.FIREWALL.ACCEPT,
                                    default_output=constants.FIREWALL.ACCEPT,
                                    default_forward=constants.FIREWALL.DROP,
                                    network=ContainerNetwork(
                                        name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_"
                                            f"{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}",
                                        subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                    f"{network_id}.{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}"
                                                    f"{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                        subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                        bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                                    )
                                )
                            ],
                            output_accept=set([]),
                            input_accept=set([]),
                            forward_accept=set(), output_drop=set(), input_drop=set(), forward_drop=set(),
                            routes=set())
    
    node_13 = NodeFirewallConfig(hostname=f"{constants.CONTAINER_IMAGES.CORP_DNS}_13",
                            ips_gw_default_policy_networks=[
                                DefaultNetworkFirewallConfig(
                                    ip=None,
                                    default_gw=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.1.10",
                                    default_input=constants.FIREWALL.ACCEPT,
                                    default_output=constants.FIREWALL.ACCEPT,
                                    default_forward=constants.FIREWALL.DROP,
                                    network=ContainerNetwork(
                                        name="",
                                        subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                    f"{network_id}{constants.CSLE.CSLE_LEVEL_SUBNETMASK_SUFFIX}",
                                        subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                        bitmask=constants.CSLE.CSLE_BITMASK
                                    )
                                ),
                                DefaultNetworkFirewallConfig(
                                    ip=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.1.13",
                                    default_gw=None,
                                    default_input=constants.FIREWALL.ACCEPT,
                                    default_output=constants.FIREWALL.ACCEPT,
                                    default_forward=constants.FIREWALL.DROP,
                                    network=ContainerNetwork(
                                        name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_1",
                                        subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                    f"{network_id}.1{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                        subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                        bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                                    )
                                ),
                                DefaultNetworkFirewallConfig(
                                    ip=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}."
                                    f"{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}.13",
                                    default_gw=None,
                                    default_input=constants.FIREWALL.ACCEPT,
                                    default_output=constants.FIREWALL.ACCEPT,
                                    default_forward=constants.FIREWALL.DROP,
                                    network=ContainerNetwork(
                                        name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_"
                                            f"{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}",
                                        subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                    f"{network_id}.{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}"
                                                    f"{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                        subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                        bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                                    )
                                )
                            ],
                            output_accept=set([]),
                            input_accept=set([]),
                            forward_accept=set(), output_drop=set(), input_drop=set(), forward_drop=set(),
                            routes=set())

    # ----------------------- DMZ -----------------------
    node_20 = NodeFirewallConfig(hostname=f"{constants.CONTAINER_IMAGES.OVS_1}_20",
                                ips_gw_default_policy_networks=[
                                    DefaultNetworkFirewallConfig(
                                        ip=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.4.20",
                                        default_gw=None,
                                        default_input=constants.FIREWALL.ACCEPT,
                                        default_output=constants.FIREWALL.ACCEPT,
                                        default_forward=constants.FIREWALL.ACCEPT,
                                        network=ContainerNetwork(
                                            name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_4",
                                            subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                        f"{network_id}.4{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                            subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                            bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                                        )
                                    ),
                                    DefaultNetworkFirewallConfig(
                                        ip=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.2.20",
                                        default_gw=None,
                                        default_input=constants.FIREWALL.ACCEPT,
                                        default_output=constants.FIREWALL.ACCEPT,
                                        default_forward=constants.FIREWALL.ACCEPT,
                                        network=ContainerNetwork(
                                            name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_2",
                                            subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                        f"{network_id}.2{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                            subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                            bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                                        )
                                    ),
                                    DefaultNetworkFirewallConfig(
                                        ip=None,
                                        default_gw=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.4.10",
                                        default_input=constants.FIREWALL.ACCEPT,
                                        default_output=constants.FIREWALL.ACCEPT,
                                        default_forward=constants.FIREWALL.ACCEPT,
                                        network=ContainerNetwork(
                                            name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_1",
                                            subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                        f"{network_id}.1{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                            subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                            bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                                        )
                                    ),
                                    DefaultNetworkFirewallConfig(
                                        ip=None,
                                        default_gw=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.4.10",
                                        default_input=constants.FIREWALL.ACCEPT,
                                        default_output=constants.FIREWALL.ACCEPT,
                                        default_forward=constants.FIREWALL.ACCEPT,
                                        network=ContainerNetwork(
                                            name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_3",
                                            subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                        f"{network_id}.3{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                            subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                            bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                                        )
                                    )
                                ],
                                output_accept=set([]),
                                input_accept=set([]),
                                forward_accept=set(), output_drop=set(), input_drop=set(), routes=set(), forward_drop=set())
    
    node_21 = NodeFirewallConfig(hostname=f"{constants.CONTAINER_IMAGES.ZONEMINDER}_21",
                                ips_gw_default_policy_networks=[
                                    DefaultNetworkFirewallConfig(
                                        ip=None,
                                        default_gw=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.2.20",
                                        default_input=constants.FIREWALL.ACCEPT,
                                        default_output=constants.FIREWALL.ACCEPT,
                                        default_forward=constants.FIREWALL.DROP,
                                        network=ContainerNetwork(
                                            name="",
                                            subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                        f"{network_id}{constants.CSLE.CSLE_LEVEL_SUBNETMASK_SUFFIX}",
                                            subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                            bitmask=constants.CSLE.CSLE_BITMASK
                                        )
                                    ),
                                    DefaultNetworkFirewallConfig(
                                        ip=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.2.21",
                                        default_gw=None,
                                        default_input=constants.FIREWALL.ACCEPT,
                                        default_output=constants.FIREWALL.ACCEPT,
                                        default_forward=constants.FIREWALL.DROP,
                                        network=ContainerNetwork(
                                            name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_2",
                                            subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                        f"{network_id}.2{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                            subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                            bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                                        )
                                    ),
                                    DefaultNetworkFirewallConfig(
                                    ip=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}."
                                        f"{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}.21",
                                    default_gw=None,
                                    default_input=constants.FIREWALL.ACCEPT,
                                    default_output=constants.FIREWALL.ACCEPT,
                                    default_forward=constants.FIREWALL.DROP,
                                    network=ContainerNetwork(
                                        name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_"
                                            f"{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}",
                                        subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                    f"{network_id}.{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}"
                                                    f"{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                        subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                        bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                                    )
                                )
                            ],
                            output_accept=set([]),
                            input_accept=set([]),
                            forward_accept=set(), output_drop=set(), input_drop=set(), forward_drop=set(),
                            routes=set())
    
    node_22 = NodeFirewallConfig(hostname=f"{constants.CONTAINER_IMAGES.RTSP_CAM}_22",
                                ips_gw_default_policy_networks=[
                                    DefaultNetworkFirewallConfig(
                                        ip=None,
                                        default_gw=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.2.20",
                                        default_input=constants.FIREWALL.ACCEPT,
                                        default_output=constants.FIREWALL.ACCEPT,
                                        default_forward=constants.FIREWALL.DROP,
                                        network=ContainerNetwork(
                                            name="",
                                            subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                        f"{network_id}{constants.CSLE.CSLE_LEVEL_SUBNETMASK_SUFFIX}",
                                            subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                            bitmask=constants.CSLE.CSLE_BITMASK
                                        )
                                    ),
                                    DefaultNetworkFirewallConfig(
                                        ip=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.2.22",
                                        default_gw=None,
                                        default_input=constants.FIREWALL.ACCEPT,
                                        default_output=constants.FIREWALL.ACCEPT,
                                        default_forward=constants.FIREWALL.DROP,
                                        network=ContainerNetwork(
                                            name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_2",
                                            subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                        f"{network_id}.2{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                            subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                            bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                                        )
                                    ),
                                    DefaultNetworkFirewallConfig(
                                    ip=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}."
                                        f"{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}.22",
                                    default_gw=None,
                                    default_input=constants.FIREWALL.ACCEPT,
                                    default_output=constants.FIREWALL.ACCEPT,
                                    default_forward=constants.FIREWALL.DROP,
                                    network=ContainerNetwork(
                                        name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_"
                                            f"{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}",
                                        subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                    f"{network_id}.{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}"
                                                    f"{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                        subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                        bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                                    )
                                )
                            ],
                            output_accept=set([]),
                            input_accept=set([]),
                            forward_accept=set(), output_drop=set(), input_drop=set(), forward_drop=set(),
                            routes=set())
    
    # ----------------------- INTRANET -----------------------
    node_30 = NodeFirewallConfig(hostname=f"{constants.CONTAINER_IMAGES.OVS_1}_30",
                                ips_gw_default_policy_networks=[
                                    DefaultNetworkFirewallConfig(
                                        ip=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.4.30",
                                        default_gw=None,
                                        default_input=constants.FIREWALL.ACCEPT,
                                        default_output=constants.FIREWALL.ACCEPT,
                                        default_forward=constants.FIREWALL.ACCEPT,
                                        network=ContainerNetwork(
                                            name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_4",
                                            subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                        f"{network_id}.4{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                            subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                            bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                                        )
                                    ),
                                    DefaultNetworkFirewallConfig(
                                        ip=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.3.30",
                                        default_gw=None,
                                        default_input=constants.FIREWALL.ACCEPT,
                                        default_output=constants.FIREWALL.ACCEPT,
                                        default_forward=constants.FIREWALL.ACCEPT,
                                        network=ContainerNetwork(
                                            name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_3",
                                            subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                        f"{network_id}.3{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                            subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                            bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                                        )
                                    ),
                                    DefaultNetworkFirewallConfig(
                                        ip=None,
                                        default_gw=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.4.10",
                                        default_input=constants.FIREWALL.ACCEPT,
                                        default_output=constants.FIREWALL.ACCEPT,
                                        default_forward=constants.FIREWALL.ACCEPT,
                                        network=ContainerNetwork(
                                            name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_1",
                                            subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                        f"{network_id}.1{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                            subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                            bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                                        )
                                    ),
                                    DefaultNetworkFirewallConfig(
                                        ip=None,
                                        default_gw=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.4.10",
                                        default_input=constants.FIREWALL.ACCEPT,
                                        default_output=constants.FIREWALL.ACCEPT,
                                        default_forward=constants.FIREWALL.ACCEPT,
                                        network=ContainerNetwork(
                                            name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_2",
                                            subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                        f"{network_id}.2{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                            subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                            bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                                        )
                                    )
                                ],
                                output_accept=set([]),
                                input_accept=set([]),
                                forward_accept=set(), output_drop=set(), input_drop=set(), routes=set(), forward_drop=set())
    
    node_31 = NodeFirewallConfig(hostname=f"{constants.CONTAINER_IMAGES.CLIENT_1}_31",
                                ips_gw_default_policy_networks=[
                                    DefaultNetworkFirewallConfig(
                                        ip=None,
                                        default_gw=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.3.30",
                                        default_input=constants.FIREWALL.ACCEPT,
                                        default_output=constants.FIREWALL.ACCEPT,
                                        default_forward=constants.FIREWALL.DROP,
                                        network=ContainerNetwork(
                                            name="",
                                            subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                        f"{network_id}{constants.CSLE.CSLE_LEVEL_SUBNETMASK_SUFFIX}",
                                            subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                            bitmask=constants.CSLE.CSLE_BITMASK
                                        )
                                    ),
                                    DefaultNetworkFirewallConfig(
                                        ip=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.3.31",
                                        default_gw=None,
                                        default_input=constants.FIREWALL.ACCEPT,
                                        default_output=constants.FIREWALL.ACCEPT,
                                        default_forward=constants.FIREWALL.DROP,
                                        network=ContainerNetwork(
                                            name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_3",
                                            subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                        f"{network_id}.3{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                            subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                            bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                                        )
                                    ),
                                    DefaultNetworkFirewallConfig(
                                        ip=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}."
                                        f"{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}.31",
                                        default_gw=None,
                                        default_input=constants.FIREWALL.ACCEPT,
                                        default_output=constants.FIREWALL.ACCEPT,
                                        default_forward=constants.FIREWALL.DROP,
                                        network=ContainerNetwork(
                                            name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_"
                                                f"{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}",
                                            subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                                        f"{network_id}.{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}"
                                                        f"{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                            subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                                            bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                                        )
                                    )
                                ],
                                output_accept=set([]),
                                input_accept=set([]),
                                forward_accept=set(), output_drop=set(), input_drop=set(), forward_drop=set(),
                                routes=set())

   
    node_configs = [node_191, node_10, node_12, node_13, node_20, node_21, node_22, node_30, node_31]
    topology = TopologyConfig(node_configs=node_configs,
                              subnetwork_masks=[
                                  f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                  f"{network_id}.1{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                  f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                  f"{network_id}.2{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                  f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                  f"{network_id}.3{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                                  f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                  f"{network_id}.4{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}"
                              ])
    return topology


def default_traffic_config(network_id: int, time_step_len_seconds: int) -> TrafficConfig:
    """
    Generates default traffic config

    :param network_id: the network id
    :param time_step_len_seconds: default length of a time-step in the emulation
    :return: the traffic configuration
    """
    traffic_generators = []
    all_ips_and_commands = []
    for i in range(len(traffic_generators)):
        all_ips_and_commands.append((traffic_generators[i].ip, traffic_generators[i].commands))
    workflows_config = WorkflowsConfig(
        workflow_services=[
            WorkflowService(id=0, ips_and_commands=all_ips_and_commands)
        ],
        workflow_markov_chains=[
            WorkflowMarkovChain(
                transition_matrix=[
                    [0.8, 0.2],
                    [0, 1]
                ],
                initial_state=0,
                id=0
            )
        ]
    )
    # client_population_config = ClientPopulationConfig()
    client_population_config = ClientPopulationConfig(
        networks=[ContainerNetwork(
            name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_2",
            subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                        f"{network_id}.2{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
            subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
            bitmask=constants.CSLE.CSLE_EDGE_BITMASK
        )],
        ip=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}."
           f"{collector_constants.EXTERNAL_NETWORK.NETWORK_ID_THIRD_OCTET}.254",
        client_manager_port=collector_constants.MANAGER_PORTS.CLIENT_MANAGER_DEFAULT_PORT,
        client_time_step_len_seconds=time_step_len_seconds,
        client_manager_log_dir=collector_constants.LOG_FILES.CLIENT_MANAGER_LOG_DIR,
        client_manager_log_file=collector_constants.LOG_FILES.CLIENT_MANAGER_LOG_FILE,
        client_manager_max_workers=collector_constants.GRPC_WORKERS.DEFAULT_MAX_NUM_WORKERS,
        clients=[
            Client(id=0, workflow_distribution=[1],
                   arrival_config=ConstantArrivalConfig(lamb=20), mu=4, exponential_service_time=True)
        ],
        workflows_config=workflows_config)
    traffic_conf = TrafficConfig(node_traffic_configs=traffic_generators,
                                 client_population_config=client_population_config)
    return traffic_conf


def default_beats_config(network_id: int) -> BeatsConfig:
    """
    Generates default beats config

    :param network_id: the network id
    :return: the beats configuration
    """
    node_beats_configs = []
    beats_conf = BeatsConfig(node_beats_configs=node_beats_configs, num_elastic_shards=1, reload_enabled=False)
    return beats_conf


def default_kafka_config(network_id: int, level: int, version: str, time_step_len_seconds: int) -> KafkaConfig:
    """
    Generates the default kafka configuration

    :param network_id: the id of the emulation network
    :param level: the level of the emulation
    :param version: the version of the emulation
    :param time_step_len_seconds: default length of a time-step in the emulation
    :return: the kafka configuration
    """
    container = NodeContainerConfig(
        name=f"{constants.CONTAINER_IMAGES.KAFKA_1}",
        os=constants.CONTAINER_OS.KAFKA_1_OS,
        ips_and_networks=[
            (f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}."
             f"{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}."
             f"{collector_constants.KAFKA_CONFIG.NETWORK_ID_FOURTH_OCTET}",
             ContainerNetwork(
                 name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_"
                      f"{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}",
                 subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                             f"{network_id}.{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}"
                             f"{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                 subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                 bitmask=constants.CSLE.CSLE_EDGE_BITMASK
             )),
        ],
        version=version, level=str(level),
        restart_policy=constants.DOCKER.ON_FAILURE_3, suffix=collector_constants.KAFKA_CONFIG.SUFFIX)

    resources = NodeResourcesConfig(
        container_name=f"{constants.CSLE.NAME}-"
                       f"{constants.CONTAINER_IMAGES.KAFKA_1}_1-{constants.CSLE.LEVEL}{level}",
        num_cpus=1, available_memory_gb=4,
        ips_and_network_configs=[
            (f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}."
             f"{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}."
             f"{collector_constants.KAFKA_CONFIG.NETWORK_ID_FOURTH_OCTET}",
             None)])

    firewall_config = NodeFirewallConfig(
        hostname=f"{constants.CONTAINER_IMAGES.KAFKA_1}_1",
        ips_gw_default_policy_networks=[
            DefaultNetworkFirewallConfig(
                ip=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}."
                   f"{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}."
                   f"{collector_constants.KAFKA_CONFIG.NETWORK_ID_FOURTH_OCTET}",
                default_gw=None,
                default_input=constants.FIREWALL.ACCEPT,
                default_output=constants.FIREWALL.ACCEPT,
                default_forward=constants.FIREWALL.ACCEPT,
                network=ContainerNetwork(
                    name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_"
                         f"{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}",
                    subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                f"{network_id}.{collector_constants.KAFKA_CONFIG.NETWORK_ID_THIRD_OCTET}"
                                f"{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                    subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                    bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                )
            )
        ],
        output_accept=set([]),
        input_accept=set([]),
        forward_accept=set([]),
        output_drop=set(), input_drop=set(), forward_drop=set(), routes=set())

    topics = [
        KafkaTopic(
            name=collector_constants.KAFKA_CONFIG.CLIENT_POPULATION_TOPIC_NAME,
            num_replicas=collector_constants.KAFKA_CONFIG.DEFAULT_NUM_REPLICAS,
            num_partitions=collector_constants.KAFKA_CONFIG.DEFAULT_NUM_PARTITIONS,
            retention_time_hours=collector_constants.KAFKA_CONFIG.DEFAULT_RETENTION_TIME_HOURS,
            attributes=collector_constants.KAFKA_CONFIG.CLIENT_POPULATION_TOPIC_ATTRIBUTES
        ),
        KafkaTopic(
            name=collector_constants.KAFKA_CONFIG.SNORT_IDS_LOG_TOPIC_NAME,
            num_replicas=collector_constants.KAFKA_CONFIG.DEFAULT_NUM_REPLICAS,
            num_partitions=collector_constants.KAFKA_CONFIG.DEFAULT_NUM_PARTITIONS,
            retention_time_hours=collector_constants.KAFKA_CONFIG.DEFAULT_RETENTION_TIME_HOURS,
            attributes=collector_constants.KAFKA_CONFIG.SNORT_IDS_LOG_TOPIC_ATTRIBUTES
        ),
        KafkaTopic(
            name=collector_constants.KAFKA_CONFIG.OSSEC_IDS_LOG_TOPIC_NAME,
            num_replicas=collector_constants.KAFKA_CONFIG.DEFAULT_NUM_REPLICAS,
            num_partitions=collector_constants.KAFKA_CONFIG.DEFAULT_NUM_PARTITIONS,
            retention_time_hours=collector_constants.KAFKA_CONFIG.DEFAULT_RETENTION_TIME_HOURS,
            attributes=collector_constants.KAFKA_CONFIG.OSSEC_IDS_LOG_TOPIC_ATTRIBUTES
        ),
        KafkaTopic(
            name=collector_constants.KAFKA_CONFIG.HOST_METRICS_TOPIC_NAME,
            num_replicas=collector_constants.KAFKA_CONFIG.DEFAULT_NUM_REPLICAS,
            num_partitions=collector_constants.KAFKA_CONFIG.DEFAULT_NUM_PARTITIONS,
            retention_time_hours=collector_constants.KAFKA_CONFIG.DEFAULT_RETENTION_TIME_HOURS,
            attributes=collector_constants.KAFKA_CONFIG.HOST_METRICS_TOPIC_ATTRIBUTES
        ),
        KafkaTopic(
            name=collector_constants.KAFKA_CONFIG.DOCKER_STATS_TOPIC_NAME,
            num_replicas=collector_constants.KAFKA_CONFIG.DEFAULT_NUM_REPLICAS,
            num_partitions=collector_constants.KAFKA_CONFIG.DEFAULT_NUM_PARTITIONS,
            retention_time_hours=collector_constants.KAFKA_CONFIG.DEFAULT_RETENTION_TIME_HOURS,
            attributes=collector_constants.KAFKA_CONFIG.DOCKER_STATS_TOPIC_ATTRIBUTES
        ),
        KafkaTopic(
            name=collector_constants.KAFKA_CONFIG.ATTACKER_ACTIONS_TOPIC_NAME,
            num_replicas=collector_constants.KAFKA_CONFIG.DEFAULT_NUM_REPLICAS,
            num_partitions=collector_constants.KAFKA_CONFIG.DEFAULT_NUM_PARTITIONS,
            retention_time_hours=collector_constants.KAFKA_CONFIG.DEFAULT_RETENTION_TIME_HOURS,
            attributes=collector_constants.KAFKA_CONFIG.ATTACKER_ACTIONS_ATTRIBUTES
        ),
        KafkaTopic(
            name=collector_constants.KAFKA_CONFIG.DEFENDER_ACTIONS_TOPIC_NAME,
            num_replicas=collector_constants.KAFKA_CONFIG.DEFAULT_NUM_REPLICAS,
            num_partitions=collector_constants.KAFKA_CONFIG.DEFAULT_NUM_PARTITIONS,
            retention_time_hours=collector_constants.KAFKA_CONFIG.DEFAULT_RETENTION_TIME_HOURS,
            attributes=collector_constants.KAFKA_CONFIG.DEFENDER_ACTIONS_ATTRIBUTES
        ),
        KafkaTopic(
            name=collector_constants.KAFKA_CONFIG.DOCKER_HOST_STATS_TOPIC_NAME,
            num_replicas=collector_constants.KAFKA_CONFIG.DEFAULT_NUM_REPLICAS,
            num_partitions=collector_constants.KAFKA_CONFIG.DEFAULT_NUM_PARTITIONS,
            retention_time_hours=collector_constants.KAFKA_CONFIG.DEFAULT_RETENTION_TIME_HOURS,
            attributes=collector_constants.KAFKA_CONFIG.DOCKER_STATS_TOPIC_ATTRIBUTES
        ),
        KafkaTopic(
            name=collector_constants.KAFKA_CONFIG.OPENFLOW_FLOW_STATS_TOPIC_NAME,
            num_replicas=collector_constants.KAFKA_CONFIG.DEFAULT_NUM_REPLICAS,
            num_partitions=collector_constants.KAFKA_CONFIG.DEFAULT_NUM_PARTITIONS,
            retention_time_hours=collector_constants.KAFKA_CONFIG.DEFAULT_RETENTION_TIME_HOURS,
            attributes=collector_constants.KAFKA_CONFIG.OPENFLOW_FLOW_STATS_TOPIC_ATTRIBUTES
        ),
        KafkaTopic(
            name=collector_constants.KAFKA_CONFIG.OPENFLOW_PORT_STATS_TOPIC_NAME,
            num_replicas=collector_constants.KAFKA_CONFIG.DEFAULT_NUM_REPLICAS,
            num_partitions=collector_constants.KAFKA_CONFIG.DEFAULT_NUM_PARTITIONS,
            retention_time_hours=collector_constants.KAFKA_CONFIG.DEFAULT_RETENTION_TIME_HOURS,
            attributes=collector_constants.KAFKA_CONFIG.OPENFLOW_PORT_STATS_TOPIC_ATTRIBUTES
        ),
        KafkaTopic(
            name=collector_constants.KAFKA_CONFIG.AVERAGE_OPENFLOW_FLOW_STATS_PER_SWITCH_TOPIC_NAME,
            num_replicas=collector_constants.KAFKA_CONFIG.DEFAULT_NUM_REPLICAS,
            num_partitions=collector_constants.KAFKA_CONFIG.DEFAULT_NUM_PARTITIONS,
            retention_time_hours=collector_constants.KAFKA_CONFIG.DEFAULT_RETENTION_TIME_HOURS,
            attributes=collector_constants.KAFKA_CONFIG.AVERAGE_OPENFLOW_FLOW_STATS_PER_SWITCH_TOPIC_ATTRIBUTES
        ),
        KafkaTopic(
            name=collector_constants.KAFKA_CONFIG.AVERAGE_OPENFLOW_PORT_STATS_PER_SWITCH_TOPIC_NAME,
            num_replicas=collector_constants.KAFKA_CONFIG.DEFAULT_NUM_REPLICAS,
            num_partitions=collector_constants.KAFKA_CONFIG.DEFAULT_NUM_PARTITIONS,
            retention_time_hours=collector_constants.KAFKA_CONFIG.DEFAULT_RETENTION_TIME_HOURS,
            attributes=collector_constants.KAFKA_CONFIG.AVERAGE_OPENFLOW_PORT_STATS_PER_SWITCH_TOPIC_ATTRIBUTES
        ),
        KafkaTopic(
            name=collector_constants.KAFKA_CONFIG.OPENFLOW_AGG_FLOW_STATS_TOPIC_NAME,
            num_replicas=collector_constants.KAFKA_CONFIG.DEFAULT_NUM_REPLICAS,
            num_partitions=collector_constants.KAFKA_CONFIG.DEFAULT_NUM_PARTITIONS,
            retention_time_hours=collector_constants.KAFKA_CONFIG.DEFAULT_RETENTION_TIME_HOURS,
            attributes=collector_constants.KAFKA_CONFIG.OPENFLOW_AGG_FLOW_STATS_TOPIC_ATTRIBUTES
        ),
        KafkaTopic(
            name=collector_constants.KAFKA_CONFIG.SNORT_IDS_RULE_LOG_TOPIC_NAME,
            num_replicas=collector_constants.KAFKA_CONFIG.DEFAULT_NUM_REPLICAS,
            num_partitions=collector_constants.KAFKA_CONFIG.DEFAULT_NUM_PARTITIONS,
            retention_time_hours=collector_constants.KAFKA_CONFIG.DEFAULT_RETENTION_TIME_HOURS,
            attributes=collector_constants.KAFKA_CONFIG.SNORT_IDS_RULE_LOG_ATTRIBUTES
        ),
        KafkaTopic(
            name=collector_constants.KAFKA_CONFIG.SNORT_IDS_IP_LOG_TOPIC_NAME,
            num_replicas=collector_constants.KAFKA_CONFIG.DEFAULT_NUM_REPLICAS,
            num_partitions=collector_constants.KAFKA_CONFIG.DEFAULT_NUM_PARTITIONS,
            retention_time_hours=collector_constants.KAFKA_CONFIG.DEFAULT_RETENTION_TIME_HOURS,
            attributes=collector_constants.KAFKA_CONFIG.SNORT_IDS_IP_LOG_ATTRIBUTES
        )
    ]

    config = KafkaConfig(container=container, resources=resources, topics=topics, firewall_config=firewall_config,
                         version=version,
                         kafka_port=collector_constants.KAFKA.PORT,
                         kafka_port_external=collector_constants.KAFKA.EXTERNAL_PORT,
                         kafka_manager_port=collector_constants.MANAGER_PORTS.KAFKA_MANAGER_DEFAULT_PORT,
                         time_step_len_seconds=time_step_len_seconds,
                         kafka_manager_log_file=collector_constants.LOG_FILES.KAFKA_MANAGER_LOG_FILE,
                         kafka_manager_log_dir=collector_constants.LOG_FILES.KAFKA_MANAGER_LOG_DIR,
                         kafka_manager_max_workers=collector_constants.GRPC_WORKERS.DEFAULT_MAX_NUM_WORKERS)
    return config


def default_users_config(network_id: int) -> UsersConfig:
    """
    Generates default users config

    :param network_id: the network id
    :return: generates the UsersConfig
    """
    users = [
        NodeUsersConfig(ip=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}."
                           f"{collector_constants.EXTERNAL_NETWORK.NETWORK_ID_THIRD_OCTET}.191",
                        users=[User(username="agent", pw="agent", root=True)])
    ]
    users_conf = UsersConfig(users_configs=users)
    return users_conf


def default_vulns_config(network_id: int) -> VulnerabilitiesConfig:
    """
    Generates default vulnerabilities config

    :param network_id: the network id
    :return: the vulnerability config
    """
    vulns = [        
        NodeVulnerabilityConfig(
            name=constants.EXPLOIT_VULNERABILITES.CVE_2023_26035,
            ip=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.2.21",
            vuln_type=VulnType.RCE,
            cvss=constants.EXPLOIT_VULNERABILITES.CVE_2023_26035_CVSS,
            cve=constants.EXPLOIT_VULNERABILITES.CVE_2023_26035,
            root=False, port=constants.CVE_2023_26035.PORT, protocol=TransportProtocol.TCP,
            service=constants.CVE_2023_26035.SERVICE_NAME),
        ]
    vulns_config = VulnerabilitiesConfig(node_vulnerability_configs=vulns)
    return vulns_config


def default_services_config(network_id: int) -> ServicesConfig:
    """
    Generates default services config

    :param network_id: the network id
    :return: The services configuration
    """
    services_configs = [
        # ----------------------- INTERNET -----------------------
        # Attacker IP [x.x.1.191]
        NodeServicesConfig(
            ip=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.1.191",
            services=[
                NetworkService(protocol=TransportProtocol.TCP, port=constants.SSH.DEFAULT_PORT,
                               name=constants.SSH.SERVICE_NAME, credentials=[])
            ]
        ),
        # Public DNS Server IP [x.x.1.12]
        NodeServicesConfig(
            ip=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.1.12",
            services=[
                NetworkService(protocol=TransportProtocol.TCP, port=constants.SSH.DEFAULT_PORT,
                               name=constants.SSH.SERVICE_NAME, credentials=[]),
                NetworkService(protocol=TransportProtocol.TCP, port=constants.DNS.DEFAULT_PORT,
                               name=constants.DNS.SERVICE_NAME, credentials=[]),
            ]
        ),
        # DNS Server IP [x.x.1.13]
        NodeServicesConfig(
            ip=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.1.13",
            services=[
                NetworkService(protocol=TransportProtocol.TCP, port=constants.SSH.DEFAULT_PORT,
                               name=constants.SSH.SERVICE_NAME, credentials=[]),
                NetworkService(protocol=TransportProtocol.TCP, port=constants.DNS.DEFAULT_PORT,
                               name=constants.DNS.SERVICE_NAME, credentials=[]),
            ]
        ),
        # ----------------------- DMZ -----------------------
        # Video Server IP [x.x.2.21]
        NodeServicesConfig(
            ip=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.2.21",
            services=[
                NetworkService(protocol=TransportProtocol.TCP, port=constants.SSH.DEFAULT_PORT,
                               name=constants.SSH.SERVICE_NAME, credentials=[]),
                NetworkService(protocol=TransportProtocol.TCP, port=constants.HTTP.DEFAULT_PORT,
                               name=constants.HTTP.SERVICE_NAME, credentials=[]),
                NetworkService(protocol=TransportProtocol.TCP, port=constants.MYSQL.DEFAULT_PORT,
                               name=constants.MYSQL.SERVICE_NAME, credentials=[]),
            ]
        ),
        # Webcam Server IP [x.x.2.22]
        NodeServicesConfig(
            ip=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.2.22",
            services=[
                NetworkService(protocol=TransportProtocol.TCP, port=constants.SSH.DEFAULT_PORT,
                               name=constants.SSH.SERVICE_NAME, credentials=[])
            ]
        ),
        # ----------------------- INTRANET -----------------------
        # Employee IP [x.x.3.31]
        NodeServicesConfig(
            ip=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.3.31",
            services=[
                NetworkService(protocol=TransportProtocol.TCP, port=constants.SSH.DEFAULT_PORT,
                               name=constants.SSH.SERVICE_NAME, credentials=[])
            ]
        ),
        # ----------------------- MIX -----------------------
        # Kafka
        NodeServicesConfig(
            ip=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}."
               f"{collector_constants.EXTERNAL_NETWORK.NETWORK_ID_THIRD_OCTET}.254",
            services=[
                NetworkService(protocol=TransportProtocol.TCP, port=constants.SSH.DEFAULT_PORT,
                               name=constants.SSH.SERVICE_NAME, credentials=[])
            ]
        ),
        # Router
        NodeServicesConfig(
            ip=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}.1.10",
            services=[
                NetworkService(protocol=TransportProtocol.TCP, port=constants.SSH.DEFAULT_PORT,
                               name=constants.SSH.SERVICE_NAME, credentials=[])
            ]
        ),
    ]
    service_cfg = ServicesConfig(
        services_configs=services_configs
    )
    return service_cfg


def default_static_attacker_sequences(subnet_masks: List[str]) -> Dict[str, List[EmulationAttackerAction]]:
    """
    Generates default attacker sequences config

    :param subnetmasks: list of subnet masks for the emulation
    :return: the default static attacker sequences configuration
    """
    d = {}
    d[constants.STATIC_ATTACKERS.EXPERT] = [
        EmulationAttackerShellActions.INSTALL_TOOLS(index=-1),

        EmulationAttackerShellActions.DNSENUM(index=-1),

        EmulationAttackerNMAPActions.TCP_CON_NON_STEALTH_SCAN(index=-1, ips=subnet_masks),

        EmulationAttackerNIKTOActions.NIKTO_WEB_HOST_SCAN(index=-1, ips=subnet_masks),

        EmulationAttackerShellActions.FFUF(index=-1),

        EmulationAttackerShellActions.CVE_2023_26035_EXPLOIT(index=-1),
        
        EmulationAttackerShellActions.ROOT_COMMANDS2(index=-1)
        # exit
        # id
        # pwd
        # cat /etc/shadow
        # lspci
        # command -v lsusb
        # date
        # find /usr -name \*virtualbox\*
        # sudo iptables -A INPUT -m conntrack --ctstate NEW,ESTABLISHED,RELATED -p tcp -s 192.168.33.65 -j DROP
        # sudo iptables -D INPUT -m conntrack --ctstate NEW,ESTABLISHED,RELATED -p tcp -s 192.168.33.65 -j DROP

    ]
    return d


def default_ovs_config(network_id: int, level: int, version: str) -> OVSConfig:
    """
    Generates default OVS config

    :param network_id: the network id of the emulation
    :param level: the level of the emulation
    :param version: the version of the emulation
    :return: the default OVS config
    """
    ovs_config = OVSConfig(switch_configs=[
    ])
    return ovs_config


def default_sdn_controller_config(network_id: int, level: int, version: str, time_step_len_seconds: int) \
        -> Union[None, SDNControllerConfig]:
    """
    Generates the default SDN controller config

    :param network_id: the network id of the emulation
    :param level: the level of the emulation
    :param version: the version of the emulation
    :param time_step_len_seconds: default length of a time-step in the emulation
    :return: the default SDN Controller config
    """
    return None


def default_host_manager_config(network_id: int, level: int, version: str, time_step_len_seconds: int) \
        -> HostManagerConfig:
    """
    Generates the default host manager configuration

    :param network_id: the id of the emulation network
    :param level: the level of the emulation
    :param version: the version of the emulation
    :param time_step_len_seconds: default length of a time-step in the emulation
    :return: the host manager configuration
    """
    config = HostManagerConfig(version=version, time_step_len_seconds=time_step_len_seconds,
                               host_manager_port=collector_constants.MANAGER_PORTS.HOST_MANAGER_DEFAULT_PORT,
                               host_manager_log_file=collector_constants.LOG_FILES.HOST_MANAGER_LOG_FILE,
                               host_manager_log_dir=collector_constants.LOG_FILES.HOST_MANAGER_LOG_DIR,
                               host_manager_max_workers=collector_constants.GRPC_WORKERS.DEFAULT_MAX_NUM_WORKERS)
    return config


def default_snort_ids_manager_config(network_id: int, level: int, version: str, time_step_len_seconds: int) \
        -> SnortIDSManagerConfig:
    """
    Generates the default Snort IDS manager configuration

    :param network_id: the id of the emulation network
    :param level: the level of the emulation
    :param version: the version of the emulation
    :param time_step_len_seconds: default length of a time-step in the emulation
    :return: the Snort IDS manager configuration
    """
    config = SnortIDSManagerConfig(
        version=version, time_step_len_seconds=time_step_len_seconds,
        snort_ids_manager_port=collector_constants.MANAGER_PORTS.SNORT_IDS_MANAGER_DEFAULT_PORT,
        snort_ids_manager_log_dir=collector_constants.LOG_FILES.SNORT_IDS_MANAGER_LOG_DIR,
        snort_ids_manager_log_file=collector_constants.LOG_FILES.SNORT_IDS_MANAGER_LOG_FILE,
        snort_ids_manager_max_workers=collector_constants.GRPC_WORKERS.DEFAULT_MAX_NUM_WORKERS)
    return config


def default_ossec_ids_manager_config(network_id: int, level: int, version: str, time_step_len_seconds: int) \
        -> OSSECIDSManagerConfig:
    """
    Generates the default OSSEC IDS manager configuration

    :param network_id: the id of the emulation network
    :param level: the level of the emulation
    :param version: the version of the emulation
    :param time_step_len_seconds: default length of a time-step in the emulation
    :return: the OSSEC IDS manager configuration
    """
    config = OSSECIDSManagerConfig(
        version=version, time_step_len_seconds=time_step_len_seconds,
        ossec_ids_manager_port=collector_constants.MANAGER_PORTS.OSSEC_IDS_MANAGER_DEFAULT_PORT,
        ossec_ids_manager_log_file=collector_constants.LOG_FILES.OSSEC_IDS_MANAGER_LOG_FILE,
        ossec_ids_manager_log_dir=collector_constants.LOG_FILES.OSSEC_IDS_MANAGER_LOG_DIR,
        ossec_ids_manager_max_workers=collector_constants.GRPC_WORKERS.DEFAULT_MAX_NUM_WORKERS)
    return config


def default_docker_stats_manager_config(network_id: int, level: int, version: str, time_step_len_seconds: int) \
        -> DockerStatsManagerConfig:
    """
    Generates the default docker stats manager configuration

    :param network_id: the id of the emulation network
    :param level: the level of the emulation
    :param version: the version of the emulation
    :param time_step_len_seconds: default length of a time-step in the emulation
    :return: the docker stats manager configuration
    """
    config = DockerStatsManagerConfig(
        version=version, time_step_len_seconds=time_step_len_seconds,
        docker_stats_manager_port=collector_constants.MANAGER_PORTS.DOCKER_STATS_MANAGER_DEFAULT_PORT,
        docker_stats_manager_log_file=collector_constants.LOG_FILES.DOCKER_STATS_MANAGER_LOG_FILE,
        docker_stats_manager_log_dir=collector_constants.LOG_FILES.DOCKER_STATS_MANAGER_LOG_DIR,
        docker_stats_manager_max_workers=collector_constants.GRPC_WORKERS.DEFAULT_MAX_NUM_WORKERS)
    return config


def default_elk_config(network_id: int, level: int, version: str, time_step_len_seconds: int) -> ElkConfig:
    """
    Generates the default ELK configuration

    :param network_id: the id of the emulation network
    :param level: the level of the emulation
    :param version: the version of the emulation
    :param time_step_len_seconds: default length of a time-step in the emulation
    :return: the ELK configuration
    """
    container = NodeContainerConfig(
        name=f"{constants.CONTAINER_IMAGES.ELK_1}",
        os=constants.CONTAINER_OS.ELK_1_OS,
        ips_and_networks=[
            (f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}."
             f"{collector_constants.ELK_CONFIG.NETWORK_ID_THIRD_OCTET}."
             f"{collector_constants.ELK_CONFIG.NETWORK_ID_FOURTH_OCTET}",
             ContainerNetwork(
                 name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_"
                      f"{collector_constants.ELK_CONFIG.NETWORK_ID_THIRD_OCTET}",
                 subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                             f"{network_id}.{collector_constants.ELK_CONFIG.NETWORK_ID_THIRD_OCTET}"
                             f"{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                 subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                 bitmask=constants.CSLE.CSLE_EDGE_BITMASK
             )),
        ],
        version=version, level=str(level),
        restart_policy=constants.DOCKER.ON_FAILURE_3, suffix=collector_constants.ELK_CONFIG.SUFFIX)

    resources = NodeResourcesConfig(
        container_name=f"{constants.CSLE.NAME}-"
                       f"{constants.CONTAINER_IMAGES.ELK_1}_1-{constants.CSLE.LEVEL}{level}",
        num_cpus=2, available_memory_gb=16,
        ips_and_network_configs=[
            (f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}."
             f"{collector_constants.ELK_CONFIG.NETWORK_ID_THIRD_OCTET}."
             f"{collector_constants.ELK_CONFIG.NETWORK_ID_FOURTH_OCTET}",
             None)])

    firewall_config = NodeFirewallConfig(
        hostname=f"{constants.CONTAINER_IMAGES.ELK_1}_1",
        ips_gw_default_policy_networks=[
            DefaultNetworkFirewallConfig(
                ip=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}."
                   f"{collector_constants.ELK_CONFIG.NETWORK_ID_THIRD_OCTET}."
                   f"{collector_constants.ELK_CONFIG.NETWORK_ID_FOURTH_OCTET}",
                default_gw=None,
                default_input=constants.FIREWALL.ACCEPT,
                default_output=constants.FIREWALL.ACCEPT,
                default_forward=constants.FIREWALL.ACCEPT,
                network=ContainerNetwork(
                    name=f"{constants.CSLE.CSLE_NETWORK_PREFIX}{network_id}_"
                         f"{collector_constants.ELK_CONFIG.NETWORK_ID_THIRD_OCTET}",
                    subnet_mask=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}"
                                f"{network_id}.{collector_constants.ELK_CONFIG.NETWORK_ID_THIRD_OCTET}"
                                f"{constants.CSLE.CSLE_EDGE_SUBNETMASK_SUFFIX}",
                    subnet_prefix=f"{constants.CSLE.CSLE_SUBNETMASK_PREFIX}{network_id}",
                    bitmask=constants.CSLE.CSLE_EDGE_BITMASK
                )
            )
        ],
        output_accept=set([]),
        input_accept=set([]),
        forward_accept=set([]),
        output_drop=set(), input_drop=set(), forward_drop=set(), routes=set())

    config = ElkConfig(version=version, time_step_len_seconds=time_step_len_seconds,
                       elastic_port=collector_constants.ELK.ELASTIC_PORT,
                       kibana_port=collector_constants.ELK.KIBANA_PORT,
                       logstash_port=collector_constants.ELK.LOGSTASH_PORT,
                       elk_manager_port=collector_constants.MANAGER_PORTS.ELK_MANAGER_DEFAULT_PORT,
                       container=container,
                       resources=resources, firewall_config=firewall_config,
                       elk_manager_log_file=collector_constants.LOG_FILES.ELK_MANAGER_LOG_FILE,
                       elk_manager_log_dir=collector_constants.LOG_FILES.ELK_MANAGER_LOG_DIR,
                       elk_manager_max_workers=collector_constants.GRPC_WORKERS.DEFAULT_MAX_NUM_WORKERS)
    return config


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--install", help="Boolean parameter, if true, install config",
                        action="store_true")
    parser.add_argument("-u", "--uninstall", help="Boolean parameter, if true, uninstall config",
                        action="store_true")
    args = parser.parse_args()
    config = default_config(name="csle-level17-070", network_id=17, level=17, version="0.7.0", time_step_len_seconds=30)
    ExperimentUtil.write_emulation_config_file(config, ExperimentUtil.default_emulation_config_path())

    if args.install:
        EmulationEnvController.install_emulation(config=config)
        img_path = ExperimentUtil.default_emulation_picture_path()
        if os.path.exists(img_path):
            encoded_image_str = ExperimentUtil.read_env_picture(img_path)
            EmulationEnvController.save_emulation_image(img=encoded_image_str, emulation_name=config.name)
    if args.uninstall:
        EmulationEnvController.uninstall_emulation(config=config)