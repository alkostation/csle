# Adversary Emulation and Traces Collection for Emulation Level 16

These are the steps that the attacker agent will execute on the emulated environment:

1. **Reconnaissance**
    - Network & host mapping (traceroute, DMZ/LAN scans).
    - Connect to the available openVPN server.
    - Web enumeration (dirb_scan, wpscan).
2. **Exploitation**
    - PHP web-shell upload via AJAX (image upload plugin).
3. **Privilege Escalation**
    - Select users from the MySQL database to obtain the hash.
    - Crack WP hash → plaintext creds (crack_wphash)
    - Reverse shell upgrade & PTY spawn (open_reverse_shell, open_pty)
4. **Persistence**
    - Malicious PHP shell left in /wp-content/uploads/
5. **Post-Exploitation**
    - Host profiling (uname, ifconfig, netstat, ps, df, uptime)
    - Export WP users table (dump_wp_users)
    - Disconnect from the openVPN server.

## Commands

To run a script, execute:
```bash
python3 <script_name>
```

## Author & Maintainer

Marco Campione <campione@kth.se>

Mateus Marinheiro <mateusma@kth.se>

## Copyright and license

[LICENSE](../../../LICENSE.md)

Creative Commons

(C) 2020-2024, Kim Hammar