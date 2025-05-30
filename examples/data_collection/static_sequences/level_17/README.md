# Adversary Emulation and Traces Collection for Emulation Level 17

These are the steps that the attacker agent will execute on the emulated environment:

1. **Reconnaissance**
    - Network & host mapping (dns-brute, nmap, nikto).
    - Web enumeration (ffuf).
2. **Exploitation**
    - Unauthenticated Remote Code Execution via Missing Authorization.
3. **Privilege Escalation**
    - Upload and execute privilege escalation search tool (linpeas).
    - Finds SSH key for root user.
    - Connect via SSH with the newly found key.
4. **Persistence**
    - Attacker adds new SSH key to authorized_keys.
5. **Post-Exploitation**
    - Host profiling (uname, ifconfig, netstat, ps, df, uptime)

## Commands

To run a script, execute:
```bash
python <script_name>
```

## Author & Maintainer

Marco Campione <campione@kth.se>

Mateus Marinheiro <mateusma@kth.se>

## Copyright and license

[LICENSE](../../../LICENSE.md)

Creative Commons

(C) 2020-2024, Kim Hammar