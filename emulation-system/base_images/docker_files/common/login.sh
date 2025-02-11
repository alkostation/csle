#!/bin/bash
VPN=$(which openvpn)
[ -z "$VPN" ] && echo "Openvpn not found. Please install it!" || $VPN --config openvpn-config-sl700-daniel-cox.ovpn
exit