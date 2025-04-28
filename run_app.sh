#!/bin/bash

# TCP Port is Open, SSH (e.g. SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8)
python app.py --tcp_port 22 --ip_address 34.209.82.230
read -p "Press Enter to continue..."

# TCP Port is Open, HTTP:
python app.py --tcp_port 80 --ip_address 34.209.82.230
read -p "Press Enter to continue..."

# TCP Port is Open, HTTPS, Bad SSL Certificate:
python app.py --tcp_port 443 --ip_address 34.209.82.230
read -p "Press Enter to continue..."

# TCP Port is Closed:
python app.py --tcp_port 22 --ip_address 65.130.44.199
read -p "Press Enter to continue..."


python app.py --tcp_port 80 --ip_address 65.130.44.199
read -p "Press Enter to continue..."

python app.py --tcp_port 443 --ip_address 65.130.44.199
read -p "Press Enter to continue..."
