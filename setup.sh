#! /bin/bash

# Install dependencies
sudo apt-get update
sudo apt-get install -y python3
sudo apt-get install -y python3-pip
sudo apt-get install -y python-is-python3

python3 -m pip install --upgrade pip
python3 -m pip install -U -r requirements.txt
