#! /bin/bash

# Install dependencies
sudo apt-get update
sudo apt-get install -y python3
sudo apt-get install -y python3-pip
sudo apt-get install -y python-is-python3

sudo apt install -y libgtk-3-0
sudo apt install -y libasound2
sudo apt install -y libx11-xcb1

python3 -m pip install --upgrade pip
python3 -m pip install -U -r requirements.txt
python3 -m camoufox fetch
