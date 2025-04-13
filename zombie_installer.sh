#!/bin/bash

# Update Kali
sudo apt update && sudo apt upgrade -y

# Install Python if not already installed
if ! command -v python3 &> /dev/null; then
    sudo apt install python3 -y
fi

# Install pip
if ! command -v pip3 &> /dev/null; then
    sudo apt install python3-pip -y
fi

# Install required modules
pip3 install requests pycryptodome

# Make sure the bot script is executable
chmod +x zombie.py

# Run zombieware
python3 zombie.py
