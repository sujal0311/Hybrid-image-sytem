#!/usr/bin/env bash
# Install Node dependencies
npm install

# Install Python and dependencies
apt-get update
apt-get install -y python3 python3-pip
pip3 install numpy pillow
