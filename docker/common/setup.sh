#!/bin/bash

# Setup crackq user
groupadd -g 1111 -r crackq && useradd -u 1111 -r -g crackq crackq
mkdir /home/crackq && chown crackq:crackq /home/crackq

#sudo -u crackq 

# Run pip install
python3 -m pip install --upgrade pip
python3 -m pip install -r ./requirements.txt

#Install modified flask-sessions
#temporarily using session_fixation branch for dev/updates
git clone https://github.com/f0cker/flask-session.git -b session_fixation
cd ./flask-session
python3 -m pip install .
cd ../

#Install pypal and pre-download nltk wordnet
git clone https://github.com/f0cker/pypal.git
cd ./pypal
python3 -m pip install .
cd ../
python3 -c 'import nltk; nltk.download("wordnet")'

# Install Circusd
python3 -m pip install circus

# Install Gunicorn
python3 -m pip install gunicorn

# Install modified RQ version while waiting for merge
#git clone https://github.com/f0cker/rq.git
#cd ./rq
#python3 -m pip install .
#cd ../

#Download and compile pyhashcat & Hashcat
git clone https://github.com/f0cker/pyhashcat.git
cd ./pyhashcat/pyhashcat

#install stable hashcat
wget https://github.com/hashcat/hashcat/archive/refs/tags/v6.2.1.tar.gz
tar xvfz v*.tar.gz && mv hashcat-* hashcat
#or install latest hashcat from git
#git clone https://github.com/hashcat/hashcat.git
cd hashcat/
make uninstall
make clean
make install
make install_library
cd ../
python3 setup.py build_ext
python3 setup.py install
