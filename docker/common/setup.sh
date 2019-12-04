#!/bin/bash

# Run pip install
python3 -m pip install --upgrade pip
python3 -m pip install -r ./requirements.txt

#Install modified flask-sessions
git clone https://github.com/f0cker/flask-session.git
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

#Download and compile pyhashcat & Hashcat
#git clone https://github.com/f0cker/pyhashcat.git
#git clone https://github.com/f0cker/pyhashcat.git --branch hashcat6.0
git clone https://github.com/f0cker/pyhashcat.git --branch dev_temp
cd ./pyhashcat/pyhashcat

#move to static version when hashcat v6 is released
#wget https://github.com/hashcat/hashcat/archive/v5.1.0.tar.gz
#tar xvfz v5.1.0.tar.gz && mv hashcat-5.1.0 hashcat
git clone https://github.com/hashcat/hashcat.git
cd hashcat/
make uninstall
make clean
make install
make install_library
cd ../
python3 setup.py build_ext
python3 setup.py install
