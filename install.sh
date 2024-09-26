#!/bin/bash
# Installation script to get Docker setup. Provide single
# argument: driver type and os (Ubuntu or Centos supported)
# in the following format docker/nvidia/ubuntu


if [ $# -lt 1 ]
	then
		echo "Argument required: docker/driver/os"
		exit
elif [ $# -gt 1 ]
	then
		echo "Building for tests"
		TESTS=true
fi
OS=$(echo $1 | cut -d '/' -f 3)
DRIVER=$(echo $1 | cut -d '/' -f 2)

if [ ! -d ./build ]
	then
		mkdir ./build
    fi
if [ ! -d /var/crackq/files/templates ]
	then
                mkdir /var/crackq/
                mkdir /var/crackq/files/
                mkdir /var/crackq/logs/
                mkdir /var/crackq/logs/reports/
                mkdir /var/crackq/logs/nginx/
		mkdir /var/crackq/logs/templates/
                mkdir /var/crackq/files/masks/
                mkdir /var/crackq/files/nginx/
                mkdir /var/crackq/files/nginx/conf.d/
                mkdir /var/crackq/files/saml/
                mkdir /var/crackq/files/rules/
                mkdir /var/crackq/files/masks/
                mkdir /var/crackq/files/wordlists/
    fi

cp ./cfg/nginx.conf /var/crackq/files/nginx/
cp ./cfg/crackq_nginx.conf /var/crackq/files/nginx/conf.d/
cp ./cfg/crackq.hcstat /var/crackq/files/crackq.hcstat
cp ./masks/* /var/crackq/files/masks/
cp -r ./rules/ /var/crackq/files/
if [ ! -f /var/crackq/files/wordlists/rockyou.txt.gz ]
	then
		wget https://github.com/praetorian-inc/Hob0Rules/raw/master/wordlists/rockyou.txt.gz
		mv rockyou.txt.gz /var/crackq/files/wordlists/
	fi

echo "" >>  ./cfg/crackq.conf
echo "[wordlists]" >> ./cfg/crackq.conf
for file in /var/crackq/files/wordlists/*; do
  if [ -f "$file" ]; then
    echo "$(basename "$file"): $file"
  fi
done >> ./cfg/crackq.conf
echo "" >> ./cfg/crackq.conf

echo "[rules]" >> ./cfg/crackq.conf
for file in /var/crackq/files/rules/*; do
  if [ -f "$file" ]; then
    echo "$(basename "$file"): $file"
  fi
done >> ./cfg/crackq.conf

echo "" >> ./cfg/crackq.conf

echo "[masks]" >> ./cfg/crackq.conf
for file in /var/crackq/files/masks/*; do
  if [ -f "$file" ]; then
    echo "$(basename "$file"): $file"
  fi
done >> ./cfg/crackq.conf


# check if running tests
if [ $TESTS ]
	then
		cp -r ./crackq/ ./build/
		cp -r ./utils/ ./build/
		cp ./cfg/hashm_dict.json /var/crackq/files/
		rm /var/crackq/files/crackq.conf
		cp ./cfg/crackq.conf /var/crackq/files/
fi
if grep -q crackq /etc/group
then 
	echo 'crackq group already exists'
else
        groupadd -g 1111 -r crackq
	useradd -u 1111 -r -g crackq crackq
fi
chown -R 1111:1111 /var/crackq/
cp $1/* ./build
cp docker/common/* ./build
cp setup.py ./build/
cp ./crackq/log_config.ini ./build
cd ./build/
docker build -t "$DRIVER-crackq" . 
