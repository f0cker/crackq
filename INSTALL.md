Install Guide
============

Pre-installation
----------------
Install all requirements, namely docker, docker-compose and your choice of drivers.

**CentOS**

```
sudo yum install -y epel-release
sudo yum install -y yum-utils device-mapper-persistent-data lvm2
```

Add the Docker repo and install (or use other preferred install method):

```
sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
sudo yum install docker-ce docker-ce-cli containerd.io
```

**NOTE: Nvidia runtime support is required, so this is the reason for using the latest version from the repo above. It's not supported in the version from the Ubuntu repo, at the time of writing. Same goes for docker-compose**

**Ubuntu**

Guide taken from here here: https://docs.docker.com/v17.09/engine/installation/linux/docker-ce/ubuntu/#install-using-the-repository:

```
sudo apt-get install \
    apt-transport-https \
    ca-certificates \
    curl \
    software-properties-common

curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository \
   "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
   $(lsb_release -cs) \
   stable"
sudo apt-get update
sudo apt-get install docker-ce
```

Install docker-compose (see here for latest version https://docs.docker.com/compose/install/#install-compose):

```
sudo curl -L "https://github.com/docker/compose/releases/download/1.24.1/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

**Drivers**

To Install OpenCL drivers follow the guide here:
https://github.com/intel/compute-runtime/blob/master/documentation/BUILD_Centos.md

Or

For Nvidia you will need the nvidia container runtime package installed. Follow the steps here:
https://github.com/NVIDIA/nvidia-docker

**Ubuntu**

```
distribution=$(. /etc/os-release;echo $ID$VERSION_ID)
curl -s -L https://nvidia.github.io/nvidia-docker/gpgkey | sudo apt-key add -
curl -s -L https://nvidia.github.io/nvidia-docker/$distribution/nvidia-docker.list | sudo tee /etc/apt/sources.list.d/nvidia-docker.list

sudo apt-get update && sudo apt-get install -y nvidia-container-toolkit
sudo systemctl restart docker
sudo apt-get install nvidia-container-runtime
```

**CentOS**

```
distribution=$(. /etc/os-release;echo $ID$VERSION_ID)
curl -s -L https://nvidia.github.io/nvidia-docker/$distribution/nvidia-docker.repo | sudo tee /etc/yum.repos.d/nvidia-docker.repo

sudo yum install -y nvidia-container-toolkit
sudo systemctl restart docker
sudo yum install nvidia-container-runtime
```

Or

**ADD AMD GUIDE HERE**


**Installation**
--------------

When you have finished the initial configuration you then need to run the install script. It requires just one argument which is your preferred driver/os setup:

```
sudo ./install.sh docker/opencl/ubuntu
```

OR

```
sudo ./install.sh docker/nvidia/centos
```

After this the docker images will be built. However, some configuration is needed before launching.

**Configuration**
------------

**CrackQ Config**

Before running the application for the first time the config *crackq.conf* file will need to be completed relevant to the installation environment, setting the paths to the required files for cracking. The following changes are mandator for the tool to run successfully:

```
[wordlists]
leaks: /var/crackq/files/leaks.txt

[files]
log_dir: /var/crackq/logs/

[redis]
host: redis
port: 6379
#password: s0m3s3cr3tpwd

```
The default hashcat rules will be automatically setup and included within the config file.

You will also want to change the application's secret key under [app] SECRET_KEY.

Put your wordlists in /var/crackq/files, copy the config file to here:

*cp ./crackq.conf /var/crackq/files/*

Then modify the config file to your needs, specifically pointing it to your wordlists and any additional rules.

**NGINX Config**

To configure nginx, all config files are loaded from /var/crackq/files/nginx/, example configuration files are provided in ./cfg.
You will need to update the nginx config for your environment. This should just be a matter of editing the following line in ./cfg/crackq_nginx.conf and adding your cert file/key:

```
server_name crackq.org;
```

This file will then be copied to */var/crackq/files/nginx/* during installation.

TLS certs need to be placed here:

```
/var/crackq/files/nginx/conf.d/certificate.pem
/var/crackq/files/nginx/conf.d/private.pem
```

Or if you really want to you can use self signed certs by using the below OpenSSL commands:

```
<INSERT COMMANDS HERE>
```

Or if your box is on the public Internet (AWS EC2 for instance) you can use certbot/letsencrypt:

```
sudo apt-get install python-certbot
sudo certbot certonly --standalone -d crackq.org
sudo cp /etc/letsencrypt/keys/fullchain.pem /var/crackq/files/nginx/conf.d/certificate.pem
sudo cp /etc/letsencrypt/keys/privkey.pem /var/crackq/files/nginx/conf.d/private.pem
```

Don't forget to set the permissions accordingly if they are not already, config files should be only accessible to the crackq users (uid:1111).

You are now ready to launch the application using the containers you just built, this is done with the following docker-compose command (from the crackq dir):

```
sudo docker-compose -f docker-compose.nvidia.yml up --build
```

You can daemonize with the following command:

```
sudo docker-compose -f docker-compose.nvidia.yml up -d
```

There are multiple docker-compose files to choose from, the above is for a setup using Nvidia, though you could alternatively use docker-compose.opencl.yml, docker-compose.amd.yml or docker-compose.dev.yml depending on your setup.

If you don't need the OpenLDAP container comment that out of the docker-compose.xxx.yml file.

**Benchmark**

Finally, you will need to run a system benchmark, which unfortunately takes up to an hour. The good news is you only need to do this once per system. CrackQ uses this information when chosing to enable the brain. In a separate window execute the benchmark script from within the crackq container:

```
sudo docker exec -it crackq /opt/crackq/build/benchmark.sh
```

Also update the supported hash modes list:

```
sudo docker exec -it crackq python3 crackq/update_hashtypes.py
```


The above scripts will create 2 files used by hashcat (/var/crackq/files/sys\_benchmark.txt & /var/crackq/files/hashm\_dict.json ). The benchmarking requirement will likely be removed in later versions.

You can now stop the containers using CTRL-C and you are ready to setup authentication.


**Authentication Setup**
---------------

There are currently 2 options for authentication - LDAP or SAML2. **If you don't have either of these setup in your network or you want to keep authentication for CrackQ segregated, there is a demo LDAP server docker container you can use (See Demo LDAP Configuration below).**


**LDAP Configuration**

Specify the auth type and location of the LDAP server in the crackq.conf. The following settings should be populated:

```
[auth]
type: ldap
ldap_server: ldaps://xxx.xxx.com
ldap_base: dc=example,dc=org
group: domain\Domain Users
```

**SAML2 Configuration**

Specify the manifest XML file location for your SAML2 IDP service within the config file and add the entity ID which is usually the server URL. Additionally, set the certificaate files. These can be reused form the NGinx certs and will be used to sign requests, though most setups don't sign requests, just the response from the IDP service.

The SAML manifest is a URL pointing to the IDP server manifest xml. For MS this is usually located at /FederationMetadata/2007-06/FederationMetadata.xml. The file 'meta_file' is a location to store this locally.

```
[auth]
type: saml2
saml_manifest: https://sso.xxx.com/FederationMetadata/2007-06/FederationMetadata.xml
meta_file = /var/crackq/files/saml/idp_meta_file.xml
entity_id = https://crackq.xxx.com
group = domain\Domain Users
sp_cert_file = /var/crackq/files/saml/certificate.pem
sp_key_file = /var/crackq/files/saml/private.key

```

Generate a metadata file for our side by using the following command:

```
sudo docker exec -it crackq make_metadata.py ./crackq/sp_conf.py > /<insert-accessible-path>/sp_meta_file.xml
```

This can be used to import on the authenticating IDP server to allow the CrackQ server to act as the SP. So the next step should be to import this to the authenticating IDP server.

Specify the group to use for authorization requests, this is the domain group in the case of MS ADFS. This file can be provided to the IDP administrators to permit authentication form this SP (CrackQ).

**Demo LDAP Configuration**

Skip this part if you are using your own LDAP server or SAML2 auth.

Firstly, point the configuration file to the internal LDAP server:

```
[auth]
type: ldap
ldap_server: ldap://ldap.crackq.org
group: domain\Domain Users
```

Adding users using the demo LDAP server container:
Generate LDAP SHA hash:

```
sudo docker exec ldap.crackq.org slappasswd -h {SSHA} -s <new-password>
```

Copy one of the example LDIF files:

```
cp ./docker/openldap/bootstrap/crackq_user1.ldif ./docker/openldap/bootstrap/<user>.ldif
```

Then modify the file to your chosen username and insert the above generated SHA hash.

Add the LDAP user from the LDIF file:

```
sudo docker exec ldap.crackq.org ldapadd -x -D 'cn=admin,dc=example,dc=org' -w <admin-password> -f /container/service/slapd/assets/config/bootstrap/ldif/custom/test.ldif -H ldap://localhost
```
Or to prompt for password:

```
sudo docker exec ldap.crackq.org ldapadd -x -D 'cn=admin,dc=example,dc=org' -W -f /container/service/slapd/assets/config/bootstrap/ldif/custom/test.ldif -H ldap://localhost
```


The default admin account is created when the container is initially run, the password for this account is set within the docker compose file (docker-compose.xxx.yml, where xxx is dependant on your driver setup). **Don't forget to change this after the container is initialized.**
Also modify any of the other LDAP config options there as needed.

Just to reiterate, it is not recommended to use the demo LDAP server in production without further hardening. However, there is a task to do this on the project roadmap.


Notification Settings
--------------

CrackQ currently supports notifications via email using SMTP. I will add another notification method in the future, but haven't decided which one yet. If you would like to see Slack, Telegram, SMS or some other notification added please let me know and I'll go with the majority.

Add your relevant SMTP mail server settings to the config file: 

```
[notify]
mail_server: mail.crackq.org
mail_port: 465
src: crackq@crackq.org
inactive_time: 20
tls: True
```

The inactive_time setting is the time to wait since last user activity before sending event notifications in minutes (there's no sense sending email if you're actively looking at the progress).

If you need to provide credentials to the SMTP server you will need them as environment variables, which will be passed to the crackq docker container before you execute docker-compose:
```
export MAIL_USERNAME=<your-mail-username>
export MAIL_PASSWORD=<your-mail-password>
```

Run The Application
------------

That's it you're all done with the installation/configuration! Run the docker containers again with:

```
sudo docker-compose -f docker-compose.nvidia.yml up --build
```

**Troubleshooting**
---------------

```
ERROR: The Compose file './docker-compose.nvidia.yml' is invalid because:
Unsupported config option for services.crackq: 'runtime'
```
This is due to the version of docker installed, you probably skipped step 1 and installed from the OS repo ;)

```
ERROR: for crackq  Cannot create container for service crackq: Unknown runtime specified nvidia
```
Install the NVidia container toolkit and runtime: https://github.com/NVIDIA/nvidia-docker

```
crackq      | FileNotFoundError: [Errno 2] No such file or directory: '/var/crackq/files/hashm_dict.json'
```

This is because you haven't run the benchmark script (see above), the benchmark creates a file listing all supported hashtypes and their benchmark speed into a file, which is needed by CrackQ. In a pinch you can ask it to copy the default benchmark file, but this is obviously not a good choice as all the brain callibration will be off.

```
sqlalchemy.exc.OperationalError: (sqlite3.OperationalError)
```
If you see SQL related error it's most likely due to an outdated SQL schema, I've made changes to the user model a couple of times since release. To resolve this, just delete the sqlite DB at /var/crackq/files/crackqdb/sqlite and a new one will be created automatically when you restart the container. I will be adding DB migration in a future update which will handle any schema changes automagically.


If you have any issues and need to debug from within one of the containers, the container names are:

nginx,
crackq,
redis,
ldap.crackq.org,

You can drop to a shell within the container using:

```
sudo docker exec -it crackq /bin/bash
```
