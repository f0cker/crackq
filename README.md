CrackQ
============

Author: Daniel Turner
@f0cker_

------------


Python 3 REST API & JS GUI for managing hashcat crack jobs in a queuing system.


[![PyPI license](https://img.shields.io/pypi/l/ansicolortags.svg)](https://pypi.python.org/pypi/ansicolortags/)
[![PyPI status](https://img.shields.io/pypi/status/ansicolortags.svg)](https://pypi.python.org/pypi/ansicolortags/)
[![Python 3.7](https://img.shields.io/badge/python-3.4+-blue.svg)](https://www.python.org/downloads/release/python-370/)





![CrackQ Dashboard](docs/crackq_dash.jpg)


Feature List
------------

* LDAP or SAML2 Authentication
* Multi-user support with privilege separation for jobs
* Uses Hashcat API directly via libhashcat, no shell commands
* Job queues with pause/restore/move
* Detailed job stats/charts for active jobs
* Email notifications when a hash cracks or job finishes
* Cracked passwords analysis and reporting
* Automated Brain integration, Brain activates when it becomes efficient
* Python remote REST client
* Markov stats pre-configured
* Sample mask files included

Requirements
------------

This tool has the following requirements:

* Drivers
	* OpenCL drivers - these can be installed from a repository or downloaded from the relevant vendor. Tested using Intel runtime.
	* Nvida drivers
	* AMD drivers

* Docker

* Nvidia-runtime

* Docker-compose

It is recommended to have a hefty server build with ample RAM/CPU power. However, the application has been tested on a VM with 8 cores and 4GB RAM so there should not be any issues with resources given that the server will need a good amount of resources for cracking anyway.

See the [Wiki](https://github.com/f0cker/crackq/wiki) or INSTALL.md for installation guides.

