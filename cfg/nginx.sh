#!/bin/bash

rm /var/run/fail2ban/fail2ban.sock
service nginx start
service fail2ban start
tail -f /var/log/nginx/access.log
