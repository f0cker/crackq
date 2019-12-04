#!/bin/bash

echo 'WARNING: Using openldap container for dev purposes, this needs configuring/hardening for pro    duction use'
echo 'See https://github.com/osixia/docker-openldap for details of this container'
echo 'Waiting for LDAP service to start'
    until (echo 0 > /dev/tcp/127.0.0.1/389) 2>/dev/null; do
        printf '.'
        sleep 5
    done
    ldapadd -x -D 'cn=admin,dc=example,dc=org' -w admin -f /container/service/slapd/assets/test/crackq_user1.ldif -H ldap://localhost -ZZ
    ldapadd -x -D 'cn=admin,dc=example,dc=org' -w admin -f /container/service/slapd/assets/test/crackq_user2.ldif -H ldap://localhost -ZZ


