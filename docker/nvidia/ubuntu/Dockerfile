FROM nvidia/cuda:runtime-ubuntu20.04

#ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update -q && apt-get install --no-install-recommends -yq wget unzip clinfo libminizip-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ENV DOCKYARD=/opt/crackq/build
ENV PYTHONPATH=$DOCKYARD:/opt/crackq/build/crackq

# Update & install packages for installing hashcat
RUN apt-get update && \
    apt-get install -y wget p7zip gcc g++ make build-essential git libcurl4-openssl-dev libssl-dev zlib1g-dev python3.7 \
    python3.7-dev python3-pip libldap2-dev libsasl2-dev libssl-dev xmlsec1 libxmlsec1-openssl

# Copy the code to the build dir
COPY . $DOCKYARD
# Run install script to setup hashcat/pyhashcat
WORKDIR $DOCKYARD
RUN $DOCKYARD/setup.sh

EXPOSE 6379
EXPOSE 8081
EXPOSE 8080

ENV LANG "C.UTF-8"
ENV LC_ALL "C.UTF-8"

RUN chown -R 1111:1111 $DOCKYARD/
USER crackq
WORKDIR $DOCKYARD/
CMD ["/usr/local/bin/circusd", "/opt/crackq/build/circus.ini"]
