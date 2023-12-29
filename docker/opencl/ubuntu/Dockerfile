FROM ubuntu:20.04

ENV TZ=Europe/London
ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update -q && apt-get install --no-install-recommends -yq ca-certificates gpg alien wget unzip clinfo libminizip-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

#Setup OpenCL drivers
RUN wget -O- https://apt.repos.intel.com/intel-gpg-keys/GPG-PUB-KEY-INTEL-SW-PRODUCTS.PUB --no-check-certificate| gpg --dearmor | tee /usr/share/keyrings/oneapi-archive-keyring.gpg
RUN echo "deb [signed-by=/usr/share/keyrings/oneapi-archive-keyring.gpg] https://apt.repos.intel.com/oneapi all main" | tee /etc/apt/sources.list.d/oneAPI.list
RUN apt update
RUN apt install intel-oneapi-runtime-libs intel-oneapi-runtime-opencl -yq

ENV DOCKYARD=/opt/crackq/build
ENV PYTHONPATH="$DOCKYARD":/opt/crackq/build/crackq

# Update & install packages for installing hashcat
RUN apt-get update && \
    apt-get install -y wget p7zip gcc g++ make build-essential git libcurl4-openssl-dev libssl-dev zlib1g-dev python3.8 \
    python3.8-dev python3-pip libldap2-dev libsasl2-dev libssl-dev xmlsec1 libxmlsec1-openssl \
    && apt-get clean
# Copy the code to the build dir
COPY . "$DOCKYARD"
# Run install script to setup hashcat/pyhashcat
WORKDIR "$DOCKYARD"
RUN "$DOCKYARD"/setup.sh

EXPOSE 6379
EXPOSE 8081
EXPOSE 8080

ENV LANG "C.UTF-8"
ENV LC_ALL "C.UTF-8"

RUN chown -R 1111:1111 "$DOCKYARD"/
USER crackq
WORKDIR "$DOCKYARD"/
CMD ["/usr/local/bin/circusd", "/opt/crackq/build/circus.ini"]
