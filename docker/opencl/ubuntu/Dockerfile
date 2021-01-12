FROM ubuntu:18.04

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update -q && apt-get install --no-install-recommends -yq alien wget unzip clinfo libminizip-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Download the Intel OpenCL 2.0 development headers
#RUN export DEVEL_URL="https://software.intel.com/file/531197/download" \
#    && wget ${DEVEL_URL} -q -O download.zip --no-check-certificate \
#    && unzip download.zip \
#    && rm -f download.zip *.tar.xz* \
#    && alien --to-deb *dev*.rpm \
#    && dpkg -i *dev*.deb \
#    && rm *.rpm *.deb

# Download the Intel OpenCL CPU runtime and convert to .deb packages
RUN export RUNTIME_URL="http://registrationcenter-download.intel.com/akdlm/irc_nas/9019/opencl_runtime_16.1.1_x64_ubuntu_6.4.0.25.tgz" \
    && export TAR=$(basename ${RUNTIME_URL}) \
    && export DIR=$(basename ${RUNTIME_URL} .tgz) \
    && wget -q ${RUNTIME_URL} \
    && tar -xf ${TAR} \
    && for i in ${DIR}/rpm/*.rpm; do alien --to-deb $i; done \
    && rm -rf ${DIR} ${TAR} \
    && dpkg -i *.deb \
    && rm *.deb

RUN mkdir -p /etc/OpenCL/vendors/ \
    && echo "/opt/intel/opencl-1.2-6.4.0.25/lib64/libintelocl.so" > /etc/OpenCL/vendors/intel.icd

# Let the system know where to find the OpenCL library at runtime
ENV OCL_INC /opt/intel/opencl/include
ENV OCL_LIB /opt/intel/opencl-1.2-6.4.0.25/lib64
ENV LD_LIBRARY_PATH $OCL_LIB:$LD_LIBRARY_PATH
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
