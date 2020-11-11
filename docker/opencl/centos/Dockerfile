FROM nvidia/opencl:runtime-centos7

RUN yum update -y && yum install -y epel-release && yum install -y gcc-c++ make clinfo opencl-headers &&\
yum install -y python36 python36-libs python36-devel python36-pip git circus wget openldap-devel minizip-devel && yum update -y
 
ENV DOCKYARD=/opt/crackq/build

# Copy the code to the build dir
COPY . $DOCKYARD
WORKDIR $DOCKYARD
RUN $DOCKYARD/setup.sh --docker

EXPOSE 6379
EXPOSE 8081
EXPOSE 8080

ENV LANG "en_US.UTF-8"
ENV LC_ALL "en_US.UTF-8"

USER crackq
WORKDIR $DOCKYARD/
CMD ["/usr/local/bin/circusd", "/opt/crackq/build/circus.ini"]
