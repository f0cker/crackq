FROM nvidia/opencl:runtime-centos7

# docker build -t nvidia-centos .
# docker network create crackq_net
# docker run --network crackq_net -d --name redis redis
# docker run --runtime=nvidia --name crackq -p8080:8080 -v /var/crackq/:/var/crackq --network crackq_net -it nvidia-centos

RUN yum update -y && yum install -y epel-release && yum install -y gcc make clinfo opencl-headers &&\
yum install -y python36 python36-libs python36-devel python36-pip git circus wget libopenldap-devel && yum update -y
 
ENV DOCKYARD=/opt/crackq/build
#ENV PYTHONPATH=$DOCKYARD:/opt/crackq/build/

# Copy the code to the build dir
COPY . $DOCKYARD
#COPY ./docker/nvidia/centos/ $DOCKYARD
# Install RQ and set it up
WORKDIR $DOCKYARD
RUN $DOCKYARD/setup.sh --docker

EXPOSE 6379
EXPOSE 8081
EXPOSE 8080

ENV LANG "en_US.UTF-8"
ENV LC_ALL "en_US.UTF-8"

RUN groupadd -r crackq && useradd -r -g crackq crackq
RUN chown crackq:crackq $DOCKYARD/crackq && chown -R crackq:crackq /var/crackq/
USER crackq
WORKDIR $DOCKYARD/
CMD ["/usr/local/bin/circusd", "/opt/crackq/build/circus.ini"]
