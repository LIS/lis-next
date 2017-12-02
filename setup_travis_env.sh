#!/bin/sh -xe

# we need to start a process in foreground in order to keep the container running
docker run --privileged -d -t -e "container=docker"  -v /sys/fs/cgroup:/sys/fs/cgroup -v `pwd`:/home/travis/build/chvalean/lis-next:rw  ${CENTOS}   /bin/bash

# get container ID for further use
DOCKER_CONTAINER_ID=$(sudo docker ps | grep centos | awk '{print $1}')
docker logs $DOCKER_CONTAINER_ID

# install a few dependencies
docker exec -t $DOCKER_CONTAINER_ID /bin/bash -xec "cat /etc/centos-release"
docker exec -t $DOCKER_CONTAINER_ID /bin/bash -xec "yum -y -q install automake make gcc wget"

if [[ "$BUILD" == "7.4.1708" ]]; then
  docker exec -t $DOCKER_CONTAINER_ID /bin/bash -xec "wget http://mirror.centos.org/centos/7/os/x86_64/Packages/kernel-devel-${KERNEL}.el7.x86_64.rpm"
elif [[ "$BUILD" == "7."* ]]; then
  docker exec -t $DOCKER_CONTAINER_ID /bin/bash -xec "wget http://88.208.217.170/${BUILD}/os/x86_64/Packages/kernel-devel-${KERNEL}.el7.x86_64.rpm"
  #
  # handling updated kernels
  #
  if [[ "$KERNEL" == "3.10.0-693.5.2" ]]; then
    docker exec -t $DOCKER_CONTAINER_ID /bin/bash -xec "wget http://88.208.217.170/${BUILD}/updates/x86_64/Packages/kernel-devel-${KERNEL}.el7.x86_64.rpm"
  fi
  if [[ "$KERNEL" == "3.10.0-514.26.2" ]]; then
    docker exec -t $DOCKER_CONTAINER_ID /bin/bash -xec "wget http://mirror.centos.org/centos/7/updates/x86_64/Packages/kernel-devel-${KERNEL}.el7.x86_64.rpm"
  fi
fi

if [[ "$BUILD" == "6.9" ]]; then
  docker exec -t $DOCKER_CONTAINER_ID /bin/bash -xec "wget http://mirror.centos.org/centos/${BUILD}/os/x86_64/Packages/kernel-devel-${KERNEL}.el6.x86_64.rpm"
elif [[ "$BUILD" == "6."* ]]; then
  docker exec -t $DOCKER_CONTAINER_ID /bin/bash -xec "wget http://88.208.217.170/${BUILD}/os/x86_64/Packages/kernel-devel-${KERNEL}.el6.x86_64.rpm"
fi

docker exec -t $DOCKER_CONTAINER_ID /bin/bash -xec "rpm -ivh kernel-devel-${KERNEL}*"

# work-around to skip warning during install, we won't boot the new kernel
docker exec -t $DOCKER_CONTAINER_ID /bin/bash -xec "mkdir -p /lib/modules/$(uname -r)/extra"
docker exec -t $DOCKER_CONTAINER_ID /bin/bash -xec "touch /lib/modules/$(uname -r)/modules.order"
docker exec -t $DOCKER_CONTAINER_ID /bin/bash -xec "touch /lib/modules/$(uname -r)/modules.builtin"
if [[ "$KERNEL" == "3.10."* ]]; then
  docker exec -t $DOCKER_CONTAINER_ID /bin/bash -xec "ln -s /usr/src/kernels/${KERNEL}.el7.x86_64 /lib/modules/$(uname -r)/build"
elif [[ "$BUILD" == "6."* ]]; then
  docker exec -t $DOCKER_CONTAINER_ID /bin/bash -xec "ln -s /usr/src/kernels/${KERNEL}.el6.x86_64 /lib/modules/$(uname -r)/build"
fi

# installing lis-next
if [[ "$BUILD" == "7"* ]]; then
  docker exec -t $DOCKER_CONTAINER_ID /bin/bash -xec "cd /home/travis/build/chvalean/lis-next/hv-rhel7.x/hv/ ; bash -e rhel7-hv-driver-install"
  docker exec -t $DOCKER_CONTAINER_ID /bin/bash -xec "cd /home/travis/build/chvalean/lis-next/hv-rhel7.x/hv/tools ; make"
elif [[ "$BUILD" == "6."* ]]; then
  docker exec -t $DOCKER_CONTAINER_ID /bin/bash -xec "cd /home/travis/build/chvalean/lis-next/hv-rhel6.x/hv/ ; bash -e rhel6-hv-driver-install"
  docker exec -t $DOCKER_CONTAINER_ID /bin/bash -xec "cd /home/travis/build/chvalean/lis-next/hv-rhel6.x/hv/tools ; make"
fi

# clean-up container
docker stop $DOCKER_CONTAINER_ID
docker rm -v $DOCKER_CONTAINER_ID
