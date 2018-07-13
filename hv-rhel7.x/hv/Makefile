obj-m	+= hv_vmbus.o
obj-m	+= hv_storvsc.o
obj-m	+= hv_netvsc.o
obj-m	+= hv_utils.o
obj-m	+= hid-hyperv.o
obj-m	+= hyperv_fb.o
obj-m	+= hv_balloon.o
obj-m	+= hyperv-keyboard.o

# Get machine bit length
arch=$(shell getconf LONG_BIT)

# RDMA should only build on 64 bits arch
ifeq ($(arch), 64)
        obj-m += hv_network_direct.o
endif

# Get RHEL/CentOS version information
rhel_major=$(shell grep -Eoh [0-9]+\.[0-9]+ /etc/{issue,*release} | head -1 | awk -F'.' '{ print $$1 }')
rhel_minor=$(shell grep -Eoh [0-9]+\.[0-9]+ /etc/{issue,*release} | head -1 | awk -F'.' '{ print $$2 }')
rhel_release_code=$(shell echo $$(($(rhel_major) << 8 | $(rhel_minor))))

# Kernel support for Hyper-V Sockets driver was introduced in RHEL/CentOS 7.4
# Only build the hv_sock driver on RHEL 7.4 and newer.
# The RHEL_RELEASE_CODE for RHEL/CentOS 7.3 = 1795.

build_hvsock=$(shell test $(rhel_release_code) -gt 1795; echo $$?)
ifeq ($(build_hvsock),0)
        obj-m	+= hv_sock.o
endif

# Kernel support for the Hyper-V PCI driver was introduced in RHEL/CentOS 7.3
# Only build the pci-hyperv driver on RHEL 7.3 and newer.
# The RHEL_RELEASE_CODE for RHEL/CentOS 7.2 = 1794.

build_pci=$(shell test $(rhel_release_code) -gt 1794; echo $$?)
ifeq ($(build_pci),0)
        obj-m	+= pci-hyperv.o
endif


# UIO underlying function are not yet in rhel6.x so make it conditional for future release
buildrdma=$(shell test $(rhel_release_code) -gt 1795; echo $$?)
ifeq ($(buildrdma),0)
        ifeq ($(arch), 64)
                obj-m   += uio_hv_generic.o
         endif
endif

# Get extra kernel version information beyond LINUX_VERSION_CODE or RHEL_RELEASE_CODE.
# This is used to identify RHEL/CentOS kernel update versions.
extraversioninfo = $(shell uname -r | awk -F'-' '{print $$2}')
extraversion1 = $(shell echo $(extraversioninfo) | awk -F'.' '{print $$1}' | grep -E '^[0-9]+$$')
ifneq ($(extraversion1),)
	ccflags-y += -DEXTRAVERSION1=$(extraversion1)
else
	ccflags-y += -DEXTRAVERSION1=0
endif

extraversion2 = $(shell echo $(extraversioninfo) | awk -F'.' '{print $$2}' | grep -E '^[0-9]+$$')
ifneq ($(extraversion2),)
	ccflags-y += -DEXTRAVERSION2=$(extraversion2)
else
	ccflags-y += -DEXTRAVERSION2=0
endif

ccflags-y += -I$(M)/include/ -I$(M)/arch/$(ARCH)/include -I$(M)/arch/$(ARCH)/include/uapi

CFLAGS_hv_trace.o = -I$(src)
CFLAGS_hv_balloon.o = -I$(src)

hv_vmbus-y := vmbus_drv.o \
		 hv.o connection.o channel.o  hv_trace.o \
		 channel_mgmt.o ring_buffer.o \
		 arch/$(ARCH)/hyperv/hv_init.o \
		 arch/$(ARCH)/hyperv/ms_hyperv_ext.o
hv_utils-y := hv_util.o hv_kvp.o hv_snapshot.o hv_fcopy.o hv_utils_transport.o

hv_storvsc-y := storvsc_drv.o
hv_netvsc-y := netvsc_drv.o netvsc.o rndis_filter.o
hyperv_keyboard-y := hyperv-keyboard.o
hv_network_direct-y := provider.o vmbus_rdma.o hvnd_addr.o
hv_sock-y := hyperv_transport.o
hv_uio_generic-y := uio_hv_generic.o

# Build MLX4 on RHEL 7.3 only
build_mlx=$(shell test $(rhel_release_code) -eq 1795; echo $$?)
ifeq ($(build_mlx),0)
	obj-m	+= mlx4/
endif
