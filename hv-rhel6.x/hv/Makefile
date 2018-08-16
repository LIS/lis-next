obj-m	+= hv_vmbus.o
obj-m	+= hv_storvsc.o
obj-m	+= hv_netvsc.o
obj-m	+= hv_utils.o
obj-m	+= hid-hyperv.o
obj-m	+= hyperv_fb.o
obj-m	+= hv_balloon.o
obj-m	+= hyperv-keyboard.o

# Get RHEL/CentOS version information
rhel_major=$(shell grep -Eoh [0-9]+\.[0-9]+ /etc/{issue,*release} | head -1 | awk -F'.' '{ print $$1 }')
rhel_minor=$(shell grep -Eoh [0-9]+\.[0-9]+ /etc/{issue,*release} | head -1 | awk -F'.' '{ print $$2 }')
rhel_release_code=$(shell echo $$(($(rhel_major) << 8 | $(rhel_minor))))

# Get machine bit length
arch=$(shell getconf LONG_BIT)

# RDMA should only build on RHEL/CentOS 6.5 or later, and on 64 bits arch
buildrdma=$(shell test $(rhel_release_code) -ge 1541; echo $$?)
ifeq ($(buildrdma),0)
        ifeq ($(arch), 64)
                obj-m += hv_network_direct.o
        endif
endif

# UIO underlying function are not yet in rhel6.x so make it conditional for future release
buildrdma=$(shell test $(rhel_release_code) -ge 1545; echo $$?)
ifeq ($(buildrdma),0)
        ifeq ($(arch), 64)
		obj-m   += uio_hv_generic.o
	 endif
endif

#Make it conditional for PCI driver to build 6.7 and above. 
build_pci=$(shell test $(rhel_release_code) -ge 1543; echo $$?)
ifeq ($(build_pci),0)
        obj-m	+= pci-hyperv.o
endif

ccflags-y += -I$(M)/include/ -I$(M)/arch/$(SRCARCH)/include -I$(M)/arch/$(SRCARCH)/include/uapi

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

CFLAGS_hv_trace.o = -I$(src)
CFLAGS_hv_balloon.o = -I$(src)

hv_vmbus-y	:= vmbus_drv.o \
		 hv.o connection.o channel.o hv_trace.o \
		 channel_mgmt.o ring_buffer.o \
		 arch/$(SRCARCH)/hyperv/hv_init.o \
		 arch/$(SRCARCH)/hyperv/ms_hyperv_ext.o

hv_utils-y	:= hv_util.o hv_kvp.o hv_snapshot.o hv_fcopy.o hv_utils_transport.o
hv_storvsc-y := storvsc_drv.o
hv_uio_generic-y := uio_hv_generic.o
hv_netvsc-y := netvsc_drv.o netvsc.o rndis_filter.o
hyperv_keyboard-y := hyperv-keyboard.o
hv_network_direct-y := provider.o vmbus_rdma.o hvnd_addr.o
