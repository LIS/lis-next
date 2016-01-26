obj-m	+= hv_vmbus.o
obj-m	+= hv_storvsc.o
obj-m	+= hv_netvsc.o
obj-m	+= hv_utils.o
obj-m	+= hid-hyperv.o
obj-m	+= hyperv_fb.o
obj-m	+= hv_balloon.o
obj-m	+= hyperv-keyboard.o
obj-m	+= hv_sock.o

# Get machine bit length
arch=$(shell getconf LONG_BIT)

# RDMA should only build on 64 bits arch
ifeq ($(arch), 64)
        obj-m += hv_network_direct.o
endif

ccflags-y += -I$(M)/include/

hv_vmbus-y := vmbus_drv.o \
		 hv.o connection.o channel.o \
		 channel_mgmt.o ring_buffer.o
hv_utils-y := hv_util.o hv_kvp.o hv_snapshot.o hv_fcopy.o hv_utils_transport.o

hv_storvsc-y := storvsc_drv.o
hv_netvsc-y := netvsc_drv.o netvsc.o rndis_filter.o
hyperv_keyboard-y := hyperv-keyboard.o
hv_network_direct-y := provider.o vmbus_rdma.o hvnd_addr.o
hv_sock-y := af_hvsock.o
