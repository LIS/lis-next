# Makefile for Hyper-V tools

CC = $(CROSS_COMPILE)gcc
PTHREAD_LIBS = -lpthread
WARNINGS = -Wall -Wextra
CFLAGS = $(WARNINGS) -g $(PTHREAD_LIBS) $(shell getconf LFS_CFLAGS)

CFLAGS += -D__EXPORTED_HEADERS__ -I../include/uapi -I ../include

# Get RHEL/CentOS version information
rhel_major=$(shell grep -Eoh [0-9]+\.[0-9]+ /etc/{issue,*release} | head -1 | awk -F'.' '{ print $$1 }')
rhel_minor=$(shell grep -Eoh [0-9]+\.[0-9]+ /etc/{issue,*release} | head -1 | awk -F'.' '{ print $$2 }')
rhel_release_code=$(shell echo $$(($(rhel_major) << 8 | $(rhel_minor))))

# hv_vss_daemon will be compiled only on RHEL5.4 and higher.
buildsnapshot=$(shell test $(rhel_release_code) -lt 1284; echo $$?)
ifeq ($(buildsnapshot),0)
all: hv_kvp_daemon hv_fcopy_daemon
%: %.c
	$(CC) $(CFLAGS) -o $@ $^
clean:
	$(RM) hv_kvp_daemon hv_fcopy_daemon

else
all: hv_kvp_daemon hv_vss_daemon hv_fcopy_daemon
%: %.c
	$(CC) $(CFLAGS) -o $@ $^
clean:
	$(RM) hv_kvp_daemon hv_vss_daemon hv_fcopy_daemon
endif

