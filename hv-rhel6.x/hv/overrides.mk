_HV_CPPFLAGS += -I$(M)/include

EXTRA_CFLAGS += $(_HV_CPPFLAGS)
CPPFLAGS := -I$(M)/include $(CPPFLAGS)
