include build/arch.mk
include build/options.mk
include build/rules.mk

.DEFAULT_GOAL := all

INCLUDES=-I$(s)/opt/include -I$(s) 

VENDOR_PATH := $(if $(VENDOR_PATH),$(VENDOR_PATH),$(s)/opt)

LDFLAGS=-L$(VENDOR_PATH)/lib -lpthread -ldl
CFLAGS=$(INCLUDES) -g -fPIC -DCONFIG_LINUX
CXXFLAGS=$(INCLUDES) -g -std=c++14

LIBS=$(VENDOR_PATH)/lib/libssl.a $(VENDOR_PATH)/lib/libcrypto.a

srcs := tools/openssl.c

objs := $(patsubst %.c,$(o)/%.o,$(sort $(srcs)))

$(o)/tools/openssl: $(o)/tools/openssl.o $(objs)
build_binaries: $(o)/tools/openssl

all: build_binaries

test: all
	$(Q)$(s)/tests/run-tests.sh --tap

clean:
	$(Q)rm -rf obj

install: install_headers install_libs

.PHONY: all build_binaries test clean install 