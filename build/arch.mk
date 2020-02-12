CC_COMPILER ?= $(or ${CROSS_COMPILER},${CROSS_COMPILER},gcc)
CX_COMPILER ?= $(or ${CROSS_COMPILER},${CROSS_COMPILER},g++)

AS=$(CROSS_COMPILE)as                                           
LD=$(CROSS_COMPILE)ld                                           
CC=$(CROSS_COMPILE)$(CC_COMPILER)
CXX=$(CROSS_COMPILE)$(CXX_COMPILER)
CPP=$(CC) -E                                                     
AR=$(CROSS_COMPILE)ar                                           
NM=$(CROSS_COMPILE)nm                                           
STRIP=$(CROSS_COMPILE)strip                                        
OBJCOPY=$(CROSS_COMPILE)objcopy                                      
OBJDUMP=$(CROSS_COMPILE)objdump

HOST_ARCH := $(shell uname -m)
HOST_SYSTEM := $(shell uname -s)
TARGET ?= $(shell $(CC) -dumpmachine 2>&1)

ARCH ?= $(shell echo $(TARGET) | sed -e s/i.86.*/i386/ -e s/x86_64.*/x86_64/ \
	-e s/.390.*/s390/ -e s/powerpc64.*/powerpc/ \
	-e s/arm-none.*/arm/ -e s/arm.*/arm/ -e s/aarch64.*/arm64/ -e s/arm.*/arm32/)
