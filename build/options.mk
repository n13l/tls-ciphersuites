default: all
s=.
o=obj
MAKEFLAGS += -rR --include-dir=$(CURDIR)
# To put more focus on warnings, be less verbose as default
# Use 'make V=1' to see the full commands
ifeq ("$(origin V)", "command line")
  BUILD_VERBOSE = $(V)
endif
ifndef BUILD_VERBOSE
  BUILD_VERBOSE = 0
endif
ifeq ($(BUILD_VERBOSE),1)
  M=@\#
  Q =
else
  M=@echo #
  Q = @
endif

ifeq ("$(origin D)", "command line")
  BUILD_DEBUG = $(D)
endif
ifeq ("$(origin DEBUG)", "command line")
  BUILD_DEBUG = $(DEBUG)
endif

ifndef BUILD_DEBUG
  BUILD_DEBUG = 0
endif
ifeq ($(BUILD_DEBUG),1)
  CFLAGS+=-g -O0 -DCONFIG_DEBUG -DDEBUG -D_DEBUG
else
  CFLAGS+=-O3 -march=native
endif
