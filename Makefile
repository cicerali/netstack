# ------------------------------------------------
# Generic Makefile
#
# Author: yanick.rochon@gmail.com
# Date  : 2011-08-10
#
# Changelog :
#   2010-11-05 - first version
#   2011-08-10 - added structure : sources, objects, binaries
#                thanks to http://stackoverflow.com/users/128940/beta
# ------------------------------------------------

# project name and version (generate library with this name with and without version)
MAJOR := 1
MINOR := 0
MICRO := 0
NAME := netstack
VERSION := $(MAJOR).$(MINOR).$(MICRO)
TARGET_LIB   = lib$(NAME).so.$(VERSION)
TARGET2_LIB  = lib$(NAME).so
TARGET_BIN = $(NAME)

CC = gcc

DPDK_INC_DIR = /usr/include/dpdk
DPDK_CFLAGS = -Wall -g -std=c99 -include $(DPDK_INC_DIR)/rte_config.h
DPDK_CFLAGS += -march=native -DRTE_MACHINE_CPUFLAG_SSE -DRTE_MACHINE_CPUFLAG_SSE2 -DRTE_MACHINE_CPUFLAG_SSE3
DPDK_CFLAGS += -DRTE_MACHINE_CPUFLAG_SSSE3 -DRTE_MACHINE_CPUFLAG_SSE4_1 -DRTE_MACHINE_CPUFLAG_SSE4_2
DPDK_CFLAGS += -DRTE_COMPILE_TIME_CPUFLAGS=RTE_CPUFLAG_SSE,RTE_CPUFLAG_SSE2,RTE_CPUFLAG_SSE3,RTE_CPUFLAG_SSSE3,RTE_CPUFLAG_SSE4_1,RTE_CPUFLAG_SSE4_2
DPDK_CFLAGS += -I${DPDK_INC_DIR}

CFLAGS   = $(CFLAGS_ENV) $(DPDK_CFLAGS) -D_BSD_SOURCE -fPIC -c -pedantic -pthread -Wall -I.

LINKER   = gcc -o
# linking flags here
LFLAGS_BIN   = -g -rdynamic -Wall -ldpdk
LFLAGS_LIB   = -shared -g -rdynamic -Wall -ldpdk

# change these to set the proper directories where each files shoould be
SRCDIR   = .
OBJDIR   = .
BINDIR   = .
LIBDIR   = .

SOURCES  := $(wildcard $(SRCDIR)/*.c)
INCLUDES := $(wildcard $(SRCDIR)/*.h)
OBJECTS  := $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
rm       = rm -f
MKDIR_P = mkdir -p

# create obj directory if does not exist
#${OBJDIR}:
#	${MKDIR_P} ${OBJDIR}

$(info $(SOURCES))

# to activate versioning activate the following line 
# and and the last line then deactivate the next line
# for TARGET2

.PHONY: bin
bin: $(TARGET_BIN)

$(TARGET_BIN): $(OBJECTS)
	@$(LINKER) $@ $(LFLAGS_BIN) $(OBJECTS)
	@echo "Linking complete!"

.PHONY: lib
lib: $(LIBDIR)/$(TARGET2_LIB)

$(LIBDIR)/$(TARGET2_LIB): $(OBJECTS)
	@$(LINKER) $@ $(LFLAGS_LIB) $(OBJECTS)
	@echo "Linking complete!"
	ln -sf $(LIBDIR)/$(TARGET_LIB) $(LIBDIR)/$(TARGET2_LIB)

$(OBJECTS): $(OBJDIR)/%.o : $(SRCDIR)/%.c
	@echo "Compiling "$<""
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "Compiled "$<" successfully!"

.PHONEY: clean
clean:
	@$(rm) $(OBJECTS)
	@$(rm) $(LIBDIR)/$(TARGET2_LIB)
	@$(rm) $(LIBDIR)/$(TARGET_LIB)
	@$(rm) $(BINDIR)/$(TARGET_BIN)
	@echo "Cleanup complete!"

