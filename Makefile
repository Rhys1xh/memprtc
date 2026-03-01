# Ultimate Makefile for memprtc v3.1
NAME := memprtc
obj-m := $(NAME).o

# Kernel build directory
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

# Compiler flags for production
ccflags-y := -Wall -Werror -O2 -fno-strict-aliasing -D_GNU_SOURCE
ccflags-y += -Wno-declaration-after-statement

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f *.ko *.o *.mod.* Module.symvers modules.order
	rm -f tags cscope.*

install:
	sudo insmod $(NAME).ko

remove:
	sudo rmmod $(NAME).ko || true

status:
	@echo "=== memprtc Ultimate v3.1 Status ==="
	@lsmod | grep $(NAME) || echo "Module not loaded"
	@echo ""
	@echo "=== Module Parameters ==="
	@sudo systool -v -m memprtc 2>/dev/null | grep -A10 "Parameters:" || echo "Module not loaded"
	@echo ""
	@echo "=== Device Interface ==="
	@if [ -e /dev/memprtc ]; then \
		echo "Device exists. Status:"; \
		cat /dev/memprtc; \
	fi
	@echo ""
	@echo "=== DebugFS Interface ==="
	@if [ -d /sys/kernel/debug/memprtc ]; then \
		echo "Protected processes:"; \
		cat /sys/kernel/debug/memprtc/protected 2>/dev/null | head -20; \
		echo ""; \
		echo "Recent violations:"; \
		cat /sys/kernel/debug/memprtc/violations 2>/dev/null | head -20; \
	else \
		echo "DebugFS not available (mount -t debugfs none /sys/kernel/debug)"; \
	fi

.PHONY: all clean install remove status