# tcpsf:  tcp splicing module for the Linux kernel

NAME	= tcpsp
VERSION = 0.0.5

# kernel header directory
KDIR := /usr/lib/modules/$(shell uname -r)/build/

# .ko name and dependency file
obj-m = $(NAME).o
$(NAME)-objs := tcpsp_ctl.o tcpsp_core.o tcpsp_conn.o



all:	build

build:
	$(MAKE) -C $(KDIR) M=$(shell pwd) modules

clean:
	$(MAKE) -C $(KDIR) M=$(shell pwd) clean

install: build
	sudo insmod $(NAME).ko
	sudo lsmod | grep "tcpsp"
remove:
	sudo rmmod $(NAME)
	sudo lsmod | grep "tcpsp"
