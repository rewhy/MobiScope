# Makefile for compile kernel for Andriod
KERNEL_DIR := xxx/goldfish
CROSS_COMPILE := xxx/Android-4.4.3_r1.1/prebuilts/gcc/linux-x86/arm/arm-eabi-4.6/bin/arm-eabi-
EXTRA_CFLAGS := -g -Wall
ARCH := arm
PWD := $(shell pwd)
obj-m := krt.o
krt-objs := pktrx.o pkthijack.o nlksp.o pkttx.o rulelist.o hash.o

.PHONY: modules package clean
default:
	$(MAKE) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(KERNEL_DIR) SUBDIRS=$(PWD) modules
clean:
	$(MAKE) -C $(KERNEL_DIR) SUBDIRS=$(PWD) clean
