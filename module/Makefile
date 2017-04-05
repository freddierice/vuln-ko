TARGET_MODULE:=vuln
BUILD_DIR ?= "/lib/modules/$(shell uname -r)/build"

ifneq ($(KERNELRELEASE),)
	$(TARGET_MODULE)-objs := main.o
	obj-m := $(TARGET_MODULE).o
else

all:
	$(MAKE) -C $(BUILD_DIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(BUILD_DIR) M=$(PWD) clean

endif
