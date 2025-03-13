PWD := $(shell pwd)
KDIR := /lib/modules/$(shell uname -r)/build
BUILD_DIR := $(PWD)/../build
obj-m += lkm.o

# Include directory
ccflags-y := -I$(PWD)/../include

# Source directory
SRC_DIR := $(PWD)/../src

all:
	make -C $(KDIR) M=$(SRC_DIR) modules
	mv $(SRC_DIR)/*.ko $(BUILD_DIR)/ || true
	mv $(SRC_DIR)/*.o $(BUILD_DIR)/ || true
	mv $(SRC_DIR)/*.mod* $(BUILD_DIR)/ || true
	mv $(SRC_DIR)/*.cmd $(BUILD_DIR)/ || true
	mv $(SRC_DIR)/modules.order $(BUILD_DIR)/ || true
	mv $(SRC_DIR)/Module.symvers $(BUILD_DIR)/ || true
	mv $(SRC_DIR)/.[!.]* $(BUILD_DIR)/

install:
	make -C $(KDIR) M=$(SRC_DIR) modules_install

clean:
	make -C $(KDIR) M=$(SRC_DIR) clean
	rm -rf $(BUILD_DIR)/*
	rm -rf $(BUILD_DIR)/* $(BUILD_DIR)/.[!.]*
