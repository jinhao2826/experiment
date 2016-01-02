obj-m +=redirect_trimack2.o

KDIR =/usr/src/linux-4.0

all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
clean:
	rm -rf *.o *.ko *.mod.* *.symvers *.order
