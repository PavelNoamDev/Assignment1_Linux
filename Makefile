obj-m += file_monitor.o
obj-m += network_monitor.o
obj-m += mount_monitor.o
obj-m += mount_monitor.o
obj-m += kmonitor.o

all:
	make -C /lib/modules/`uname -r`/build M=$(PWD) modules

clean:
	make -C /lib/modules/`uname -r`/build M=$(PWD) clean