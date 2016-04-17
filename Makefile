<<<<<<< HEAD
obj-m += file_monitor.o
=======
obj-m += hook_open.o
obj-m += hook_read.o
obj-m += hook_listen.o
>>>>>>> a3dc0cbc7921827d44ea6a67ee90d665a474875f

all:
	make -C /lib/modules/`uname -r`/build M=$(PWD) modules

clean:
	make -C /lib/modules/`uname -r`/build M=$(PWD) clean