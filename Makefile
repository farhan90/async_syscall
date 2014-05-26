obj-m += async_mod.o

async_mod-objs := checksum.o fileops.o sys_async.o

all: hw3 async

hw3:
	gcc -Werror sub_one_wait.c -o sub_one_wait 

async:
	make -Wall -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	
