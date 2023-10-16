obj-m += wds.o
user_src := cpp_main.cpp configure.cpp
user_program := main

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

$(user_program): $(user_src)
	g++ $^ -o $@
	
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm main
