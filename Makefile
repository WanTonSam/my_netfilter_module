SRC_DIRS := . configure RuleManager Validator

# 使用通配符找到所有 .cpp 文件
SOURCES := $(foreach dir, $(SRC_DIRS), $(wildcard $(dir)/*.cpp))

user_program := main

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

$(user_program): $(SOURCES)
	g++ $^ -o $@ $(addprefix -I, $(SRC_DIRS))

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f $(user_program)
