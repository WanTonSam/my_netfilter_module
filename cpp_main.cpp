#include <iostream>
#include <string>
#include <fstream>
#include <memory>
#include <fcntl.h>
#include <csignal>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include "RuleManager.hpp"
#include "configure.hpp"


//using namespace std;
class DeviceFile {
public:
    DeviceFile(const char* _path)  : path(_path) {
        system("insmod wds.ko");
        if (mknod(_path, S_IFCHR | 0666, makedev(124, 0)) == -1) {
            //throw std::runtime_error("mknod error");
        }
    }

    ~DeviceFile() {
        if (fd != -1) {
            close(fd);
        }
        system("rmmod wds.ko");
    }

    ssize_t writeData(const std::vector<my_rule> &rules) {
        fd = open(path, O_WRONLY);
        if (fd == -1) {
            throw std::runtime_error("Failed to open device file");
        }
        ssize_t bytes_written = write(fd, rules.data(), sizeof(my_rule) * rules.size());
        if (bytes_written == -1) {
            close(fd);
            throw std::runtime_error("Failed to write to device");
        }
        close(fd);
        return bytes_written;
    }
public:
    static int fd;
    const char * path;
};
int DeviceFile::fd = -1;

class menu {
public:
    void display(){
        for (auto &i : menulist)
            std::cout << i << std::endl;
    }
private:
    const char * menulist[6] = {
"******** 1. Enable/Disable Firewall ***********",
"******** 2. Add rule in Firewall **************",
"******** 3. Modify rule in Firewall ***********",
"******** 4. Delete rule in Firewall ***********",
"******** 5. Query rule in Firewall ************",
"******** enter 0 to quit **********************",
};

};
//query rules
//add rule
//delete rule
void sigint_handler(int signum)
{
	printf("exit and remove the module\n");
    if (DeviceFile::fd)
        close(DeviceFile::fd);
	system("rmmod wds.ko");
	exit(1);
}



int main(int argc, char * argv[])
{
    configure config;
    DeviceFile device("/dev/controlinfo");
    device.writeData(config.getRules());
    menu mainMenu;
    std::shared_ptr<RuleManager> ruleManager = std::make_shared<RuleManager>(config);

    if (signal(SIGINT, sigint_handler) == SIG_ERR)
	{
		perror("Failed to set signal handler");
		return 1;
	}

    int op;
    while (true)
    {
        mainMenu.display();
       
        std::cin >> op;

        if (op == 0) break;
        switch (op)
        {
        case 1 :
            std::cout << "Please enter 1 : Enable / 0 : Disable: ";
            std::cin >> op;
            if (op == 0)
            {
                if ( 0 == system("rmmod wds.ko"))
                    std::cout << "Disable the firewall successfully" << std::endl;
                else std::cout << "Fail to disable firewall" << std::endl;
            }
            else 
            {
                if ( 0 == system("insmod wds.ko"))
                    std::cout << "Enable the firewall successfully" << std::endl;
                else std::cout << "Fail to enable firewall" << std::endl;
            }
            break;
        case 2 :
            ruleManager->addRule();
            device.writeData(config.getRules());
            break;
        case 3 :
            ruleManager->modifyRule();
            device.writeData(config.getRules());
            break;
        case 4 :
            ruleManager->deleteRule();
            device.writeData(config.getRules());
            break;
        case 5 :
            ruleManager->query_rule();
            break;
        default:
            std::cout << "Invalid operation, please try again!" << std::endl;
            break;
        }
    }
    return 0;
}