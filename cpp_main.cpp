#include <iostream>
#include <string>
#include <fstream>
#include <memory>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include "RuleManager.hpp"
#include "configure.hpp"

//using namespace std;

class DeviceFile {
public:
    DeviceFile(const char* path) {
        if (mknod(path, S_IFCHR | 0666, makedev(124, 0)) == -1) {
            //throw std::runtime_error("mknod error");
        }

        fd = open(path, O_WRONLY);
        if (fd == -1) {
            throw std::runtime_error("Failed to open device file");
        }
    }

    ~DeviceFile() {
        if (fd != -1) {
            close(fd);
        }
    }

    ssize_t writeData(const std::vector<my_rule> &rules) {
        ssize_t bytes_written = write(fd, rules.data(), sizeof(my_rule) * rules.size());
        if (bytes_written == -1) {
            throw std::runtime_error("Failed to write to device");
        }
        return bytes_written;
    }

private:
    int fd = -1;
};


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

int main(int argc, char * argv[])
{
    configure config;
    DeviceFile device("/dev/controlinfo");
    device.writeData(config.getRules());
    menu mainMenu;
    std::shared_ptr<RuleManager> ruleManager = std::make_shared<RuleManager>(config);
    int op;
    while (true)
    {
        mainMenu.display();
       
        std::cin >> op;

        switch (op)
        {
        case 1 :
            std::cout << "Please enter 1 : Enable / 0 : Disable: ";
            std::cin >> op;
            if (op == 0)
            {

            }
            else 
            {

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