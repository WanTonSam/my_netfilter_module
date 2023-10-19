#include <iostream>
#include <string>
#include <fstream>
#include <memory>
#include "RuleManager.hpp"
#include "configure.hpp"

//using namespace std;


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
"******** 6. enter Q to quit *******************",
};

};
//query rules
//add rule
//delete rule

int main(int argc, char * argv[])
{
    configure config;
    menu mainMenu;
    std::shared_ptr<RuleManager> ruleManager = std::make_shared<RuleManager>(config);
    int op;
    char scan_string[100];
    while (true)
    {
        mainMenu.display();

        if (fgets(scan_string, sizeof(scan_string), stdin) == NULL)
            continue;

        if (scan_string[0] == 'Q' || scan_string[0] == 'q')
            break;

        op = atoi(scan_string);

        switch (op) 
        {
        case 1 :
            std::cout << "Please enter 1 : Enable / 0 : Disable: ";
            std::cin >> op;
            if (op == 1)
            break;
        case 2 :
            ruleManager->addRule();
            break;
        case 3 :
            ruleManager->modifyRule();
            break;
        case 4 :
            ruleManager->deleteRule();
            break;
        case 5 :
            config.query(1, -1);
            config.query(0, -1);
            break;
        default:
            std::cout << "Invalid operation, please try again!" << std::endl;
            break;
        }
    }

    return 0;
}