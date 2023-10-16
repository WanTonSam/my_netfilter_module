#include <iostream>
#include <string>
#include <fstream>
#include "configure.hpp"

//using namespace std;


class menu {
public:

private:
    
};
//query rules
//add rule
//delete rule



int main(int argc, char * argv[])
{
    configure config;
    config.read_rule();
    config.query_rule();
    return 0;
}