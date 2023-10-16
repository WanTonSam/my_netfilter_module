#include <iostream>
#include <fstream>
#include "configure.hpp"

bool fileExists(const std::string& filename) {
    std::ifstream file(filename);
    return file.good();
}

configure::~configure(){}

void configure::query_rule()
{
    std::cout << "*************** rules start **************" << std::endl;
    for (auto rule : rules)
    {
        ;
    }
    std::cout << "*************** rules end **************" << std::endl;
}

bool configure::read_rule()
{
    if(fileExists(rule_name) == false)
    {
        std::cout << "rule file doesn't exit!" << std::endl;
        return false;
    }
    std::cout << "Read rule from file successfully" << std::endl;
    return true;
}
