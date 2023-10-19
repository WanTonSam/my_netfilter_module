#include <iostream>
#include <string>
#include <climits>
#include <arpa/inet.h>
#include "RuleManager.hpp"
#include "configure.hpp"
#include "Validator.hpp"

void RuleManager::addRule()
{
    bool result = false;
    my_rule newRule;
    std::string ip;

    memset(&newRule, 0, sizeof(my_rule));

    std::cout << "Enter 0 for IPV4 / 1 for IPV6 :";
    
    newRule.rule = Validator::getValidUnsignedint();

    std::cout << "Please enter the Protocol: 1-ICMP 6-TCP 17-UDP:";

    newRule.protocol = Validator::getValidUnsignedint();

    std::cout << "Please enter the " << ((newRule.rule == 1) ? "IPv6 source address/" : "IPv4 source address/") << "0 to continue:";

    ip = Validator::getValidIPv4v6();

    (newRule.rule == 0) ? (newRule.src_add = inet_addr(ip.c_str())) : (inet_pton(AF_INET6, ip.c_str(), &newRule.ipv6_saddr.ipv6_addr));

    if (newRule.rule == 1 && ip[0] != '0') newRule.ipv6_saddr.valid = 1;

    std::cout << "Please enter the Source Port:";

    newRule.src_port = Validator::getValidPort();
    newRule.src_port = htons(newRule.src_port);

    std::cout << "Please enter the " << ((newRule.rule == 1) ? "IPv6 Destination address/" : "IPv4 Destination address/") << "0 to continue:";

    ip = Validator::getValidIPv4v6();

   (newRule.rule == 0) ? (newRule.dst_add = inet_addr(ip.c_str())) : (inet_pton(AF_INET6, ip.c_str(), &newRule.ipv6_daddr.ipv6_addr));
    
    if (newRule.rule == 1 && ip[0] != '0') newRule.ipv6_daddr.valid = 1;
    
    std::cout << "Please enter the Destination Port:";

    newRule.dst_port = Validator::getValidPort();
    newRule.dst_port = htons(newRule.dst_port);

    std::cout << "Rule timer 1:Enable 0:Disable ? :";

    newRule.time_flag = Validator::getValidUnsignedint();
    if (newRule.time_flag == 1)
        Validator::getValidTimeRange(newRule.time_begin, newRule.time_end); 

    result = config.updateRuleInFile(-1, newRule, Add_rule);

    if (result)
        std::cout << std::endl << "Add rule successfully!" << std::endl << std::endl;
    else std::cout << "Add rule fail" << std::endl;
}

void RuleManager::deleteRule()
{
    bool result = false;
    unsigned int index;
    my_rule rule;

    std::cout << "Please enter the rule's index that you want to delete:";

    index = Validator::getValidUnsignedint();

    result = config.updateRuleInFile(index, rule, Delete_rule);

    if(result)
        std::cout << std::endl << "Delete rule successfully!" << std::endl << std::endl;
    else std::cout << "Delelte rule fail!" << std::endl;
}

void RuleManager::modifyRule()
{
    unsigned int index;
    my_rule rule;
    std::cout << "Please enter the index that you want to modify:";

    index = Validator::getValidUnsignedint();

    config.updateRuleInFile(index, rule, Modify_rule);
}

void RuleManager::query_rule()
{
    unsigned int rule;
    std::cout << "Please enter 0-IPv4 rule / 1-IPv6 rule / 2-All rule : ";
    rule = Validator::getValidUnsignedint();

    config.query(rule);
}