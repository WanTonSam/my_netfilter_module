#include <iostream>
#include <fstream>
#include <arpa/inet.h>
#include <functional>
#include <cstring>  // For C++
#include <map>

#include "configure.hpp"

bool fileExists(const std::string& filename) {
    std::ifstream file(filename);
    return file.good();
}

configure::~configure(){}

void configure::init()
{
    //初始化操作
    
    this->loadRuleFromFile();
}

void configure::loadRuleFromFile(const std::string &filename)
{
    std::ifstream file(filename);
    if (!file.is_open()){
        throw std::runtime_error("Failed to open file!");
    }

    my_rule rule;
    std::string ipSource, ipDest, ipv6Source, ipv6Dest;
    while (file >> rule.rule
                >> ipSource >> rule.src_port
                >> ipDest >> rule.dst_port
                >> rule.protocol
                >> rule.time_flag >> rule.time_begin >> rule.time_end
                >> rule.ipv6_saddr.valid >> ipv6Source
                >> rule.ipv6_daddr.valid >> ipv6Dest)
    {

        rule.src_add = inet_addr(ipSource.c_str());
        rule.src_port = htons(rule.src_port);
        rule.dst_add = inet_addr(ipDest.c_str());
        rule.dst_port = htons(rule.dst_port);
        if (rule.ipv6_saddr.valid)
            inet_pton(AF_INET6, ipv6Source.c_str(), &rule.ipv6_saddr.ipv6_addr);
        else memset(&rule.ipv6_saddr.ipv6_addr, 0, sizeof(in6_addr));
        if (rule.ipv6_daddr.valid)
            inet_pton(AF_INET6, ipv6Dest.c_str(), &rule.ipv6_daddr.ipv6_addr);
        else memset(&rule.ipv6_daddr.ipv6_addr, 0, sizeof(in6_addr));

        rules.push_back(rule);
    }
}

std::string configure::ruleTostring(const my_rule &rule)
{
    char ipSource[INET_ADDRSTRLEN + 1];
    char ipDest[INET_ADDRSTRLEN + 1]; 
    char ipv6Source[INET6_ADDRSTRLEN + 1];
    char ipv6Dest[INET6_ADDRSTRLEN + 1];
    inet_ntop(AF_INET, &rule.src_add, ipSource, sizeof(ipSource));
    inet_ntop(AF_INET, &rule.dst_add, ipDest, sizeof(ipDest));
    inet_ntop(AF_INET6, &rule.ipv6_saddr.ipv6_addr, ipv6Source, sizeof(ipv6Source));
    inet_ntop(AF_INET6, &rule.ipv6_daddr.ipv6_addr, ipv6Dest, sizeof(ipv6Dest));
    return std::to_string(rule.rule) + " "
            + ipSource + " " + std::to_string(ntohs(rule.src_port)) + " "
            + ipDest + " " + std::to_string(ntohs(rule.dst_port)) + " "
            + std::to_string(rule.protocol) + " "
            + std::to_string(rule.time_flag) + " " + std::to_string(rule.time_begin) + " " + std::to_string(rule.time_end) + " "     
            + std::to_string(rule.ipv6_saddr.valid) + " " + ipv6Source + " "
            + std::to_string(rule.ipv6_daddr.valid) + " " + ipv6Dest;
}

void configure::updateRuleInFile(int index, const my_rule &rule, operation op)
{
    std::string tempFileName = rule_name + ".tmp";

    std::vector<std::string> lines;
    {
        std::ifstream inFile(rule_name);
        if (!inFile){
            throw std::runtime_error("Failed to open file!");
        }
        
        std::string line;
        while (getline(inFile, line))
            lines.push_back(line);
    }

    auto performDelete = [&](){
        if (index < lines.size()){
            lines.erase(lines.begin() + index);
        }
    };

    auto performModify = [&]() {
        if (index < lines.size()) {
            lines[index] = ruleTostring(rule);
        }
    };

    std::map<operation, std::function<void()>> opMap = {
        {Add_rule, [&](){ lines.push_back(ruleTostring(rule)); }},
        {Delete_rule, performDelete},
        {Modify_rule, performModify}
    };

    if (opMap.find(op) != opMap.end())
        opMap[op]();
    else
    {
        std::cout << "error" << std::endl;
        return;
    } 

    std::ofstream outFile(tempFileName, std::ios::trunc);  //std::ios::trunc如果该文件已经存在，那么其内容会被清空。如果文件不存在，那么会创建一个新的空文件
    if (!outFile){
        throw std::runtime_error("Failed to creat file!");
    }

    for (const auto& l : lines){
        outFile << l << "\n";
    }

    outFile.close();

    if (std::rename(tempFileName.c_str(), rule_name.c_str()) != 0)
        std::cout << "Failed to rename file" << std::endl;

    return;
}

void configure::query(unsigned int rule, unsigned int index)
{
    if (index != -1)
    {
        std::cout << ruleTostring(rules[index]);
        return;
    }
     for (auto &r : rules)
     {
        if (r.rule == rule)
            std::cout << ruleTostring(r);
     }
     return;
}