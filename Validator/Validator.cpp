#include <limits>
#include "Validator.hpp"


bool Validator::isValidIPv4(const std::string& ip) {
    std::regex ipv4Pattern("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");
    return std::regex_match(ip, ipv4Pattern);
}

bool Validator::isValidIPv6(const std::string& ip) {
    std::regex ipv6Pattern("^(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}$");
    return std::regex_match(ip, ipv6Pattern);
}

bool Validator::isValidPort(const int &port) {
    return port >= 0 && port <= 65535;
}

std::string Validator::getValidIPv4v6()
{
    std::string ip;
    while (true)
    {
        //std::cout << "Please enter a valid IPv4/v6 address:";
        std::cin >> ip;
        if (isValidIPv4(ip) || isValidIPv6(ip) || ip[0] == '0') break;
        else std::cout << "Invalid IPv4/v6 address ! please enter it again" << std::endl;
    }
    return ip;
}

unsigned int Validator::getValidUnsignedint()
{
    unsigned int value;
    while (true)
    {
        if (std::cin >> value) break;
        else{
            std::cout << "Invalid input! Try again:";
            std::cin.clear();   // 清除失败的状态
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');  // 清空输入缓冲区
        }
    }
    return value;
}

unsigned int Validator::getValidPort()
{
    unsigned int port;
    while (true)
    {
        port = getValidUnsignedint();
        if (isValidPort(port)) break;
        else std::cout << "Invalid Port! please try again:";
    }
    return port;
}



unsigned int Validator::getValidhour()
{
    unsigned int hour;
    while (true)
    {
        hour = getValidUnsignedint();
        if (hour <= 24) break;
        else std::cout << "Invalid hour! please try again:";
    }
    return hour;
}


void Validator::getValidTimeRange(unsigned int &startTime, unsigned int &endTime)
{
    while (true)
    {
        std::cout << "Please enter the start time (0 - 24):";
        startTime = getValidhour();

        std::cout << "Please enter the end time (0 - 24):";
        endTime = getValidhour();

        if (startTime < endTime) break;
        else std::cout << "Invalid time range! Try again!" << std::endl;
    }
}