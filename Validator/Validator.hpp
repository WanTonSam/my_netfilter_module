#include <iostream>
#include <regex>
#include <string>

class Validator {
public:
    static std::string getValidIPv4v6();
    static unsigned int getValidPort();
    static unsigned int getValidUnsignedint();
    static void getValidTimeRange(unsigned int &startTime, unsigned int &endtime);
private:
    static bool isValidIPv4(const std::string &ip);
    static bool isValidIPv6(const std::string &ip);
    static bool isValidPort(const int &port);
    static unsigned int getValidhour();
};