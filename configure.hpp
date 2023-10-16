#include <linux/ipv6.h> // IPv6头文件
#define FILE_RULE "rule.txt"
#define MAX_RULE 50

struct in_6_addr_ext{
	struct in6_addr ipv6_addr;
	unsigned short vaild;
};

struct my_rule{
	unsigned short rule;
	unsigned int src_add;
	unsigned short src_port;
	unsigned int dst_add;
	unsigned short dst_port;
	unsigned int protocol;
	unsigned int time_flag;
	unsigned int time_begin;
	unsigned int time_end;
	struct in_6_addr_ext ipv6_saddr;
	struct in_6_addr_ext ipv6_daddr;
};

class configure  {
public:
    configure(std::string R = FILE_RULE) : rule_name(R), rules{{{}}} {};
    bool read_rule();
    bool write_rule();
    void query_rule();
	~configure();
private:
    std::string rule_name;
    my_rule rules[MAX_RULE];
};