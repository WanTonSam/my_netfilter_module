#include <linux/ipv6.h> // IPv6头文件
#include <vector>


#define FILE_RULE "rule.txt"
#define MAX_RULE 50

enum operation{
	Add_rule = 0,
	Delete_rule,
	Modify_rule,
};

struct in_6_addr_ext{
	struct in6_addr ipv6_addr;
	unsigned short valid;
};

struct my_rule{
	unsigned short rule;	//保存的全是网络字节序，可以直接比较
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
	void init();
	void loadRuleFromFile(const std::string &filename = FILE_RULE);
	void updateRuleInFile(int index, const my_rule &rule, operation op);
	std::string ruleTostring(const my_rule	&rule);
	void query(unsigned int rule, unsigned int index);
	~configure();
private:
    std::string rule_name;
    std::vector<my_rule> rules;
};