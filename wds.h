#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/string.h>
#include <linux/ipv6.h> // IPv6头文件
#include <linux/icmpv6.h> // IPv6 ICMP头文件（如果需要处理IPv6 ICMP数据包）
#include <linux/time.h>
#include <linux/timex.h>
#include <linux/rtc.h>
#include <linux/timekeeping.h> // 包含时间相关的头文件

#define MATCH 1
#define NMATCH 0
#define IPV4_RULE 0
#define IPV6_RULE 1
#define INET6_ADDRSTRLEN 50
static struct nf_hook_ops my_hook_ops;	//hook结构体
struct in_6_addr_ext{
	struct in6_addr ipv6_addr;
	unsigned short vaild;
};
//源端口 目的端口 源地址 目的地址 协议
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
struct my_rule rules[50]; //MAX to 50
static int rule_num = 0;

struct timespec64 ts;
struct rtc_time tm;

struct sk_buff *tmpskb;
struct iphdr *ip_header;
struct ipv6hdr *ipv6_header;

//字符串输出
char src_port_buff[10];
char dst_port_buff[10];
char src_addr_buff[16];
char dst_addr_buff[16];
char protocol_buff[16];
char time_buff[50];
char ipv6_src_addr_buff[INET6_ADDRSTRLEN + 1];
char ipv6_dst_addr_buff[INET6_ADDRSTRLEN + 1];