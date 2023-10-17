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

typedef char* (*AddrToStrFunc)(void*, char*);	//定义函数指针

typedef struct {
	__u8 protocol;
	char name[16];
} ProtocolMap;

typedef struct {
    __u8 protocol;            // Protocol (TCP, UDP, ICMP, etc.)
    void *src_addr;           // Source address (IPv4 or IPv6)
    void *dst_addr;           // Destination address (IPv4 or IPv6)
    unsigned short src_port;  // Source port (relevant for TCP/UDP)
    unsigned short dst_port;  // Destination port (relevant for TCP/UDP)
    bool is_ipv6;             // Flag to indicate if the packet is IPv6
} PacketInfo;

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

static struct nf_hook_ops my_hook_ops;	//hook结构体
struct my_rule rules[50]; //MAX to 50
static int rule_num = 0;

struct timespec64 ts;
struct rtc_time tm;

struct sk_buff *tmpskb;
struct iphdr *ip_header;
struct ipv6hdr *ipv6_header;

char* addr_from_ipv4(void *addr, char * buff);
char* addr_from_ipv6(void *addr, char * buff);
//字符串输出
char src_addr_buff[16];
char dst_addr_buff[16];
char time_buff[50];
char ipv6_src_addr_buff[INET6_ADDRSTRLEN + 1];
char ipv6_dst_addr_buff[INET6_ADDRSTRLEN + 1];
AddrToStrFunc addr_to_str[2] = {addr_from_ipv4, addr_from_ipv6};

static const ProtocolMap protocol_map[] = {
	{IPPROTO_TCP, "TCP"},
	{IPPROTO_UDP, "UDP"},
	{IPPROTO_ICMP, "ICMP"},
};

const char * getprotobynumber(__u8 protocol)
{
	int i;
	for (i = 0; i < sizeof(protocol_map) / sizeof(ProtocolMap); i++)	//查表法
	{
		if (protocol_map[i].protocol == protocol)
		{
			return protocol_map[i].name;
		}
	}
	return "Unknown";
}

char * addr_from_net(char *buff, __be32 addr)
{
	__u8 *p = (__u8*)&addr;
	snprintf(buff, 16, "%u.%u.%u.%u", 
		(__u32)p[0], (__u32)p[1], (__u32)p[2], (__u32)p[3]);
	return buff;
}

// 模拟 inet_ntop 函数，将 IPv6 地址转换为字符串 void * 值得学习！！！
char *my_inet_ntop(const void *src, char *dst, size_t size) {
	const struct in6_addr *addr6 = (const struct in6_addr *)src;
	if (size < INET6_ADDRSTRLEN) 
		return NULL;  // 缓冲区太小
	snprintf(dst, size, "%x:%x:%x:%x:%x:%x:%x:%x",
		ntohs(addr6->s6_addr16[0]), ntohs(addr6->s6_addr16[1]),
		ntohs(addr6->s6_addr16[2]), ntohs(addr6->s6_addr16[3]),
		ntohs(addr6->s6_addr16[4]), ntohs(addr6->s6_addr16[5]),
		ntohs(addr6->s6_addr16[6]), ntohs(addr6->s6_addr16[7]));
	return dst;
}

char* addr_from_ipv4(void *addr, char * buff)
{
	return addr_from_net(buff, *(unsigned int *)addr);
}

char* addr_from_ipv6(void *addr, char *buff)
{
	return my_inet_ntop(addr, buff, sizeof(ipv6_src_addr_buff));
}

bool check_time(struct rtc_time * tm, int i)	//是否在运行时间内 true在运行时间内
{
	if (tm->tm_hour * 60 +  tm->tm_min >= rules[i].time_begin && tm->tm_hour *60 + tm->tm_min <= rules[i].time_end)
		return true;
	return false;
}

bool ip_addr_check(unsigned int saddr, unsigned int daddr, unsigned int i)
{
	bool src_addr_match = (rules[i].src_add == 0 || rules[i].src_add == saddr);	//源地址匹配
	bool dst_addr_match = (rules[i].dst_add == 0 || rules[i].dst_add == daddr);	//目的地址匹配
	return src_addr_match && dst_addr_match;
}

bool ip_port_check(unsigned short sport, unsigned short dport, unsigned int i)
{
	bool src_port_match = (rules[i].src_port == 0 || rules[i].src_port == sport);	//源端口匹配
	bool dst_port_match = (rules[i].dst_port == 0 || rules[i].dst_port == dport);	//目的端口匹配
	return src_port_match && dst_port_match;
}

bool ipv6_addr_check(struct in6_addr saddr, struct in6_addr daddr, int i)
{
	bool src_addr_match = (rules[i].ipv6_saddr.vaild == 0 || memcmp(&saddr, &rules[i].ipv6_saddr.ipv6_addr, sizeof(struct in6_addr)) == 0);	//源地址匹配
	bool dst_addr_match = (rules[i].ipv6_daddr.vaild == 0 || memcmp(&saddr, &rules[i].ipv6_daddr.ipv6_addr, sizeof(struct in6_addr)) == 0);	//目的地址匹配
	return src_addr_match && dst_addr_match;
}

// Check if a given rule matches the packet info
bool rule_matches(const PacketInfo *pkt_info, int rule_index)
{
	if (rules[rule_index].protocol != pkt_info->protocol) 
		return false;
	//指针强制转换
	if (pkt_info->is_ipv6 && !ipv6_addr_check(*(struct in6_addr *)pkt_info->src_addr, *(struct in6_addr *)pkt_info->dst_addr, rule_index))
	{
		return false;
	}
	else if (!pkt_info->is_ipv6 && !ip_addr_check(*(unsigned int *)pkt_info->src_addr, *(unsigned int *)pkt_info->dst_addr, rule_index))
	{
		return false;
	}

	if ((pkt_info->protocol == IPPROTO_TCP || pkt_info->protocol == IPPROTO_UDP) 
		&& !ip_port_check(pkt_info->src_port, pkt_info->dst_port, rule_index))
	{
		return false;
	}
	return true;
}

static unsigned int process_rule(PacketInfo * pkt_info)
{
	int i;
	//利用PacketInfo 对IPv4 和 IPv6 进行透明处理
	if (pkt_info->protocol == IPPROTO_TCP || pkt_info->protocol == IPPROTO_UDP) 
	{
		struct tcphdr *hdr = (struct tcphdr*)skb_transport_header(tmpskb);
		pkt_info->src_port = ntohs(hdr->source);
		pkt_info->dst_port = ntohs(hdr->dest);
	} 
		
	for (i = 0; i < rule_num; i++)
	{
		if ((pkt_info->is_ipv6 && rules[i].rule != IPV6_RULE) ||
			(!pkt_info->is_ipv6 && rules[i].rule != IPV4_RULE))
			continue;
		
		if (rules[i].time_flag == 1 && !check_time(&tm, i))
			continue;

		if (rule_matches(pkt_info, i))
		{
			printk("Time[%s] reject a packet by rule %d : %s from %s:%d to %s:%d \n",
				time_buff, i + 1, getprotobynumber(pkt_info->protocol), 
				addr_to_str[pkt_info->is_ipv6](pkt_info->src_addr, src_addr_buff), pkt_info->src_port,
				addr_to_str[pkt_info->is_ipv6](pkt_info->dst_addr, dst_addr_buff), pkt_info->dst_port
				);
			return NF_DROP;
		}
	}

	return NF_ACCEPT;
}
/*0
static unsigned int process_rule_for_ipv4(void)
{
	int i;
	bool reject = false;
	struct tcphdr *ptcphdr;
	struct udphdr *pudphdr;
	struct icmphdr *picmphdr;

	for (i = 0; i < rule_num; i++)
	{
		if (rules[i].rule != IPV4_RULE) continue;	//rule doesn't match
		else if (rules[i].protocol != ip_header->protocol) continue;
		else if (rules[i].time_flag == 1 && check_time(&tm, i) == false) continue;
		switch(ip_header->protocol)
		{
			case IPPROTO_ICMP :	//ICMP
				picmphdr = (struct icmphdr *)skb_transport_header(tmpskb);
				snprintf(src_port_buff, 10, " ");
				snprintf(dst_port_buff, 10, " ");
				reject = ip_addr_check(ip_header->saddr, ip_header->daddr, i);
				break;
			case IPPROTO_TCP :	//TCP
				ptcphdr = (struct tcphdr *)skb_transport_header(tmpskb);
				snprintf(src_port_buff, 10, "%d", htons(ptcphdr->dest));
				snprintf(dst_port_buff, 10, "%d", htons(ptcphdr->source));
				reject = ip_addr_check(ip_header->saddr, ip_header->daddr, i) && ip_port_check(ptcphdr->source, ptcphdr->dest, i);
				break;
			case IPPROTO_UDP :	//UDP
				pudphdr = (struct udphdr *)skb_transport_header(tmpskb);
				snprintf(src_port_buff, 10, "%d", htons(pudphdr->dest));
				snprintf(dst_port_buff, 10, "%d", htons(pudphdr->source));
				reject = ip_addr_check(ip_header->saddr, ip_header->daddr, i) && ip_port_check(pudphdr->source, pudphdr->dest, i);
				break;
			default :
				printk("Unknow protocol!\n");
				break;
			
		}
		if (reject)
		{
			//printk message
			printk("Time[%s] reject a packet by rule %d : %s from %s:%s to %s:%s \n", 	\
				time_buff, i + 1, getprotobynumber(protocol_buff, ip_header->protocol), \
				addr_from_net(src_addr_buff, ip_header->saddr), 						\
				src_port_buff, 															\
				addr_from_net(dst_addr_buff, ip_header->daddr), 						\
				dst_port_buff);
			return NF_DROP;
		}
	}
	
	return NF_ACCEPT;
}

static unsigned int process_rule_for_ipv6(void)
{
	int i;
	bool reject = false;
	// 使用 inet_ntop 将 in6_addr 转换为字符串
	if (my_inet_ntop(&ipv6_header->saddr, ipv6_src_addr_buff, sizeof(ipv6_src_addr_buff)) == NULL) 
	{
        printk("inet_ntop error");
		return NF_ACCEPT;
    }

    if (my_inet_ntop(&ipv6_header->daddr, ipv6_dst_addr_buff, sizeof(ipv6_dst_addr_buff)) == NULL) 
	{
        printk("inet_ntop error");
		return NF_ACCEPT;
    }

	for (i = 0; i < rule_num; i++)
	{
		if (rules[i].rule != IPV6_RULE) continue;	//rule doesn't match
		
		if (rules[i].time_flag == 1 && check_time(&tm, i) == false) continue;

		switch (ipv6_header->nexthdr)
		{
		case IPPROTO_ICMP :
			reject = ipv6_addr_check(ipv6_header->saddr, ipv6_header->daddr, i);
			break;
		case IPPROTO_TCP :
			struct tcphdr *ptcphdr = NULL;
			ptcphdr = (struct tcphdr*)(skb_transport_header(tmpskb));
			reject = ipv6_addr_check(ipv6_header->saddr, ipv6_header->daddr, i) && ip_port_check(ptcphdr->source, ptcphdr->dest, i);
			break;
		case IPPROTO_UDP :
			struct udphdr *pudphdr = NULL;
			pudphdr = (struct udphdr *)(skb_transport_header(tmpskb));
			reject = ipv6_addr_check(ipv6_header->saddr, ipv6_header->daddr, i) && ip_port_check(pudphdr->source, pudphdr->dest, i);
			break;	
		default:
			printk("Unknow protocol!\n");
			break;
		}

		if (reject)
		{
			printk("Time[%s] reject a packet by rule %d : %s from %s:%s to %s:%s \n", 	\
				time_buff, i + 1, getprotobynumber(protocol_buff, ip_header->protocol), \
				ipv6_src_addr_buff, 													\
				src_port_buff, 															\
				ipv6_dst_addr_buff, 													\
				dst_port_buff);
			return NF_DROP;
		}	
	}
	return NF_ACCEPT;
}
*/
void Get_current_time(void)
{
	// 获取当前时间
	ktime_get_real_ts64(&ts);
	// 调整为本地时间（UTC+8）
	ts.tv_sec += 8 * 60 * 60;

	rtc_time64_to_tm(ts.tv_sec, &tm);

	snprintf(time_buff, 50, "%04d.%02d.%02d %02d:%02d:%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
}
/*unsigned int hook_func(unsigned int hooknum,struct sk_buff **skb,const struct net_device *in,const struct net_device *out,int (*okfn)(struct sk_buff *))
*/
unsigned int MY_hook_func(void * priv,struct sk_buff *skb,const struct nf_hook_state * state)
{
	unsigned int result = 0;
	PacketInfo pkt_info;

	memset(&pkt_info, 0, sizeof(PacketInfo));
	//get the current time
	Get_current_time();
	
	tmpskb = skb;
	//handle ipv4 packet
	if (skb->protocol == htons(ETH_P_IP))
	{
		ip_header = ip_hdr(skb);
		pkt_info.protocol = ip_header->protocol;
		pkt_info.src_addr = &ip_header->saddr;
		pkt_info.dst_addr = &ip_header->daddr;
		pkt_info.is_ipv6 = false;
		printk("this is a ipv4 packet!\n");
	}
	//handle ipv6 packet
	else if (skb->protocol == htons(ETH_P_IPV6))
	{
		ipv6_header = ipv6_hdr(skb);
		pkt_info.protocol = ipv6_header->nexthdr;
		pkt_info.src_addr = &ipv6_header->saddr;
		pkt_info.dst_addr = &ipv6_header->daddr;
		pkt_info.is_ipv6 = true;
		printk("this is a ipv6 packet!\n");
	}
	else 
	{
		printk("Unkonw ip protocol!\n");
		return NF_ACCEPT;
	}
	
	result = process_rule(&pkt_info);
	return result == NF_DROP ? NF_DROP : NF_ACCEPT;  // can not just return result;
}

static ssize_t my_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	int i = 0;
	if (count > sizeof(rules))
	{
		printk("Data too large! \n");
		return -EINVAL;
	}
	
	if (copy_from_user(rules, buf, count))
	{
		printk("failed to copy data frome user \n");
		return -EINVAL;
	}
	
	rule_num = count / sizeof(struct my_rule);
	for (; i < rule_num; i++)
	{
		printk("rule %d: %d %d \n", i, rules[i].protocol, rules[i].time_end);
	}
	
	return count;
}

static const struct file_operations my_fops = {
	.owner = THIS_MODULE,
	.write = my_write,
};

static int __init MY_Firewall(void)
{
	int ret = 0;
	printk("initiate the module \n");	//\n 刷新控制台，立即输出
	my_hook_ops.hook = MY_hook_func;
	my_hook_ops.pf = NFPROTO_INET;	//IPv4、IPv6
	my_hook_ops.hooknum = NF_INET_PRE_ROUTING;	//在NF_INET_PRE_ROUTING点上处理数据包 Linux 主机自己发出的数据包通常不会经过 PREROUTING 阶段，而是经过 OUTPUT 链
	//Netfilter允许在同一钩子点上注册多个钩子函数，而优先级用于确定它们的执行顺序。
	my_hook_ops.priority = NF_IP_PRI_FIRST; 
	nf_register_net_hook(&init_net,&my_hook_ops); //init_net Linux内核全局变量,一个指向默认网络命名空间的指针

	ret = register_chrdev(124, "/dev/controlinfo", &my_fops); 
	if (ret != 0)
	{
		printk("Can't not register device file! \n");
	}
        return 0;
}


static void __exit MY_Firewall_exit(void)
{
	printk("exit the MY_Firewall module \n");  //\n 刷新控制台，立即输出
	nf_unregister_net_hook(&init_net,&my_hook_ops);
	
	unregister_chrdev(124, "controlinfo");	
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sam wen");
MODULE_DESCRIPTION("A Linux module base on netfilter");
MODULE_VERSION("0.1");
module_init(MY_Firewall);
module_exit(MY_Firewall_exit);




























