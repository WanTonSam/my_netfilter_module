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
//this is a test
#define MATCH 1
#define NMATCH 0
#define IPV4_RULE 0
#define IPV6_RULE 1
static struct nf_hook_ops my_hook_ops;	//hook结构体
//test
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
char * getprotobynumber(char *protocol_name, __u8 protocol)
{
	switch (protocol) {
        case IPPROTO_TCP:
            snprintf(protocol_name, 16, "%s", "TCP");
            break;
        case IPPROTO_UDP:
            snprintf(protocol_name, 16, "%s", "UDP");
            break;
        case IPPROTO_ICMP:
            snprintf(protocol_name, 16, "%s", "ICMP");
            break;
        default:
            snprintf(protocol_name, 16, "%s", "Unknow");
            break;
    }
	return protocol_name;
}

char * addr_from_net(char *buff, __be32 addr)
{
	__u8 *p = (__u8*)&addr;
	snprintf(buff, 16, "%u.%u.%u.%u", 
		(__u32)p[0], (__u32)p[1], (__u32)p[2], (__u32)p[3]);
	return buff;
}

bool check_time(struct rtc_time * tm, int i)
{
	if (tm->tm_hour * 60 +  tm->tm_min >= rules[i].time_begin && tm->tm_hour *60 + tm->tm_min <= rules[i].time_end)
		return true;
	return false;
}

bool ipaddr_check(unsigned int saddr, unsigned int daddr, unsigned int i)
{
	if (rules[i].src_add != 0 && rules[i].dst_add == 0)
		return saddr == rules[i].src_add;
	else if (rules[i].src_add == 0 && rules[i].dst_add != 0)
		return daddr == rules[i].dst_add;
	else if (rules[i].src_add != 0 && rules[i].dst_add != 0)
		return saddr == rules[i].src_add && daddr == rules[i].dst_add;
	return true;
}

bool ip_port_check(unsigned short sport, unsigned short dport, unsigned int i)
{
	if (rules[i].src_port != 0 && rules[i].dst_port == 0)
		return sport == rules[i].src_port;
	else if (rules[i].src_port == 0 && rules[i].dst_port != 0)
		return dport == rules[i].dst_port;
	else if (rules[i].src_port != 0 && rules[i].dst_port != 0)
		return sport == rules[i].src_port && dport == rules[i].dst_port;
	return true;
}

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
				reject = ipaddr_check(ip_header->saddr, ip_header->daddr, i);
				break;
			case IPPROTO_TCP :	//TCP
				ptcphdr = (struct tcphdr *)skb_transport_header(tmpskb);
				snprintf(src_port_buff, 10, "%d", htons(ptcphdr->dest));
				snprintf(dst_port_buff, 10, "%d", htons(ptcphdr->source));
				reject = ipaddr_check(ip_header->saddr, ip_header->daddr, i) && ip_port_check(ptcphdr->source, ptcphdr->dest, i);
				break;
			case IPPROTO_UDP :	//UDP
				pudphdr = (struct udphdr *)skb_transport_header(tmpskb);
				snprintf(src_port_buff, 10, "%d", htons(pudphdr->dest));
				snprintf(dst_port_buff, 10, "%d", htons(pudphdr->source));
				reject = ipaddr_check(ip_header->saddr, ip_header->daddr, i) && ip_port_check(pudphdr->source, pudphdr->dest, i);
				break;
			default :
				printk("Unknow protocol!\n");
				break;
			
		}
		if (reject)
		{
			//printk message
			printk("Time[%s]reject a packet by rule %d : %s from %s:%s to %s:%s \n", time_buff, i + 1, getprotobynumber(protocol_buff, ip_header->protocol), addr_from_net(src_addr_buff, ip_header->saddr), src_port_buff, addr_from_net(dst_addr_buff, ip_header->daddr), dst_port_buff);
			return NF_DROP;
		}
	}
	
	return NF_ACCEPT;
}

static unsigned int process_rule_for_ipv6(void)
{
	int i;
	for (i = 0; i < rule_num; i++)
	{
		if (rules[i].rule != IPV4_RULE) continue;	//rule doesn't match
		
		if (rules[i].time_flag == 1 && check_time(&tm, i) == 0) continue;
		
	}
	return NF_ACCEPT;
}

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
	//get the current time
	Get_current_time();
	
	tmpskb = skb;
	//handle ipv4 packet
	

	
	if (skb->protocol == htons(ETH_P_IP))
	{
		ip_header = ip_hdr(skb);
		printk("this is a ipv4 packet!\n");
		result = process_rule_for_ipv4();
		return result == NF_DROP ? NF_DROP : NF_ACCEPT;  // can not just return result;
	}
	//handle ipv6 packet
	else if (skb->protocol == htons(ETH_P_IPV6))
	{
		ipv6_header = ipv6_hdr(skb);
		printk("this is a ipv6 packet!\n");
		result = process_rule_for_ipv6();
		return result == NF_DROP ? NF_DROP : NF_ACCEPT;  // can not just return result;
	}
	printk("Unkonw ip protocol!\n");
	
	return NF_ACCEPT;
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
	my_hook_ops.hooknum = NF_INET_POST_ROUTING;	//在NF_INET_PRE_ROUTING点上处理数据包 Linux 主机自己发出的数据包通常不会经过 PREROUTING 阶段，而是经过 OUTPUT 链
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




























