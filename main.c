#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
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

#define MAX_RULE 50

void sigint_handler(int signum)
{
	printf("exit and remove the module\n");
	//remove
	exit(1);
}

int read_rules_from_file(const char *filename, struct my_rule *rules, int max_rules,  int *rule_count)
{
	FILE *file = fopen(filename, "r");
	if (file == NULL)
	{
		perror("Failed to open file!");
		return -1;
	}
	
	while(*rule_count < max_rules && 
		fscanf(file, "%hu %u %hu %u %hu %u %u %u %u",
			&rules[*rule_count].rule,
			&rules[*rule_count].src_add,
			&rules[*rule_count].src_port,
			&rules[*rule_count].dst_add,
			&rules[*rule_count].dst_port,
			&rules[*rule_count].protocol,
			&rules[*rule_count].time_flag,
			&rules[*rule_count].time_begin,
			&rules[*rule_count].time_end) == 9)
	{
		(*rule_count)++;
	}
	
	fclose(file);
	return *rule_count;
}
int main()
{
	int fd, rule_count = 0;
	struct my_rule rules[MAX_RULE];
	memset(&rules, 0, sizeof(struct my_rule) * MAX_RULE);
	
	if (signal(SIGINT, sigint_handler) == SIG_ERR)
	{
		perror("Failed to set signal handler");
		return 1;
	}
	
	read_rules_from_file("rule.txt", rules, MAX_RULE, &rule_count);

	if (mknod("/dev/controlinfo", S_IFCHR | 0666, makedev(124, 0)) == -1) 
	{
        	perror("mknod error\n");
    }
	fd = open("/dev/controlinfo", O_WRONLY);

	if (fd == -1)
	{
		printf("Failed to open device file\n");
		return -1;
	}	
    	
	printf("rule_count %d\n", rule_count);
	ssize_t bytes_written = write(fd, &rules, sizeof(struct my_rule) * rule_count);
	if (bytes_written == -1)
	{
		perror("Failed to write to device\n");
		close(fd);
		return -1;
	}
	printf("Wrote %zd bytes to the devide \n", bytes_written);

	close(fd);
	return 0;
}


















