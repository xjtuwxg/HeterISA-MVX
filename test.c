#include <stdio.h>
#include <stdlib.h>	// system
#include <unistd.h>

int main()
{
	char name[30];
	char cmd[512];
	sprintf(cmd, "cat /proc/%d/maps", getpid());
	//printf("%s", cmd);
	//system(cmd);

	printf("Input your name: \n");
	fflush(stdout);
	scanf("%s", name);
	printf("pid: %d. test. Hi %s.\n", getpid(), name);
	return 0;
}
