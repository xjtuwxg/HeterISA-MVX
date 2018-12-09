#include <stdio.h>
#include <stdlib.h>	// system
#include <unistd.h>

int main()
{
	char name[30];
	char cmd[512];
	sprintf(cmd, "cat /proc/%d/maps", getpid());
	int ret = 0;
	//printf("%s", cmd);
	//system(cmd);

	while (1) {
		printf("Input your name: \n");
		fflush(stdout);
		ret = scanf("%s", name);
		//ret = read(0, name, 100);
		printf("pid: %d. test. Hi %s. ret %d\n", getpid(), name, ret);
	}
	return 0;
}
