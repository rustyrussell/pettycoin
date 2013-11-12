#include <ccan/read_write_all/read_write_all.h>
#include <ccan/short_types/short_types.h>
#include <ccan/endian/endian.h>
#include <ccan/err/err.h>
#include <ccan/io/io.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>

static struct io_plan free_contents(struct io_conn *conn, le32 *contents)
{
	free(contents);
	return io_close();
}

static void send_addresses(int fd, void *unused)
{
	struct stat st;
	le32 *contents;
	int addrfd, len;

	addrfd = open("addresses", O_RDONLY);
	if (addrfd < 0)
		err(1, "Opening addresses");

	fstat(addrfd, &st);

	len = sizeof(le32)*2 + st.st_size;
	contents = malloc(len);
	contents[0] = cpu_to_le32(st.st_size);
	contents[1] = 0;
	if (!read_all(addrfd, contents + 2, st.st_size))
		err(1, "Reading %u bytes", (unsigned)st.st_size);
	close(addrfd);

	io_new_conn(fd, io_write(contents, len, free_contents, contents));
}

int main(int argc, char *argv[])
{
	struct addrinfo *addrinfo;
	int fd, on = 1;

	err_set_progname(argv[0]);

	if (getaddrinfo("localhost", "9000", NULL, &addrinfo) != 0)
		err(1, "getaddrinfo failed");

	fd = socket(addrinfo->ai_family, addrinfo->ai_socktype,
		    addrinfo->ai_protocol);
	if (fd < 0)
		err(1, "creating socket");

	freeaddrinfo(addrinfo);

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	if (bind(fd, addrinfo->ai_addr, addrinfo->ai_addrlen) != 0)
		err(1, "binding socket");

	if (listen(fd, 1) != 0)
		err(1, "listening on socket");

	io_new_listener(fd, send_addresses, NULL);

	io_loop();
	exit(1);
}
