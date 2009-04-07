/* TCP loopback test utility, copyright 2001 Dan Egnor.
 * This software comes with ABSOLUTELY NO WARRANTY.  You may redistribute it
 * under the terms of the GNU General Public License, version 2.
 * See the file COPYING for more details. */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/uio.h>
#include <netdb.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

struct state {
	unsigned int counter;
	unsigned int value;
};

unsigned char next(struct state *state) {
	if (0 == state->value) {
		state->value = ++(state->counter);
		return ' ';
	} else {
		unsigned char ch = '0' + (state->value % 10);
		state->value /= 10;
		return ch;
	}
}

void fill(unsigned char *buffer,int length) {
	static struct state state = { 0, 0 };
	while (0 != length--) *buffer++ = next(&state);
}

int drain(unsigned char *buffer,int length) {
	static struct state state = { 0, 0 };
	while (0 != length--) if (next(&state) != *buffer++) return 0;
	return 1;
} 

int main(int argc,char *argv[]) {
	int sock;
	unsigned char buffer[8192];
	size_t buffer_pos;

	int opt;
	char *end;

	double max_time = 0.0;
	size_t max_bytes = (size_t) -1;
	size_t bytes_written = 0,bytes_read = 0;

	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(7);

	while (EOF != (opt = getopt(argc,argv,"s:t:")))
	switch (opt) {
	case 's':
		max_bytes = strtoul(optarg,&end,0);
		if ('\0' == *optarg || '\0' != *end || 0 == max_bytes) {
			fprintf(stderr,"%s: invalid length\n",optarg);
			return 2;
		}
		break;

	case 't':
		max_time = strtod(optarg,&end);
		if ('\0' == *optarg || '\0' != *end || max_time <= 0.0) {
			fprintf(stderr,"%s: invalid timeout\n",optarg);
			return 2;
		}
		break;

	case '?':
	usage:
		fputs(
"TCP loopback test utility version 1, copyright 2001 Dan Egnor.\n"
"\n"
"usage: looptest [flags] host [port]\n"
"flags: -s bytes         Maximum amount of data to send\n"
"       -t seconds       Maximum time in seconds to run\n"
"\n"
"Connects to TCP <host> and <port> (default 7), transmits a continuous stream\n"
"of data, expects to receive the same data in return, verifies consistency\n"
"and measures throughput.  Will run forever if not limited or stopped.\n"
		, stderr);
		return 2;
	}

	if (argc - optind == 2) {
		const char * const name = argv[optind + 1];
		struct servent * const service = getservbyname(name,"tcp");
		if (NULL != service)
			sin.sin_port = htons(service->s_port);
		else {
			sin.sin_port = htons(strtoul(name,&end,0));
			if ('\0' == *name || '\0' != *end 
			||  0 == sin.sin_port) {
				fprintf(stderr,"%s: invalid port\n",name);
				return 1;
			}
		}
		--argc;
	}

	if (argc - optind != 1) 
		goto usage;
	else {
		const char * const name = argv[optind];
		struct hostent * const host = gethostbyname(name);
		if (NULL == host) {
			fprintf(stderr,"%s: invalid host\n",name);
			return 1;
		}

		if (sin.sin_family != host->h_addrtype
		||  sizeof(sin.sin_addr) != host->h_length) {
			fprintf(stderr,"%s: wrong address type\n",name);
			return 1;
		}

		sin.sin_addr = * (struct in_addr *) host->h_addr;
		--argc;
	}

	sock = socket(PF_INET,SOCK_STREAM,0);
	if (sock < 0) {
		perror("socket");
		return 1;
	}

	if (connect(sock,(struct sockaddr *) &sin,sizeof(sin))) {
		perror("connect");
		return 1;
	}

	fill(buffer,sizeof(buffer));
	buffer_pos = 0;

	for (;;) {
		int r;
		fd_set rfd,wfd;

		FD_ZERO(&rfd);
		FD_SET(sock,&rfd);
		FD_ZERO(&wfd);
		if (0 != max_bytes) FD_SET(sock,&wfd);
		r = select(1 + sock,&rfd,&wfd,NULL,NULL); /* TODO: timeout */
		if (r < 0) {
			perror("select");
			return 1;
		}

		if (FD_ISSET(sock,&rfd)) {
			unsigned char buffer[8192];
			r = read(sock,buffer,sizeof(buffer));
			if (r < 0) perror("read");
			if (0 != max_bytes && 0 == r)
				fputs("read: connection closed\n",stderr);
			if (r <= 0) break;

			bytes_read += r;
			if (!drain(buffer,r)) break;
		}

		if (FD_ISSET(sock,&wfd)) {
			struct iovec iov[2];
			iov[0].iov_base = &buffer[buffer_pos];
			iov[0].iov_len = sizeof(buffer) - buffer_pos;
			if (max_bytes != (size_t) -1
			&& iov[0].iov_len > max_bytes) {
				iov[0].iov_len = max_bytes;
				iov[1].iov_len = 0;
			} else {
				iov[1].iov_base = &buffer[0];
				iov[1].iov_len = buffer_pos;
				if (max_bytes != (size_t) -1
				&& iov[1].iov_len > max_bytes - iov[0].iov_len)
					iov[1].iov_len = 
						max_bytes - iov[0].iov_len;
			}

			r = writev(sock,iov,2);
			if (r < 0) {
				perror("write");
				max_bytes = 0;
			} else {
				if (max_bytes != (size_t) -1) max_bytes -= r;
				bytes_written += r;
				if (r > iov[0].iov_len) {
					buffer_pos = r - iov[0].iov_len;
					fill(iov[0].iov_base,iov[0].iov_len);
					fill(iov[1].iov_base,buffer_pos);
				} else {
					fill(iov[0].iov_base,r);
					buffer_pos += r;
				}
			}

			if (0 == max_bytes && shutdown(sock,1))
				perror("shutdown");
		}
	}

	printf("read: %d; written: %d\n",bytes_read,bytes_written);
	return 0;
}
