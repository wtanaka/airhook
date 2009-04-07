/* Airhook TCP proxy, copyright 2001 Dan Egnor.
 * This software comes with ABSOLUTELY NO WARRANTY.  You may redistribute it
 * under the terms of the GNU General Public License, version 2.   
 * See the file COPYING for more details. */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <sys/types.h>
#include <sys/time.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <syslog.h>
#include <fcntl.h>
#include <errno.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "airhook.h"

enum { packet_size = 1500 };
enum { allocation_size = 8192 };
enum { escape_value = airhook_size - 1 };

struct owner {
	unsigned int use_count;
	unsigned char data[1];
};

struct memory {
	struct owner *owner;
	unsigned char *begin,*end;
};

enum {
	input_closed = 1,
	output_closed = 2,
	is_dirty = 128,
};

struct options {
	struct airhook_time keepalive;
	struct airhook_time timeout;
	struct sockaddr_in remote;
};

struct socket {
	signed short handle;
	struct memory incoming[256];
	struct airhook_outgoing outgoing[256];
	struct airhook_outgoing handshake;
	unsigned char out_head,out_tail;
	unsigned char in_tail;
	unsigned char flags,out_flags;
	unsigned short out_pending;
};

static struct memory current = { NULL, NULL, NULL };
static unsigned int socket_count = 0;

static struct socket *active = NULL;
static unsigned int active_size = 0;

static unsigned short *handle = NULL;
static unsigned int handle_size = 0;

static struct memory get_memory(unsigned long min) {
	struct memory mem = current;
	unsigned long size;
	if (NULL != mem.owner && mem.end - mem.begin >= min) {
		current.owner = NULL;
		return mem;
	}

	size = min + sizeof(*mem.owner) - sizeof(mem.owner->data);
	if (size < allocation_size) size = allocation_size;
	mem.owner = malloc(size);
	if (NULL == mem.owner) {
		syslog(LOG_ERR,"malloc: %m");
		exit(1);
	}

	mem.begin = &mem.owner->data[0];
	mem.end = &mem.owner->data[size
		- sizeof(*mem.owner) 
		+ sizeof(mem.owner->data)];
	mem.owner->use_count = 1;
	return mem;
}

static void release_memory(struct memory mem) {
	if (NULL != current.owner) {
		if (current.end - current.begin > mem.end - mem.begin) {
			if (0 == --mem.owner->use_count) free(mem.owner);
			return;
		}
		if (0 == --current.owner->use_count) free(current.owner);
	}

	current = mem;
}

static void release_outgoing(struct airhook_outgoing *out) {
	const struct airhook_outgoing_status status =
		airhook_outgoing_status(out);
	if (ah_discarded != status.state) {
		const struct memory mem = {
			(struct owner *) status.user,
			(unsigned char *) status.data.begin,
			(unsigned char *) status.data.end
		};
		airhook_discard_outgoing(out);
		release_memory(mem);
	}
}

static unsigned char inc(unsigned char ch) {
	++ch;
	if (escape_value == ch) ++ch;
	return ch;
}

static void close_socket(int i) {
	unsigned char c = active[i].in_tail;
	do {
		if (NULL != active[i].incoming[c].owner) 
			release_memory(active[i].incoming[c]);
		c = inc(c);
	} while (c != active[i].in_tail);

	while (active[i].out_tail != active[i].out_head) {
		release_outgoing(&active[i].outgoing[active[i].out_tail]);
		active[i].out_tail = inc(active[i].out_tail);
	}

	release_outgoing(&active[i].handshake);
        if (active[i].handle < 0) {
                assert(-active[i].handle < handle_size);
                handle[-active[i].handle] = 0;
        }
	active[i].handle = 0;
	close(i);
        --socket_count;
}

static void send_handshake(struct airhook_socket *air,int i) {
	struct memory mem = get_memory(5);
	const struct airhook_data data = { mem.begin, mem.begin + 5 };

	++mem.owner->use_count;
	mem.begin += data.end - data.begin;
	release_memory(mem);

	mem.end = mem.begin;
	mem.begin -= data.end - data.begin;
	mem.begin[0] = active[i].handle >> 8; /* BUG? */
	mem.begin[1] = active[i].handle & 0xFF;
	mem.begin[2] = escape_value;
	mem.begin[3] = active[i].out_flags;
	mem.begin[4] = active[i].in_tail;
	airhook_init_outgoing(&active[i].handshake,air,data,mem.owner);
}

static void open_socket(struct airhook_socket *air,int i) {
	unsigned char c = 0;

	if (i >= active_size) {
		active = realloc(active,sizeof(*active)*(1 + 2*i));
		if (NULL == active) {
			syslog(LOG_ERR,"malloc: %m");
			exit(1);
		}

		while (active_size <= 2*i) active[active_size++].handle = 0;
	}

	assert(0 == active[i].handle);
	do {
		active[i].incoming[c].owner = NULL;
		c = inc(c);
	} while (0 != c);

	active[i].handle = i;
	active[i].out_head = active[i].out_tail = 0;
	active[i].in_tail = 0;
	active[i].flags = active[i].out_flags = 0;
	active[i].out_pending = 0;
	fcntl(i,F_SETFL,O_NONBLOCK);
        ++socket_count;
}

static void reset(void) {
        int i;
	for (i = 0; i < active_size; ++i)
		if (0 != active[i].handle && (active[i].flags & is_dirty))
			close_socket(i);
}

static void run(
	struct airhook_socket *air,
	struct options opt,int udp,int tcp)
{
	unsigned long last_session = 0;
	struct timeval last,now;
	struct airhook_time idle;
	unsigned char buffer[packet_size];

	gettimeofday(&now,NULL);
	last = now;

	idle.second = 2 * opt.keepalive.second;
	idle.nanosecond = 2 * opt.keepalive.nanosecond;
	if (idle.nanosecond > 1000000000) {
		idle.nanosecond -= 1000000000;
		++idle.second;
	}

	if (0 == tcp) {
		tcp = dup(tcp);
		if (tcp < 0) {
			syslog(LOG_ERR,"TCP socket: %m");
			exit(1);
		}

		close(0);
		open_socket(air,tcp);
		send_handshake(air,tcp);
		tcp = -1;
	}

	for (;;) {
		int i,r;
		int delay_update = 0;
		fd_set rfd,wfd;
		struct airhook_data data;
		struct airhook_time next;
		struct airhook_status status;
		struct airhook_outgoing *out;

		status = airhook_status(air);
		if (status.remote_session != last_session) {
			last_session = status.remote_session;
                        reset();
		}

                /* Discard confirmed data. */
		while (airhook_next_changed(air,&out)) {
			const struct airhook_outgoing_status s =
				airhook_outgoing_status(out);
			if (ah_confirmed == s.state)
				release_outgoing(out);
		}

                /* Process incoming messages.  Must happen after confirmed
                 * data is discarded. */
		while (airhook_next_incoming(air,&data)) {
			signed short h;
			unsigned char seq;

			if (data.end - data.begin < 4
			|| (escape_value == data.begin[2]
			&&  data.end - data.begin < 5)) {
				syslog(LOG_WARNING,"truncated message received");
				continue;
			}

			h = (data.begin[0] << 8) | data.begin[1];
			h = -h;
			if (h < 0) {
				if (-h >= handle_size) {
					handle = realloc(handle,
						sizeof(*handle) * 2 * (-h + 1));
					if (NULL == handle) {
						syslog(LOG_ERR,"malloc: %m");
						exit(1);
					}

					while (handle_size <= 2 * -h)
						handle[handle_size++] = 0;
				}

				i = handle[-h];
				if (0 == i) {
					i = socket(PF_INET,SOCK_STREAM,0);
					/* TODO: i < 0? */
					open_socket(air,i);
					handle[-h] = i;
					active[i].handle = h;
					active[i].flags |= is_dirty;
                                        send_handshake(air,i);
					if (connect(i,
						(struct sockaddr *) &opt.remote,
						sizeof(opt.remote))
					&&  errno != EINPROGRESS)
						active[i].flags |=
							  input_closed
							| output_closed;
				}
			} else if (h >= active_size || 0 == active[h].handle) {
				syslog(LOG_WARNING,"unknown link");
				continue;
			} else
				i = h;

			seq = data.begin[2];
			if (escape_value == seq) {
				const unsigned char flags = data.begin[3];
				const unsigned char tail = data.begin[4];

				if (flags & output_closed) {
				        if (!(active[i].flags & input_closed))
        					shutdown(i,0);
                                        active[i].flags |= input_closed;
                                        active[i].out_flags |= input_closed;
                                }

				if (flags & input_closed) {
				        if (!(active[i].flags & output_closed))
        					shutdown(i,1);
                                        active[i].flags |= output_closed;
                                        active[i].out_flags |= output_closed;
                                }

				while (active[i].out_tail != tail 
				   &&  active[i].out_tail != active[i].out_head)
				{
					struct airhook_outgoing * const out =
						&active[i].outgoing[
							active[i].out_tail];
					const struct airhook_outgoing_status s =
						airhook_outgoing_status(out);
					if (ah_discarded != s.state) {
						syslog(LOG_WARNING,"bad");
						break;
					}

					active[i].out_pending -= 
						s.data.end - s.data.begin - 3;
					active[i].out_tail = 
						inc(active[i].out_tail);
				}
			} else {
				struct memory * const mem = 
                                        &active[i].incoming[seq];
				const unsigned long len = 
					data.end - data.begin - 3;
				if (NULL != mem->owner) {
					syslog(LOG_WARNING,"overflow");
					continue;
				}

				*mem = get_memory(len);
				memcpy(mem->begin,data.begin + 3,len);

				++mem->owner->use_count;
				mem->begin += len;
				release_memory(*mem);
				mem->end = mem->begin;
				mem->begin -= len;
			}
		}

                /* Check flags for outgoing updates or closed connections.
                 * Must come after incoming messages are processed and
                 * after confirmations are discarded. */
		for (i = 0; i < active_size; ++i) {
                        unsigned char out_flags;
			if (0 == active[i].handle) continue;

                        out_flags = active[i].flags & ~is_dirty;
			if (active[i].out_head != active[i].out_tail)
				out_flags &= ~input_closed;

                        out_flags |= active[i].out_flags;
			if (out_flags != active[i].out_flags) {
				active[i].out_flags = out_flags;
				release_outgoing(&active[i].handshake);
				send_handshake(air,i);
                                continue;
			}

			if ((active[i].out_flags & input_closed)
			&&  (active[i].out_flags & output_closed)) {
                                const struct airhook_outgoing_status s =
                                        airhook_outgoing_status(
                                                &active[i].handshake);
                                if (ah_discarded == s.state) close_socket(i);
                        }
		}

		/* If we have no way to get more TCP sockets, we're done. */
		if (0 == socket_count && 0 > tcp && 0 == opt.remote.sin_port)
			break;

		/* Check for timeout. */
		if (now.tv_sec > last.tv_sec
		|| (now.tv_sec == last.tv_sec && now.tv_usec > last.tv_usec)) {
			struct timeval age;
			age.tv_sec = now.tv_sec - last.tv_sec;
			if (now.tv_usec >= last.tv_usec)
				age.tv_usec = now.tv_usec - last.tv_usec;
			else {
				--age.tv_sec;
				age.tv_usec = 1000000+now.tv_usec-last.tv_usec;
			}

			if (0 == socket_count
			&& (age.tv_sec > idle.second
			|| (age.tv_sec == idle.second
			&&  age.tv_usec > idle.nanosecond / 1000)))
				break;

			if (age.tv_sec > opt.timeout.second
			|| (age.tv_sec == opt.timeout.second
			&&  age.tv_usec > opt.timeout.nanosecond / 1000)) {
				reset();
				last = now;
			}
		}

                /* Compute fd_set and timeout for select.
                 * Must come after everything else. */
		status = airhook_status(air);

		FD_ZERO(&rfd);
		FD_ZERO(&wfd);
		FD_SET(udp,&rfd);
		if (tcp >= 0) FD_SET(tcp,&rfd);

		for (i = 0; i < active_size; ++i) {
			if (0 == active[i].handle) continue;

			if (status.wanted > 0
			&&  active[i].out_pending < status.settings.window_size
			&&  inc(active[i].out_head) != active[i].out_tail
                        && ((active[i].flags & is_dirty)
                        ||  ah_discarded
                        ==  airhook_outgoing_status(&active[i].handshake).state)
			&& !(active[i].flags & input_closed))
				FD_SET(i,&rfd);

			if (NULL != active[i].incoming[active[i].in_tail].owner
			&& !(active[i].flags & output_closed))
				FD_SET(i,&wfd);
		}

		next = status.last_transmit;
		next.second += opt.keepalive.second;
		next.nanosecond += opt.keepalive.nanosecond;
		if (next.nanosecond > 1000000000) {
			++next.second;
			next.nanosecond -= 1000000000;
		}

		if (next.second > status.next_transmit.second
		|| (next.second == status.next_transmit.second
		&&  next.nanosecond > status.next_transmit.nanosecond))
			next = status.next_transmit;

		if (now.tv_sec > next.second
		|| (now.tv_sec == next.second
		&&  now.tv_usec > next.nanosecond / 1000)) {
			FD_SET(udp,&wfd);
			r = select(FD_SETSIZE,&rfd,&wfd,NULL,NULL);
		} else {
			struct timeval tv;
			if (next.nanosecond / 1000 < now.tv_usec) {
				--next.second;
				next.nanosecond += 1000000000;
			}

			tv.tv_sec = next.second - now.tv_sec;
			tv.tv_usec = next.nanosecond / 1000 - now.tv_usec;
			r = select(FD_SETSIZE,&rfd,&wfd,NULL,&tv);
		}

		if (r < 0) {
			syslog(LOG_ERR,"select: %m");
			exit(1);
		}

		gettimeofday(&now,NULL);
		if (r == 0) continue;

                /* Accept new incoming connections. */
		if (tcp >= 0 && FD_ISSET(tcp,&rfd)) {
			struct sockaddr_in sin;
			socklen_t len = sizeof(sin);
			const int s = accept(tcp,(struct sockaddr *) &sin,&len);
			if (s < 0) 
				syslog(LOG_WARNING,"accept: %m");
			else {
				open_socket(air,s);
                                send_handshake(air,s);
                        }
		}

		for (i = 0; i < active_size; ++i) {
			unsigned char in_tail = active[i].in_tail;
			if (0 == active[i].handle) continue;

			if (FD_ISSET(i,&rfd)) {
				struct memory mem = get_memory(4);
				const unsigned long len = mem.end - mem.begin;
				unsigned long max = len - 3;
				if (max > airhook_message_size - 3)
					max = airhook_message_size - 3;

				active[i].flags |= is_dirty;
				r = read(i,3 + mem.begin,max); /* TODO: ??? */
				if (r <= 0)
					active[i].flags |= input_closed;
				else {
					struct airhook_data data;
					mem.begin[0] = active[i].handle >> 8;
					mem.begin[1] = active[i].handle;
					mem.begin[2] = active[i].out_head;
					data.begin = mem.begin;
					data.end = mem.begin + 3 + r;
					airhook_init_outgoing(
						&active[i].outgoing[
							active[i].out_head],
						air,data,mem.owner);
					active[i].out_head = 
						inc(active[i].out_head);
					active[i].out_pending += r;
					AIRHOOK_ASSERT(active[i].out_head 
					            != active[i].out_tail);

					++mem.owner->use_count;
					mem.begin += 3 + r;
				}

				release_memory(mem);
				delay_update = 1;
			}

			if (FD_ISSET(i,&wfd)) {
				struct memory * const mem = 
					&active[i].incoming[in_tail];
				const unsigned long len = 
					mem->end - mem->begin;

				active[i].flags |= is_dirty;
				r = write(i,mem->begin,len); /* TODO: writev? */
				if (r <= 0)
					active[i].flags |= output_closed;
				else {
					++mem->owner->use_count;
					mem->end = mem->begin + r;
					release_memory(*mem);

					mem->end = mem->begin + len;
					mem->begin += r;
					if (mem->begin == mem->end) {
						release_memory(*mem);
						mem->owner = NULL;
						in_tail = inc(in_tail);
					}
				}
			}

			if (in_tail != active[i].in_tail) {
				active[i].in_tail = in_tail;
				release_outgoing(&active[i].handshake);
				send_handshake(air,i);
				delay_update = 1;
			}
                }

		if (FD_ISSET(udp,&rfd)) {
			struct airhook_time when;
			when.second = now.tv_sec;
			when.nanosecond = now.tv_usec * 1000;
			r = recv(udp,buffer,sizeof(buffer),0);
			if (r < 0) {
                                if (ECONNREFUSED == errno)
                                        reset();
                                else
				        syslog(LOG_WARNING,"recv: %m");
                        } else {
				const struct airhook_data data = 
					{ buffer, r + buffer };
				if (!airhook_receive(air,when,data))
					syslog(LOG_WARNING,"invalid packet");
				else
					last = now;
			}
		}
		else if (!delay_update && FD_ISSET(udp,&wfd)) {
			struct airhook_time when;
			when.second = now.tv_sec;
			when.nanosecond = now.tv_usec * 1000;
			r = airhook_transmit(air,when,sizeof(buffer),buffer);
			if (r > 0) {
				r = send(udp,buffer,r,0);
				if (r < 0) {
                                        if (ECONNREFUSED == errno)
                                                reset();
                                        else
                                                syslog(LOG_WARNING,"send: %m");
                                }
			}
		}
	}
}

static void usage(struct airhook_settings s,struct options o) {
	fprintf(stderr,
"Airhook TCP proxy version 1, copyright 2001 Dan Egnor\n"
"\n"
"flags: -l [host:]port   Local UDP port [and interface] to receive Airhook\n"
"       -r [host:]port   Remote UDP port [and host] to send Airhook\n"
"       -i [host:]port   Incoming TCP port [and interface] to listen on\n"
"       -o [host:]port   Outgoing TCP port [and host] to connect to\n"
"       -f retransmit    Retransmission interval in seconds (normally %g)\n"
"       -k keepalive     Keepalive interval in seconds (normally %g)\n"
"       -t timeout       Connection timeout in seconds (normally %g)\n"
"       -w windowsize    Transmission window size in bytes (normally %lu)\n"
"\n"
"At least one of -i or -o must be specified unless run from inetd/tcp, and\n"
"at least one of -l or -r must be specified unless run from inetd/udp.\n"
"\n"
"Connections from the remote UDP port are forwarded to the outgoing TCP port.\n"
"Connections to the incoming TCP port are forwarded to the remote UDP port.\n"
"Interfaces default to INADDR_ANY.  Hosts default to the local host.\n"
"\n"
"This software comes with ABSOLUTELY NO WARRANTY.  You may redistribute it\n"
"under the terms of the GNU General Public License, Version 2.\n"
	, s.retransmit.second + 0.000000001 * s.retransmit.nanosecond
	, o.keepalive.second + 0.000000001 * o.keepalive.nanosecond
        , o.timeout.second + 0.000000001 * o.timeout.nanosecond
	, s.window_size);
	exit(3);
}

static struct sockaddr_in parse_address(char *str,const char *proto) {
	struct sockaddr_in sin;
	struct servent *service;
	const char *first = strtok(str,":");
	const char *second = strtok(NULL,"");
	char *end;

	sin.sin_family = AF_INET;
	if (NULL == second) {
		second = first;
		sin.sin_addr.s_addr = 0;
	} else {
		struct hostent * const host = gethostbyname(first);
		if (NULL == host) {
			syslog(LOG_ERR,"%s: unknown host",first);
			exit(2);
		}

		if (sin.sin_family != host->h_addrtype
		||  sizeof(sin.sin_addr) != host->h_length) {
			syslog(LOG_ERR,"%s: wrong address type",first);
			exit(2);
		}

		sin.sin_addr = * (struct in_addr *) host->h_addr;
	}

	service = getservbyname(second,proto);
	if (NULL != service)
		sin.sin_port = service->s_port;
	else {
		sin.sin_port = htons(strtoul(second,&end,0));
		if (*second == '\0' || *end != '\0' || 0 == sin.sin_port) {
			syslog(LOG_ERR,"%s: unknown service and invalid port number",second);
			exit(3);
		}
	}

	return sin;
}

static struct airhook_time parse_time(char *str) {
	char *end;
	const double d = strtod(str,&end);
	struct airhook_time time;
	if ('\0' == *str || '\0' != *end || d <= 0.0) {
		syslog(LOG_ERR,"%s: invalid time value",str);
		exit(2);
	}

	time.second = d;
	time.nanosecond = 1000000000.0 * (d - time.second);
	return time;
}

unsigned long swap(unsigned long value) {
	return ((value & 0x000000FF) << 24)
	     | ((value & 0x0000FF00) <<  8)
             | ((value & 0x00FF0000) >>  8)
             | ((value & 0xFF000000) >> 24);
}

int main(int argc,char *argv[]) {
	int opt;
	struct sockaddr_in local_tcp,remote_tcp;
	struct sockaddr_in local_udp,remote_udp;
	struct airhook_socket airhook;
	struct airhook_settings settings;
	struct options options;
	int udp_socket,tcp_socket,socket_type;
        unsigned long session = time(NULL) ^ swap(getpid());
	socklen_t length = sizeof(int);
	const int o = 1;

	local_tcp.sin_family = AF_INET;
	local_tcp.sin_port = 0;
	local_tcp.sin_addr.s_addr = 0;
	remote_udp = local_udp = remote_tcp = local_tcp;

	openlog("airproxy",LOG_CONS|LOG_PERROR|LOG_PID,LOG_DAEMON);
	signal(SIGCHLD,SIG_IGN);
	signal(SIGPIPE,SIG_IGN);

	airhook_init(&airhook,session);
	settings = airhook_status(&airhook).settings;
	options.keepalive.second = 60;
	options.keepalive.nanosecond = 0;
        options.timeout.second = 86400;
        options.timeout.nanosecond = 0;

	while (EOF != (opt = getopt(argc,argv,"l:r:i:o:f:k:t:w:")))
	switch (opt) {
	case 'l': local_udp = parse_address(optarg,"udp"); break;
	case 'r': remote_udp = parse_address(optarg,"udp"); break;
	case 'i': local_tcp = parse_address(optarg,"tcp"); break;
	case 'o': remote_tcp = parse_address(optarg,"tcp"); break;
	case 'f': settings.retransmit = parse_time(optarg); break;
	case 'k': options.keepalive = parse_time(optarg); break;
        case 't': options.timeout = parse_time(optarg); break;
	case 'w': settings.window_size = strtoul(optarg,NULL,0);
	          if (0 == settings.window_size) {
		          syslog(LOG_ERR,"%s: invalid window size",optarg);
		          exit(2);
	          }
	          break;
	case '?': usage(settings,options);
	}

	if (argc != optind) usage(settings,options);

	if (getsockopt(0,SOL_SOCKET,SO_TYPE,&socket_type,&length)
	||  length != sizeof(socket_type))
		socket_type = -1;

	if (SOCK_STREAM == socket_type) {
		if (0 != local_tcp.sin_port) {
			syslog(LOG_WARNING,"ignoring -i in inetd/tcp mode");
			local_tcp.sin_port = 0;
		}
		if (0 != remote_tcp.sin_port) {
			syslog(LOG_WARNING,"ignoring -o in inetd/tcp mode");
			remote_tcp.sin_port = 0;
		}
		if (0 != local_udp.sin_port) {
			syslog(LOG_WARNING,"ignoring -l in inetd/tcp mode");
			local_udp.sin_port = 0;
		}

		tcp_socket = 0;
	} else if (0 == local_tcp.sin_port && 0 == remote_tcp.sin_port) {
		syslog(LOG_ERR,"invalid usage: no TCP endpoint specified (-i or -o)");
		usage(settings,options);
	} else if (0 == local_tcp.sin_port)
		tcp_socket = -1;
	else {
		struct sockaddr * const local = (struct sockaddr *) &local_tcp;
		tcp_socket = socket(PF_INET,SOCK_STREAM,0);
		if (0 == tcp_socket) {
			tcp_socket = dup(tcp_socket);
			close(0);
		}
		assert(0 != tcp_socket);
		if (tcp_socket < 0
		||  setsockopt(tcp_socket,SOL_SOCKET,SO_REUSEADDR,&o,sizeof(o))
		||  bind(tcp_socket,local,sizeof(local_tcp))
                ||  fcntl(tcp_socket,F_SETFL,O_NONBLOCK)
		||  listen(tcp_socket,20)) {
			syslog(LOG_ERR,"TCP socket: %m");
			exit(1);
		}
	}

	options.remote = remote_tcp;

	if (SOCK_DGRAM == socket_type) {
		if (0 != local_udp.sin_port) {
			syslog(LOG_WARNING,"ignoring -l in inetd/udp mode");
			local_udp.sin_port = 0;
		}
		if (0 != remote_udp.sin_port) {
			syslog(LOG_WARNING,"ignoring -r in inetd/udp mode");
			remote_udp.sin_port = 0;
		}

		udp_socket = 0;
	} else if (0 == local_udp.sin_port && 0 == remote_udp.sin_port) {
		syslog(LOG_ERR,"invalid usage: no UDP endpoint specified (-l or -r)");
		usage(settings,options);
	} else {
		struct sockaddr * const local = (struct sockaddr *) &local_udp;
		udp_socket = socket(PF_INET,SOCK_DGRAM,0);

		if (udp_socket < 0
		||  setsockopt(udp_socket,SOL_SOCKET,SO_REUSEADDR,&o,sizeof(o))
		||  bind(udp_socket,local,sizeof(local_udp))) 
		{
			syslog(LOG_ERR,"UDP socket: %m");
			exit(1);
		}
	}

        fcntl(udp_socket,F_SETFL,O_NONBLOCK);

	if (0 != remote_udp.sin_port) { /* UDP client mode */
		struct sockaddr * const addr = (struct sockaddr *) &remote_udp;
		if (connect(udp_socket,addr,sizeof(remote_udp))) {
			syslog(LOG_ERR,"UDP connect: %m");
			exit(1);
		}
	        airhook_settings(&airhook,settings);
		do run(&airhook,options,udp_socket,tcp_socket);
		while (0 != tcp_socket); /* Exit if run from inetd */
		return 0;
	} 

	assert(0 != tcp_socket);

	do { /* UDP server mode */
                struct sockaddr_in sock,peer;
                socklen_t socklen = sizeof(sock),peerlen = sizeof(peer);
                const int new_socket = socket(PF_INET,SOCK_DGRAM,0);
		struct timeval tv;
		struct airhook_time now;
		unsigned char buf[packet_size];
                fd_set fds;
		int r;

                FD_ZERO(&fds);
                FD_SET(udp_socket,&fds);
                r = select(1 + udp_socket,&fds,NULL,NULL,NULL);
                if (r < 0) {
                        syslog(LOG_ERR,"select: %m");
                        exit(1);
                }

                r = recvfrom(udp_socket,
                        buf,sizeof(buf),0,
                        (struct sockaddr *) &peer,&peerlen);
		if (r < 0) {
			syslog(LOG_WARNING,"recv: %m");
                        close(new_socket);
			continue;
		}

		gettimeofday(&tv,NULL);
		now.second = tv.tv_sec;
		now.nanosecond = tv.tv_usec * 1000;

                if (new_socket < 0
		||  setsockopt(new_socket,SOL_SOCKET,SO_REUSEADDR,
                        &o,sizeof(o))
                ||  getsockname(udp_socket,(struct sockaddr *) &sock,&socklen)
        	||  bind(new_socket,(struct sockaddr *) &sock,socklen)
                ||  connect(new_socket,(struct sockaddr *) &peer,peerlen)) {
		       	syslog(LOG_WARNING,"UDP socket: %m");
                        close(new_socket);
                        continue;
	        }

                ++session;
		if (0 == fork()) {
                        struct airhook_socket airhook;
			struct airhook_data data = { buf, buf + r };
                        close(udp_socket);
                        airhook_init(&airhook,session);
	                airhook_settings(&airhook,settings);
			airhook_receive(&airhook,now,data);
			run(&airhook,options,new_socket,tcp_socket);
			exit(0);
		}

                close(new_socket);
                while (recv(udp_socket,buf,sizeof(buf),0) >= 0) ;
	} while (0 != local_udp.sin_port || 0 != remote_udp.sin_port);
	return 0;
}
