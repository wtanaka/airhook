/* Airhook connect-and-test utility, copyright 2001 Dan Egnor.
 * This software comes with ABSOLUTELY NO WARRANTY.  You may redistribute it
 * under the terms of the GNU General Public License, version 2. 
 * See the file COPYING for more details. */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <sys/types.h>
#include <sys/time.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "airhook.h"

enum { packet_size = 1500 };

struct message {
	struct airhook_outgoing outgoing;
	char data[1 + airhook_size_maximum];
};

int run_airhook(int sock,struct sockaddr_in verify) {
	unsigned long last_session = 0;
	struct timeval now;
	struct airhook_socket air;
	unsigned char buffer[packet_size];

	airhook_init(&air,time(NULL));
	gettimeofday(&now,NULL);

	for (;;) {
		int r;
		fd_set rfd,wfd;
		struct timeval tout,*pout = NULL;
		struct airhook_data data;
		struct airhook_status status;
		struct airhook_outgoing *out;

		FD_ZERO(&rfd);
		FD_SET(sock,&rfd);
		FD_SET(0,&rfd);

		FD_ZERO(&wfd);
		status = airhook_status(&air);
		if (status.remote_session != last_session) {
			fprintf(stderr,"airhook: new remote session\n");
			last_session = status.remote_session;
		}

		while (airhook_next_incoming(&air,&data)) {
			fwrite(data.begin,data.end-data.begin,1,stdout);
			fflush(stdout);
		}

		if (now.tv_sec > status.next_transmit.second
		|| (now.tv_sec == status.next_transmit.second
		&&  now.tv_usec > status.next_transmit.nanosecond / 1000))
			FD_SET(sock,&wfd);
		else {
			tout.tv_sec = status.next_transmit.second;
			tout.tv_usec = status.next_transmit.nanosecond / 1000;
			if (tout.tv_sec > 0) {
				if (tout.tv_usec < now.tv_usec) {
					--tout.tv_sec;
					tout.tv_usec += 1000000;
				}
				tout.tv_usec -= now.tv_usec;
				tout.tv_sec -= now.tv_sec;
				pout = &tout;
			}
		}

		r = select(FD_SETSIZE,&rfd,&wfd,NULL,pout);
		if (r < 0) {
			perror("select");
			return 1;
		}

		gettimeofday(&now,NULL);
		if (r == 0) continue;

		if (FD_ISSET(0,&rfd)) {
			struct message *msg = malloc(sizeof(struct message));
			if (NULL == msg) {
				perror("malloc");
				return 1;
			}

			if (NULL == fgets(msg->data,sizeof(msg->data),stdin))
				return 0;

			data.begin = msg->data;
			data.end = msg->data + strlen(msg->data);
			airhook_init_outgoing(&msg->outgoing,&air,data,msg);
		}

		if (FD_ISSET(sock,&wfd)) {
			struct airhook_time when;
			when.second = now.tv_sec;
			when.nanosecond = now.tv_usec * 1000;
			r = airhook_transmit(&air,when,packet_size,buffer);
			if (r > 0) {
				r = send(sock,buffer,r,0);
				if (r < 0) perror("send");
			}
		}

		if (FD_ISSET(sock,&rfd)) {
			struct airhook_time when;
			struct sockaddr_in from;
			socklen_t fromlen = sizeof(from);

			when.second = now.tv_sec;
			when.nanosecond = now.tv_usec * 1000;
			r = recvfrom(sock,
				buffer,sizeof(buffer),0,
				(struct sockaddr *) &from,&fromlen);

			if (r < 0) 
				perror("recvfrom");
			else {
				struct airhook_data data;
				data.begin = buffer;
				data.end = r + buffer;
				if (!airhook_receive(&air,when,data))
					fprintf(stderr,"invalid packet\n");
			}
		}

		while (airhook_next_changed(&air,&out)) {
			const struct airhook_outgoing_status status =
				airhook_outgoing_status(out);
			if (ah_confirmed == status.state) {
				airhook_discard_outgoing(out);
				free(status.user);
			}
		}
	}
}

int main(int argc,char *argv[]) {
	struct hostent *host;
	int sock,local,remote;
	struct sockaddr_in sin;

	if (4 != argc) {
		fputs(
"Airhook connect-and-test utility version 1, copyright 2001 Dan Egnor.\n"
"\n"
"usage: aircat lport rhost rport\n"
"Uses port <lport> and attempts to connect to a peer running on host\n"
"<rhost> and port <rport>.  Lines of text from standard input are sent\n"
"as Airhook messages.  Incoming messages are written to standard output.\n"
"\n"
"This software comes with ABSOLUTELY NO WARRANTY.  You may redistribute it\n"
"under the terms of the GNU General Public License, Version 2.\n"
		, stderr);
		return 3;
	}

	local = atoi(argv[1]);
	if (local <= 0 || local >= 65536) {
		fprintf(stderr,"%s: invalid local port\n",argv[1]); 
		return 3; 
	} 

	remote = atoi(argv[3]);
	if (remote <= 0 || remote >= 65536) {
		fprintf(stderr,"%s: invalid remote port\n",argv[3]);
		return 3;
	}

	host = gethostbyname(argv[2]);
	if (NULL == host) {
		herror(argv[2]);
		return 2;
	}

	sin.sin_family = AF_INET;
	if (sin.sin_family != host->h_addrtype
	||  sizeof(sin.sin_addr) != host->h_length) {
		fprintf(stderr,"%s: wrong address type\n",argv[2]);
		return 2;
	}

	sock = socket(PF_INET,SOCK_DGRAM,0);
	if (sock < 0) {
		perror("socket");
		return 1;
	}

	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(local);
	if (bind(sock,(struct sockaddr *) &sin,sizeof(sin))) {
		perror("bind");
		return 1;
	}

	sin.sin_addr = * (struct in_addr *) host->h_addr;
	sin.sin_port = htons(remote);
	if (connect(sock,(struct sockaddr *) &sin,sizeof(sin))) {
		perror("connect");
		return 1;
	}

	run_airhook(sock,sin);
	return 1;
}
