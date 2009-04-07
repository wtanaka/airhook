/* Airhook test driver, copyright 2001 Dan Egnor.
 * This software comes with ABSOLUTELY NO WARRANTY.  You may redistribute it
 * under the terms of the GNU General Public License, version 2.   
 * See the file COPYING for more details. */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include "airhook.h"
#include "airhook-private.h"

struct airhook_socket socket;

struct airhook_outgoing **outgoing = NULL;
size_t outgoing_alloc = 0,outgoing_count = 0;

struct airhook_time now(void) {
	struct airhook_time time;
	struct timeval tv;
	gettimeofday(&tv,NULL);
	time.second = tv.tv_sec;
	time.nanosecond = tv.tv_usec * 1000;
	return time;
}

struct airhook_data read_file(const char *path) {
	FILE *fp = NULL;
	long size = 0;
	struct airhook_data data = { NULL, NULL };
	static unsigned char *buffer = NULL;
	static size_t alloc = 0;

	if (NULL == path)
		fprintf(stderr,"filename expected\n");
	else if (NULL == (fp = fopen(path,"rb")) || fseek(fp,0L,SEEK_END)
	     ||  -1 == (size = ftell(fp)) || fseek(fp,0L,SEEK_SET))
		perror(path);
	else if (0 == size)
		fprintf(stderr,"%s: empty file\n",path);
	else if (size > alloc 
	     &&  NULL == (buffer = realloc(buffer,(alloc = size))))
		perror("malloc");
	else if (size > 0 && 1 != fread(buffer,size,1,fp))
		perror(path);
	else {
		data.begin = buffer;
		data.end = buffer + size;
	}

	if (NULL != fp) fclose(fp);
	return data;
}

void read_packet(void) {
	const char * const path = strtok(NULL,"\n");
	struct airhook_outgoing *out;
	struct airhook_data data = read_file(path);
	if (data.end == data.begin) return;
	if (!airhook_receive(&socket,now(),data)) {
		fprintf(stderr,"%s: invalid packet\n",path);
		return;
	}

	while (airhook_next_incoming(&socket,&data)) {
		printf("m ");
		fwrite(data.begin,data.end - data.begin,1,stdout);
		printf("\n");
	}

	while (airhook_next_changed(&socket,&out)) {
		int i;
		for (i = 0; outgoing[i] != out; ++i) ;
		printf("s %d\n",1 + i);
	}
}

void write_packet(void) {
	const char *path = strtok(NULL," \n");
	const char *length = path ? strtok(NULL,"\n") : NULL;
	FILE * const fp = fopen(path,"wb");
	unsigned char *buffer = NULL;
	size_t size = 520,actual;

	if (NULL == fp) {
		if (NULL == path) 
			fprintf(stderr,"filename expected\n");
		else
			perror(path);
		return;
	}

	if (NULL != length) size = atoi(length);

	if (0 == size)
		fprintf(stderr,"%s: invalid length\n",length);
	else if (NULL == (buffer = malloc(size)))
		perror("malloc");
	else if ((actual = airhook_transmit(&socket,now(),size,buffer)) > size)
		fprintf(stderr,"insufficient length %u, need %u\n",size,actual);
	else if (0 == actual)
		printf("nothing to send\n");
	else if (1 != fwrite(buffer,actual,1,fp))
		perror(path);

	free(buffer);
	fclose(fp);
}

void dump_packet(void) {
	const char * const path = strtok(NULL,"\n");
	struct airhook_data data = read_file(path);
	struct packet packet;
	
	if (data.end == data.begin)
		return;
	else if (!input_packet(&packet,data.begin,data.end))
		fprintf(stderr,"%s: invalid packet\n",path);
	else  {
		struct message *m; 
		printf("sequence: %04hx\n",packet.sequence);
		printf("sequence_observed: %02hhx\n",packet.sequence_observed);
		if (packet.interval)
			printf("interval: %02hhx\n",packet.interval);
		if (packet.session)
			printf("session: %08lx\n",packet.session);
		if (packet.session_observed)
			printf("session_observed: %08lx\n",packet.session_observed);
		if (packet.missed_begin != packet.missed_end) {
			printf("missed:");
			do printf(" %02hhx",*packet.missed_begin++);
			while (packet.missed_begin != packet.missed_end);
			printf("\n");
		}
		printf("unsent: %02hhx\n",packet.unsent);
		for (m = packet.data; m != packet.data_end; ++m)
			printf("message: %.*s\n",m->end - m->begin,m->begin);
	}
}

static const char *state_name(enum airhook_state state) {
	switch (state) {
	case ah_pending: return "pending";
	case ah_sent: return "sent";
	case ah_confirmed: return "confirmed";
	case ah_discarded: return "discarded";
	default: return "(invalid!)";
	}
}

static const char *time_name(struct airhook_time time) {
	static char buf[256];
	time_t sec = time.second;
	strftime(buf,sizeof(buf),"%Y-%m-%d %H:%M:%S",localtime(&sec));
	sprintf(buf,"%s.%03lu",buf,time.nanosecond / 1000000);
	return buf;
}

void print_status(void) {
	const char * const name = strtok(NULL,"\n");
	if (NULL != name) {
		const int number = atoi(name);
		struct airhook_outgoing_status status;
		if (0 == number || outgoing_count < number) {
			fprintf(stderr,"%s: invalid message\n",name);
			return;
		}

		status = airhook_outgoing_status(outgoing[number - 1]);
		printf("data: %.*s\n",
			status.data.end - status.data.begin,
			status.data.begin);
		printf("state: %s\n",state_name(status.state));
		printf("transmit_count: %lu\n",status.transmit_count);
		printf("last_change: %s\n",time_name(status.last_change));
	} else {
		struct airhook_status status = airhook_status(&socket);
		if (status.session) 
			printf("session: %08lx\n",status.session);
		if (status.remote_session) 
			printf("session: %08lx\n",status.remote_session);
		printf("state: %s\n",state_name(status.state));
		printf("remote_state: %s\n",state_name(status.remote_state));
		printf("last_transmit: %s\n",time_name(status.last_transmit));
		printf("next_transmit: %s\n",time_name(status.next_transmit));
		printf("last_response: %s\n",time_name(status.last_response));
	}
}

void discard_message(void) {
	const char * const name = strtok(NULL,"\n");
	if (NULL == name)
		fprintf(stderr,"message number expected\n");
	else {
		const int number = atoi(name);
		if (0 == number || outgoing_count < number)
			fprintf(stderr,"%s: invalid message\n",name);
		else
			airhook_discard_outgoing(outgoing[number - 1]);
	}
}

void send_message(void) {
	const char *message = strtok(NULL,"\n");
	if (NULL == message) {
		fprintf(stderr,"message expected\n");
		return;
	}

	if (outgoing_count == outgoing_alloc) {
		const size_t alloc = outgoing_alloc ? outgoing_alloc * 2 : 16;
		struct airhook_outgoing ** const out = 
			realloc(outgoing,sizeof(*out) * alloc);
		if (NULL == out) {
			perror("malloc");
			return;
		}

		outgoing_alloc = alloc;
		outgoing = out;
	}


	message = strdup(message);
	if (NULL == message)
		perror("strdup");
	else {
		struct airhook_data data;
		struct airhook_outgoing * const out = malloc(sizeof(*out));
		data.begin = message;
		data.end = message + strlen(message);

		if (NULL == out)
			perror("malloc");
		else {
			airhook_init_outgoing(out,&socket,data,NULL);
			outgoing[outgoing_count++] = out;
			printf("s %d\n",outgoing_count);
		}
	}
}

int main() {
	airhook_init(&socket,time(NULL));
	for (;;) {
		char line[1024],*command;
		fprintf(stderr,"] ");
		if (NULL == fgets(line,sizeof(line),stdin)) break;
		command = strtok(line," \n");
		if (NULL == command || !strcmp(command,"")) ;
		else if (!strcmp(command,"r")) read_packet();
		else if (!strcmp(command,"w")) write_packet();
		else if (!strcmp(command,"p")) dump_packet();
		else if (!strcmp(command,"m")) send_message();
		else if (!strcmp(command,"s")) print_status();
		else if (!strcmp(command,"d")) discard_message();
		else {
			fprintf(stderr,"invalid command: %s\n"
			"commands: r filename        -- read packet\n"
			"          w filename length -- write packet\n"
			"          p filename        -- print packet\n"
			"          m message         -- send message\n"
			"          s                 -- get status\n"
			"          s num             -- get message status\n"
			"          d num             -- discard message\n",
			command);
		}
	}

	return 0;
}
