/* Airhook protocol library, copyright 2001 Dan Egnor.
 * This software comes with ABSOLUTELY NO WARRANTY.  You may redistribute it
 * under the terms of the GNU General Public License, version 2.
 * See the file COPYING for more details. */

#ifndef AIRHOOK_PRIVATE_H
#define AIRHOOK_PRIVATE_H

#include <stddef.h>

struct message {
	const unsigned char *begin;
	const unsigned char *end;
};

struct packet {
	unsigned short sequence;
	unsigned char sequence_observed;
	unsigned char interval;
	unsigned long session;
	unsigned long session_observed;
	const unsigned char *missed_begin,*missed_end;
	unsigned char unsent;
	struct message data[0x100],*data_end;
};

size_t packet_length(const struct packet *in);
void output_packet(unsigned char *out,const struct packet *in);
int input_packet(struct packet *out,
	const unsigned char *begin,
	const unsigned char *end);

#endif
