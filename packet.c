/* Airhook protocol library, copyright 2001 Dan Egnor.
 * This software comes with ABSOLUTELY NO WARRANTY.  You may redistribute it
 * under the terms of the GNU General Public License, version 2.
 * See the file COPYING for more details. */

#include "airhook-private.h"
#include "airhook.h"

enum {
	flag_interval = 1,
	flag_sent = 2,
	flag_missed = 4,
	flag_session = 8,
	flag_session_observed = 16,
	flag_reserved = 128,
};

static inline size_t output_char(int f,unsigned char *out,unsigned char in) {
	if (!f) return 0;
	if (NULL != out) *out = in;
	return 1;
}

static inline size_t output_short(int f,unsigned char *out,unsigned short in) {
	if (!f) return 0;
	if (NULL != out) {
		out[0] = in >> 8;
		out[1] = in & 0xFF;
	}
	return 2;
}

static inline size_t output_long(int f,unsigned char *out,unsigned long in) {
	if (!f) return 0;
	if (NULL != out) {
		out[0] =  in >> 24;
		out[1] = (in >> 16) & 0xFF;
		out[2] = (in >>  8) & 0xFF;
		out[3] =  in        & 0xFF;
	}
	return 4;
}

static size_t output_sequence(unsigned char *out,
	const unsigned char *begin,
	const unsigned char *end) 
{
	size_t length;
	if (begin == end) return 0;
	AIRHOOK_ASSERT(end - begin <= 0x100);

	length = 1 + end - begin;
	if (NULL != out) {
		*out++ = end - begin - 1;
		while (end != begin) *out++ = *begin++;
	}

	return length;
}

size_t packet_length(const struct packet *in) {
	const struct message *m;
	size_t length =
		  output_char(1,NULL,0)
		+ output_char(1,NULL,0)
		+ output_short(1,NULL,0)
		+ output_long(in->session_observed,NULL,0)
		+ output_long(in->session,NULL,0)
		+ output_char(in->interval,NULL,0)
		+ output_char(in->unsent,NULL,0)
		+ output_sequence(NULL,in->missed_begin,in->missed_end);
	for (m = in->data; m != in->data_end; ++m)
		length += output_sequence(NULL,m->begin,m->end);
	return length;
}

void output_packet(unsigned char *out,const struct packet *in) {
	unsigned char f;
	const struct message *m;

	f = 0;
	if (in->interval) f |= flag_interval;
	if (in->session) f |= flag_session;
	if (in->session_observed) f |= flag_session_observed;
	if (in->unsent) f |= flag_sent;
	if (in->missed_begin != in->missed_end) f |= flag_missed;

	out += output_char(1,out,f);
	out += output_char(1,out,in->sequence_observed);
	out += output_short(1,out,in->sequence);
	out += output_long(in->session_observed,out,in->session_observed);
	out += output_long(in->session,out,in->session);
	out += output_char(in->interval,out,in->interval);
	out += output_char(in->unsent,out,in->unsent);
	out += output_sequence(out,in->missed_begin,in->missed_end);

	for (m = in->data; m != in->data_end; ++m) {
		AIRHOOK_ASSERT(m->begin != m->end); /* BUG */
		out += output_sequence(out,m->begin,m->end);
	}
}

static inline int input_char(int flag,
	unsigned char *out,
	const unsigned char **in,const unsigned char *end)
{
	if (!flag) *out = 0;
	else if (end == *in) return 0;
	else *out = *(*in)++;
	return 1;
}

static inline int input_short(int flag,
	unsigned short *out,
	const unsigned char **in,const unsigned char *end)
{
	if (!flag) *out = 0;
	else if (*in + 2 > end) return 0;
	else {
		*out = ((*in)[0] << 8) | (*in)[1];
		*in += 2;
	}
	return 1;
}

static inline int input_long(int flag,
	unsigned long *out,
	const unsigned char **in,const unsigned char *end)
{
	if (!flag) *out = 0;
	else if (*in + 4 > end) return 0;
	else {
		*out = ((*in)[0] << 24)
		     | ((*in)[1] << 16)
		     | ((*in)[2] <<  8)
		     |  (*in)[3];
		*in += 4;
	}
	return 1;
}

static int input_sequence(int flag,
	const unsigned char **out_begin,const unsigned char **out_end,
	const unsigned char **in,const unsigned char *end) 
{
	if (!flag) {
		*out_begin = NULL;
		*out_end = NULL;
	} else {
		if (end == *in) return 0;
		*out_begin = *in + 1;
		*out_end = **in + 1 + *out_begin;
		if (*out_end > end) return 0;
		*in = *out_end;
	}

	return 1;
}

int input_packet(struct packet *out,
	const unsigned char *begin,
	const unsigned char *end) 
{
	unsigned char f;
	if (!input_char(1,&f,&begin,end)
	||  !input_char(1,&out->sequence_observed,&begin,end)
	||  !input_short(1,&out->sequence,&begin,end)
	||  !input_long(f & flag_session_observed,&out->session_observed,&begin,end)
	||  !input_long(f & flag_session,&out->session,&begin,end)
	||  !input_char(f & flag_interval,&out->interval,&begin,end)
	||  !input_char(f & flag_sent,&out->unsent,&begin,end)
	||  !input_sequence(f & flag_missed,&out->missed_begin,&out->missed_end,&begin,end))
		return 0;

	out->data_end = out->data;
	while (end != begin) {
		if (out->data_end - out->data == 0x100) return 0;
		if (!input_sequence(1,
			&out->data_end->begin,
			&out->data_end->end,&begin,end))
			return 0;
		++(out->data_end);
	}

	return 1;
}
