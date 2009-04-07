/* Airhook protocol library, copyright 2001 Dan Egnor.
 * This software comes with ABSOLUTELY NO WARRANTY.  You may redistribute it
 * under the terms of the GNU General Public License, version 2.
 * See the file COPYING for more details. */

#include "airhook.h"
#include "airhook-private.h"

#include <limits.h>

static const struct airhook_time zero_time = { 0, 0 };
static const struct airhook_time forever = { ULONG_MAX, 0 };

enum { ah_session_init, ah_session_sent, ah_session_confirmed };

static inline unsigned char octet(unsigned char c) { 
	return (airhook_size - 1) & c; 
}

static inline unsigned short word(unsigned short s) { 
	return (airhook_size * airhook_size - 1) & s; 
}

static void changed_insert(struct airhook_outgoing *out,struct airhook_time t) {
	out->status.last_change = t;
	if (NULL != out->next_changed) return;
	if (NULL == out->socket->last_changed)
		out->next_changed = out;
	else {
		out->next_changed = out->socket->last_changed->next_changed;
		out->socket->last_changed->next_changed = out;
	}
	out->socket->last_changed = out;
}

static void changed_remove(struct airhook_outgoing *out) {
	struct airhook_outgoing *prev = out->socket->last_changed;
	if (NULL == out->next_changed) return;
	while (prev->next_changed != out) {
		prev = prev->next_changed;
		AIRHOOK_ASSERT(prev != out->socket->last_changed);
	}

	if (prev == out)
		prev = NULL;
	else
		prev->next_changed = out->next_changed;

	out->next_changed = NULL;
	if (out->socket->last_changed == out)
		out->socket->last_changed = prev;
}

static void queue_remove(struct airhook_outgoing *out) {
	AIRHOOK_ASSERT(out != out->socket->first_pending);
	AIRHOOK_ASSERT((out->next == NULL) 
	            == (out->socket->last_outgoing == out));
	if (NULL == out->next)
		out->socket->last_outgoing = out->prev;
	if (NULL != out->prev) out->prev->next = out->next;
	if (NULL != out->next) out->next->prev = out->prev;
	out->socket->status.wanted += out->status.data.end - out->status.data.begin;
}

static void from_waiting(struct airhook_outgoing *out) {
	AIRHOOK_ASSERT(ah_sent == out->status.state);
	AIRHOOK_ASSERT(out->socket->waiting[out->number] == out);
	out->socket->waiting[out->number] = NULL;
}

static void to_waiting(struct airhook_outgoing *out,struct airhook_time t) {
	AIRHOOK_ASSERT(out->socket->waiting[out->number] == NULL);
	out->socket->waiting[out->number] = out;
	out->status.state = ah_sent;
	changed_insert(out,t);
}

static void from_pending(struct airhook_outgoing *out) {
	if (out->socket->first_pending == out) {
		struct airhook_socket * const socket = out->socket;
		do socket->first_pending = socket->first_pending->next;
		while (NULL != socket->first_pending 
		   &&  ah_pending != socket->first_pending->status.state);
	}
}

static void to_pending(struct airhook_outgoing *out,struct airhook_time t) {
	struct airhook_outgoing *next = out->next;
	out->status.state = ah_pending;
	while (NULL != next && ah_pending != next->status.state)
		next = next->next;
	if (out->socket->first_pending == next)
		out->socket->first_pending = out;
	changed_insert(out,t);
}

static void to_confirmed(struct airhook_outgoing *out,struct airhook_time t) {
	queue_remove(out);
	out->status.state = ah_confirmed;
	changed_insert(out,t);
}

static void to_discarded(struct airhook_outgoing *out) {
	if (ah_confirmed != out->status.state) queue_remove(out);
	out->status.state = ah_discarded;
	changed_remove(out);
}

void airhook_init(struct airhook_socket *conn,unsigned long session) {
	unsigned char i = 0;
	airhook_magic_init(&conn->magic,"SOCK");

	/* Default settings. */
	conn->status.settings.retransmit.second = 1;
	conn->status.settings.retransmit.nanosecond = 0;
	conn->status.settings.window_size = 32768;

	conn->status.session = session;
	conn->status.remote_session = 0;
	conn->status.state = ah_pending;
	conn->status.remote_state = ah_pending;
	conn->status.wanted = conn->status.settings.window_size;
	conn->status.last_transmit = zero_time;
	conn->status.next_transmit = zero_time;
	conn->status.last_response = zero_time;

	conn->sequence = 1;
	conn->sequence_observed = 0;
	conn->sequence_confirmed = 0;
	conn->last_observed = 0;

	conn->missed_end = conn->missed;
	conn->incoming_end = conn->incoming_next = conn->incoming;
	conn->last_changed = NULL;
	conn->last_outgoing = conn->first_pending = NULL;

	conn->current.unsent = 0;
	conn->current.unseen = 0;
	conn->current.transmit = zero_time;
	do {
		conn->log[i] = conn->current;
		conn->waiting[i] = NULL;
	} while ((i = octet(i + 1)) != 0);
}

void airhook_settings(struct airhook_socket *conn,struct airhook_settings set) {
	airhook_magic_check(&conn->magic,"SOCK");
	conn->status.wanted += set.window_size - conn->status.settings.window_size;
	conn->status.settings = set;
}

static inline int is_prior(unsigned short a,unsigned short b) {
	const unsigned short w = word(a - b);
	return w != octet(w);
}

static inline int is_between(unsigned char a,unsigned char b,unsigned char c) {
	return octet(octet(b) - octet(a)) < octet(octet(c) - octet(a));
}

static struct airhook_outgoing *first_pending(const struct airhook_socket *conn) {
	if (octet(conn->current.unsent + 1) 
	==  conn->log[conn->sequence_confirmed].unsent)
		return NULL;
	return conn->first_pending;
}

static inline int is_before(struct airhook_time a,struct airhook_time b) {
	if (a.second < b.second) return 1;
	if (a.second > b.second) return 0;
	return (a.nanosecond < b.nanosecond);
}

static struct airhook_time add_time(
	struct airhook_time a,
	struct airhook_time b) 
{
	struct airhook_time r;
	r.second = a.second + b.second;
	r.nanosecond = a.nanosecond + b.nanosecond;
	if (r.nanosecond > 1000000000) {
		r.nanosecond -= 1000000000;
		++r.second;
	}

	return r;
}

static int novel(const struct airhook_socket *conn) {
	return
	    conn->sequence_confirmed != octet(conn->sequence + 1)
	&& (octet(conn->sequence_observed) != conn->last_observed
	|| (conn->sequence_confirmed != octet(conn->sequence + 2)
	&& (conn->log[octet(conn->sequence)].unseen != conn->current.unseen
	||  NULL != first_pending(conn))));
}

struct airhook_status airhook_status(const struct airhook_socket *conn) {
	struct airhook_status status = conn->status;
	const struct airhook_record 
		* const last = &conn->log[octet(conn->sequence)],
		* const confirmed = &conn->log[conn->sequence_confirmed];

	airhook_magic_check(&conn->magic,"SOCK");

	if (novel(conn)
	&& (last->unseen != conn->current.unseen
	||  NULL != first_pending(conn)))
		status.next_transmit = zero_time;
	else
	if (ah_confirmed != status.state
	||  conn->current.unsent != confirmed->unsent
	||  conn->missed_end != conn->missed) {
		struct airhook_time retry = add_time(
			status.last_transmit,
			status.settings.retransmit);
		if (is_before(retry,status.next_transmit))
			status.next_transmit = retry;
	}

	return status;
}

size_t airhook_transmit(
	struct airhook_socket *conn,
	struct airhook_time now,
	size_t length,unsigned char *data)
{
	struct packet packet;
	size_t actual_length;
	struct airhook_record 
		* const last = &conn->log[octet(conn->sequence)],
		* const confirmed = &conn->log[conn->sequence_confirmed];
	struct airhook_outgoing *pending;
	airhook_magic_check(&conn->magic,"SOCK");

	pending = first_pending(conn);
	packet.sequence = word(conn->sequence + 1);
	packet.sequence_observed = octet(conn->sequence_observed);

	if (ah_confirmed != conn->status.remote_state) {
		packet.session = conn->status.session;
		packet.session_observed = conn->status.remote_session;
	} else {
		packet.session = 0;
		packet.session_observed = 0;
	}

	if (!novel(conn)) {
		/* We have nothing new to say; just resend the last header. */
		packet.sequence = conn->sequence;
		packet.sequence_observed = conn->last_observed;
		packet.interval = 0;
		packet.unsent = last->unsent;

		/* Missed entries in [last->unseen,current.unseen) are new. */
		packet.missed_begin = conn->missed;
		packet.missed_end = conn->missed_end;
		while (packet.missed_end != packet.missed_begin 
			&& is_between(last->unseen,
				packet.missed_end[-1],
				conn->current.unseen))
			--packet.missed_end;

		packet.data_end = packet.data;
		actual_length = packet_length(&packet);
		if (actual_length <= length) {
			output_packet(data,&packet);
			conn->status.last_transmit = now;
			conn->status.next_transmit = forever;
		}
		return actual_length;
	}

	packet.interval = 0; /* TODO */
	packet.missed_begin = conn->missed;
	packet.missed_end = conn->missed_end;
	packet.unsent = conn->current.unsent;
	packet.data_end = packet.data;

	if (NULL == pending) {
		actual_length = packet_length(&packet);
		if (actual_length > length) return actual_length;
	} else do {
		size_t new_length;
		packet.data_end->begin = pending->status.data.begin;
		packet.data_end->end = pending->status.data.end;
		++packet.data_end;

		new_length = packet_length(&packet);
		if (new_length > length) {
			if (packet.data_end - packet.data == 1)
				return new_length;
			--packet.data_end;
			break;
		}

		actual_length = new_length;
		pending->number = conn->current.unsent;
		conn->current.unsent = octet(conn->current.unsent + 1);
		AIRHOOK_ASSERT(conn->current.unsent != confirmed->unsent);

		++(pending->status.transmit_count);
		from_pending(pending);
		to_waiting(pending,now);
		pending = first_pending(conn);
	} while (NULL != pending);

	AIRHOOK_ASSERT(actual_length <= length);
	output_packet(data,&packet);

	conn->status.last_transmit = now;
	conn->status.next_transmit = forever;
	conn->sequence = packet.sequence;
	conn->last_observed = packet.sequence_observed;

	if (ah_pending == conn->status.remote_state
	&&  packet.session && packet.session_observed) {
		conn->push_sequence = packet.sequence;
		conn->status.remote_state = ah_sent;
	}

	conn->current.transmit = now;
	conn->log[octet(packet.sequence)] = conn->current;
	return actual_length;
}

int airhook_receive(struct airhook_socket *conn,
	struct airhook_time now,
	struct airhook_data data)
{
	struct packet packet;
	struct message *message;
	struct airhook_record *confirmed,*old_confirmed;
	const unsigned char *missed;
	airhook_magic_check(&conn->magic,"SOCK");

	conn->incoming_end = conn->incoming_next = &conn->incoming[0];
	if (!input_packet(&packet,data.begin,data.end))
                return 0;

	AIRHOOK_ASSERT((conn->status.state == ah_pending) 
	            == (conn->status.remote_session == 0));

	old_confirmed = &conn->log[conn->sequence_confirmed];

	/* If the remote session changes, resynchronize. */
	if (packet.session != 0
	&&  packet.session != conn->status.remote_session) {
		conn->missed_end = conn->missed;
		conn->current.unseen = 0;

		/* TODO -- this is not good */
		if (ah_confirmed == conn->status.state) {
			unsigned char sent = old_confirmed->unsent;
			while (sent != conn->current.unsent) {
				struct airhook_outgoing * const out = 
					conn->waiting[sent];
				if (NULL != out) {
					from_waiting(out);
					to_pending(out,now);
				}
				sent = octet(sent + 1);
			}

			conn->current.unsent = 0;
			conn->sequence_confirmed = octet(conn->sequence);
			old_confirmed = &conn->log[conn->sequence_confirmed];
		}

		conn->last_observed = octet(packet.sequence - 1);
		conn->status.state = ah_sent;
		conn->status.remote_state = ah_pending;
		conn->status.remote_session = packet.session;
	} 
	else if (conn->status.state == ah_pending) 
		return 0; /* Unknown session */
	else if (!is_prior(conn->sequence_observed,packet.sequence)) {
		if (conn->sequence_observed != packet.sequence) return 1;
		packet.unsent = octet(packet.unsent 
		                   + (packet.data_end - packet.data));
		packet.data_end = packet.data;
	}

	if (packet.session_observed != 0) {
		/* Ignore messages to a different session. */
		if (packet.session_observed != conn->status.session) 
			return 0;
		/* Otherwise -- golly, they're talking to us. */
		conn->status.state = ah_confirmed;
	}

	if (ah_confirmed == conn->status.state) {
		if (is_between(
			conn->sequence + 1,
			packet.sequence_observed,
			conn->sequence_confirmed)) /* Inverse! */
			return 0;

		if (ah_sent == conn->status.remote_state
		&&  is_between(
			conn->sequence_confirmed + 1,
			conn->push_sequence,
			packet.sequence_observed + 1))
			conn->status.remote_state = ah_confirmed;

		conn->sequence_confirmed = packet.sequence_observed;
	}

	confirmed = &conn->log[conn->sequence_confirmed];
	conn->status.last_response = confirmed->transmit;
	conn->sequence_observed = packet.sequence;

	/* Cull confirmed entries from missed */
	if (confirmed->unseen != old_confirmed->unseen) {
		unsigned char *p = conn->missed,*q = conn->missed;
		while (p != conn->missed_end 
		   &&  is_between(old_confirmed->unseen,*p,confirmed->unseen))
			++p;
		while (p != conn->missed_end)
			*q++ = *p++;
		conn->missed_end = q;
	}

	/* Discover any messages we missed. */
	while (packet.unsent != conn->current.unseen) {
		AIRHOOK_ASSERT(conn->missed_end < conn->missed + airhook_size);
		*conn->missed_end++ = conn->current.unseen;
		conn->current.unseen = octet(conn->current.unseen + 1);
	}

	/* Retransmit any messages they missed. */
	missed = packet.missed_end;
	while (missed != packet.missed_begin) {
		const unsigned char m = octet(*--missed);
		struct airhook_outgoing * const out = conn->waiting[m];
		if (!is_between(old_confirmed->unsent, m, confirmed->unsent))
			break;
		if (NULL != out) {
			from_waiting(out);
			to_pending(out,now);
		}
	}

	/* Confirm the messages they saw. */
	{
		unsigned char sent;
		for (sent = old_confirmed->unsent
		  ;  sent != confirmed->unsent
		  ;  sent = octet(1 + sent)) {
			struct airhook_outgoing *out = conn->waiting[sent];
			if (NULL != out) {
				from_waiting(out);
				to_confirmed(out,now);
			}
		}
	}

	/* Record the messages they sent. */
	for (message = packet.data; message != packet.data_end; ++message) {
		conn->current.unseen = octet(conn->current.unseen + 1);
		AIRHOOK_ASSERT(conn->incoming_end < conn->incoming + airhook_size);
		conn->incoming_end->begin = message->begin;
		conn->incoming_end->end = message->end;
		++(conn->incoming_end);
	}

	/* Trigger a response if necessary. */
	if (ah_confirmed != conn->status.remote_state)
		conn->status.next_transmit = zero_time;
	else 
	if (confirmed->unseen != conn->current.unseen
	||  packet.missed_begin != packet.missed_end) {
		struct airhook_time retry = add_time(
			conn->status.last_transmit,
			conn->status.settings.retransmit);
		if (is_before(retry,conn->status.next_transmit))
			conn->status.next_transmit = retry;
	}

	return 1;
}

int airhook_next_incoming(struct airhook_socket *conn,struct airhook_data *d) {
	airhook_magic_check(&conn->magic,"SOCK");
	if (conn->incoming_end == conn->incoming_next) return 0;
	*d = *conn->incoming_next++;
	return 1;
}

void airhook_init_outgoing(struct airhook_outgoing *out,
	struct airhook_socket *conn,
	struct airhook_data data,void *user)
{
	airhook_magic_check(&conn->magic,"SOCK");
	airhook_magic_init(&out->magic,"OUTG");
	out->socket = conn;
	out->status.data = data;
	out->status.user = user;
	out->status.transmit_count = 0;
	out->status.last_change = zero_time;
	out->next_changed = NULL;
	out->next = NULL;
	out->prev = conn->last_outgoing;
	if (NULL != out->prev) out->prev->next = out;
	conn->last_outgoing = out;
	conn->status.wanted -= out->status.data.end - out->status.data.begin;
	to_pending(out,zero_time);
}

void airhook_discard_outgoing(struct airhook_outgoing *out) {
	airhook_magic_check(&out->magic,"OUTG");
	airhook_magic_check(&out->socket->magic,"SOCK");
	switch (out->status.state) {
	case ah_pending: from_pending(out); to_discarded(out); break;
	case ah_sent: from_waiting(out); to_discarded(out); break;
	case ah_confirmed: to_discarded(out); break;
	case ah_discarded: break;
	default: AIRHOOK_ASSERT(0);
	}
}

struct airhook_outgoing_status airhook_outgoing_status(
	const struct airhook_outgoing *out) 
{
	airhook_magic_check(&out->magic,"OUTG");
	airhook_magic_check(&out->socket->magic,"SOCK");
	return out->status;
}

int airhook_next_changed(struct airhook_socket *conn,
	struct airhook_outgoing **out) 
{
	airhook_magic_check(&conn->magic,"SOCK");
	if (NULL == conn->last_changed) return 0;

	*out = conn->last_changed->next_changed;
	airhook_magic_check(&(*out)->magic,"OUTG");
	AIRHOOK_ASSERT((*out)->socket == conn);
	changed_remove(*out);
	return 1;
}
