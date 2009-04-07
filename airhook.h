/* Airhook protocol library, copyright 2001 Dan Egnor.
 * This software comes with ABSOLUTELY NO WARRANTY.  You may redistribute it
 * under the terms of the GNU General Public License, version 2.
 * See the file COPYING for more details. */

#ifndef AIRHOOK_H
#define AIRHOOK_H

#include <stddef.h>

#ifndef AIRHOOK_DEBUG
#  ifdef NDEBUG
#    define AIRHOOK_DEBUG 0
#  else
#    define AIRHOOK_DEBUG 1
#  endif
#endif

struct airhook_time {
	unsigned long second;
	unsigned long nanosecond;
};

struct airhook_data {
	const unsigned char *begin;
	const unsigned char *end;
};

enum airhook_state { ah_pending, ah_sent, ah_confirmed, ah_discarded };

struct airhook_settings {
	struct airhook_time retransmit;
	unsigned long window_size;
};

struct airhook_status {
	struct airhook_settings settings;
	unsigned long session,remote_session;
	enum airhook_state state,remote_state;
	signed long wanted;
	struct airhook_time last_transmit;
	struct airhook_time next_transmit;
	struct airhook_time last_response;
};

struct airhook_outgoing_status {
	struct airhook_data data;
	void *user;
	enum airhook_state state;
	unsigned long transmit_count;
	struct airhook_time last_change;
};

enum { airhook_bits = 8 };
enum { airhook_size = 1 << airhook_bits };
enum { airhook_message_size = airhook_size - 1 };

struct airhook_socket;
struct airhook_outgoing;

#include "airhook-internal.h"

void airhook_init(struct airhook_socket *,unsigned long session);
void airhook_settings(struct airhook_socket *,struct airhook_settings);
struct airhook_status airhook_status(const struct airhook_socket *);

/* -- top half -------------------------------------------------------------- */

int airhook_next_incoming(struct airhook_socket *,struct airhook_data *);
int airhook_next_changed(struct airhook_socket *,struct airhook_outgoing **);

void airhook_init_outgoing(struct airhook_outgoing *,
	struct airhook_socket *,
	struct airhook_data,void *user);
void airhook_discard_outgoing(struct airhook_outgoing *);
struct airhook_outgoing_status airhook_outgoing_status(
	const struct airhook_outgoing *);

/* -- bottom half ----------------------------------------------------------- */

size_t airhook_transmit(
	struct airhook_socket *,
	struct airhook_time now,
	size_t length,unsigned char *data);

int airhook_receive(struct airhook_socket *,
	struct airhook_time now,
	struct airhook_data data);

#endif
