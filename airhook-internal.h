/* Airhook protocol library, copyright 2001 Dan Egnor.
 * This software comes with ABSOLUTELY NO WARRANTY.  You may redistribute it
 * under the terms of the GNU General Public License, version 2.
 * See the file COPYING for more details. */

#ifndef AIRHOOK_INTERNAL_H
#define AIRHOOK_INTERNAL_H

#if AIRHOOK_DEBUG
#  ifndef AIRHOOK_ASSERT
#    include <assert.h>
#    define AIRHOOK_ASSERT(t) assert(t)
#  endif
#else
#  define AIRHOOK_ASSERT(t)
#endif

typedef char airhook_type[4];
typedef union { void *pointer; char string[1]; } airhook_magic;

static inline void airhook_magic_init(airhook_magic *m,airhook_type t) {
#if AIRHOOK_DEBUG
	int i;
	m->pointer = m;
	for (i = 0; i < sizeof(t) && i < sizeof(*m); ++i) m->string[i] ^= t[i];
#endif
}

static inline void airhook_magic_check(const airhook_magic *m,airhook_type t) {
#if AIRHOOK_DEBUG
	int i;
	airhook_magic k = *m;
	for (i = 0; i < sizeof(k) && i < sizeof(t); ++i) k.string[i] ^= t[i];
	AIRHOOK_ASSERT(k.pointer == m);
#endif
}

struct airhook_record {
	struct airhook_time transmit;
	unsigned char unsent,unseen;
};

struct airhook_socket {
	airhook_magic magic;
	struct airhook_status status;

	/* synchronization */
	unsigned short sequence,sequence_observed;
	unsigned char sequence_confirmed,push_sequence;

	/* incoming messages */
	unsigned char missed[0x100],*missed_end;
	struct airhook_data incoming[0x100],*incoming_end,*incoming_next;

	/* outgoing messages */
	unsigned char last_observed;
	struct airhook_outgoing *waiting[0x100];
	struct airhook_outgoing *last_changed;
	struct airhook_outgoing *last_outgoing,*first_pending;

	struct airhook_record current,log[0x100];
};

struct airhook_outgoing {
	airhook_magic magic;
	struct airhook_socket *socket;
	struct airhook_outgoing_status status;
	struct airhook_outgoing *next_changed;
	struct airhook_outgoing *prev,*next;
	unsigned char number;
};

#endif
