/* Airhook packet dissector module for Ethereal, copyright 2002 Dan Egnor.
 * This software comes with ABSOLUTELY NO WARRANTY.  You may redistribute it
 * under the terms of the GNU General Public License, version 2.
 * See the file COPYING for more details. */

#include <gmodule.h>
#include <sys/time.h>

#define HAVE_STDARG_H

#include "plugins/plugin_api.h"
#include "epan/packet.h"
#include "airhook.h"
#include "airhook-private.h"

G_MODULE_EXPORT 
const gchar version[] = "1";

static int proto_airhook = -1;

static int ett_airhook = -1;
static int ett_airhook_header = -1;
static int ett_airhook_flags = -1;
static int ett_airhook_missed = -1;
static int ett_airhook_message = -1;

static int hf_airhook_flags = -1;
static int hf_airhook_flags_observed_session = -1;
static int hf_airhook_flags_session = -1;
static int hf_airhook_flags_missed = -1;
static int hf_airhook_flags_unsent = -1;
static int hf_airhook_flags_interval = -1;
static int hf_airhook_observed_sequence = -1;
static int hf_airhook_sequence = -1;
static int hf_airhook_observed_session = -1;
static int hf_airhook_session = -1;
static int hf_airhook_interval = -1;
static int hf_airhook_unsent = -1;
static int hf_airhook_missed_count = -1;
static int hf_airhook_missed_id = -1;
static int hf_airhook_message_id = -1;
static int hf_airhook_message_length = -1;

static dissector_table_t airhook_dissector_table;
static heur_dissector_list_t heur_dissector_list;
static dissector_handle_t data_handle;

static 
gboolean dissect_airhook(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
	const guint8 * const begin = tvb_get_ptr(tvb, 0, tvb_length(tvb));
	const guint8 * const end = begin + tvb_length(tvb);
	const guint8 flags = tvb_get_guint8(tvb, 0);
	proto_tree *subtree = NULL, *header = NULL, *flagtree = NULL;
	proto_item *header_item = NULL;
	struct packet packet;
	gint offset = 4;

	if (flags & 0xE0) return FALSE;
	if (!input_packet(&packet, begin, end)) return FALSE;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "Airhook");
	if (check_col(pinfo->cinfo, COL_INFO)) {
		if (pinfo->srcport < pinfo->destport
		||  pinfo->srcport == pinfo->destport
		&&  CMP_ADDRESS(&pinfo->src, &pinfo->dst) < 0) {
			col_add_fstr(pinfo->cinfo, COL_INFO,
				"%s -> %s: seq=%04X obseq=%02X",
				get_udp_port(pinfo->srcport),
				get_udp_port(pinfo->destport),
				packet.sequence, packet.sequence_observed);
			if (packet.session)
				col_append_fstr(pinfo->cinfo, COL_INFO,
					" sess=%08X", packet.session);
			if (packet.session_observed)
				col_append_fstr(pinfo->cinfo, COL_INFO,
					" obss=%08X", packet.session_observed);
		}
		else {
			col_add_fstr(pinfo->cinfo, COL_INFO,
				"%s <- %s: obseq=%02X seq=%04X",
				get_udp_port(pinfo->destport),
				get_udp_port(pinfo->srcport),
				packet.sequence_observed, packet.sequence);
			if (packet.session_observed)
				col_append_fstr(pinfo->cinfo, COL_INFO,
					" obss=%08X", packet.session_observed);
			if (packet.session)
				col_append_fstr(pinfo->cinfo, COL_INFO,
					" sess=%08X", packet.session);
		}

		if (packet.missed_end != packet.missed_begin)
			col_append_fstr(pinfo->cinfo, COL_INFO, " missed=%d", 
				packet.missed_end - packet.missed_begin);
	}

	if (tree) {
		subtree = proto_item_add_subtree(
			proto_tree_add_item(tree, proto_airhook, 
			                    tvb, 0, -1, FALSE), ett_airhook);
		header_item = proto_tree_add_text(subtree, tvb, 0, -1, "Header");
		header = proto_item_add_subtree(header_item, ett_airhook_header);
		flagtree = proto_item_add_subtree(proto_tree_add_item(
			header, hf_airhook_flags,
			tvb, 0, 1, FALSE), ett_airhook_flags);

		proto_tree_add_item(
			flagtree, hf_airhook_flags_observed_session,
			tvb, 0, 1, FALSE);
		proto_tree_add_item(
			flagtree, hf_airhook_flags_session,
			tvb, 0, 1, FALSE);
		proto_tree_add_item(
			flagtree, hf_airhook_flags_missed,
			tvb, 0, 1, FALSE);
		proto_tree_add_item(
			flagtree, hf_airhook_flags_unsent,
			tvb, 0, 1, FALSE);
		proto_tree_add_item(
			flagtree, hf_airhook_flags_interval,
			tvb, 0, 1, FALSE);

		proto_tree_add_item(header, hf_airhook_sequence, 
		                    tvb, 2, 2, FALSE);
		proto_tree_add_item(header, hf_airhook_observed_sequence, 
		                    tvb, 1, 1, FALSE);

		if (flags & 0x08) offset += 4;
		if (flags & 0x10)
			proto_tree_add_item(
				header, hf_airhook_session, 
				tvb, offset, 4, FALSE);
		if (flags & 0x10) offset += 4;
		if (flags & 0x08)
			proto_tree_add_item(
				header, hf_airhook_observed_session,
				tvb, offset - 4, 4, FALSE);

		if (flags & 0x01)
			proto_tree_add_item(
				header, hf_airhook_interval,
				tvb, offset++, 1, FALSE);
		if (flags & 0x02)
			proto_tree_add_item(
				header, hf_airhook_unsent,
				tvb, offset++, 1, FALSE);

		if (flags & 0x04) {
			const int len = packet.missed_end - packet.missed_begin;
			proto_tree * const missed = proto_item_add_subtree(
				proto_tree_add_uint_format(
					header, hf_airhook_missed_count,
				        tvb, offset++, 1 + len,
					len, "%d message%s missed",
					len, len > 1 ? "s" : ""), 
				ett_airhook_missed);
			while (packet.missed_begin != packet.missed_end) {
				proto_tree_add_item(
					missed, hf_airhook_missed_id,
					tvb, offset++, 1, FALSE);
				++packet.missed_begin;
			}
		}

		proto_item_set_len(header_item, offset);
	}
	else {
		if (flags & 0x10) offset += 4;
		if (flags & 0x08) offset += 4;
		if (flags & 0x04) offset += 
			1 + (packet.missed_end - packet.missed_begin);
		if (flags & 0x02) ++offset;
		if (flags & 0x01) ++offset;
	}

	if (packet.data != packet.data_end) {
		const int num = packet.data_end - packet.data;
		const struct message *msg;
		int id = packet.unsent;
		for (msg = packet.data; msg != packet.data_end; ++msg) {
			const int len = msg->end - msg->begin;
			proto_tree *message = NULL;
			tvbuff_t * const next_tvb =
				tvb_new_subset(tvb, offset+1, len, len);
			const int low_port = 
				MIN(pinfo->srcport, pinfo->destport);
			const int high_port =
				MAX(pinfo->srcport, pinfo->destport);

			if (subtree) {
				proto_item * const ti = 
					proto_tree_add_uint(
						subtree, hf_airhook_message_id,
						tvb, offset, len + 1, id++);
				proto_item_append_text(ti, " (%d bytes)", len);
				proto_tree_add_uint_hidden(
					message, hf_airhook_message_length,
					tvb, offset, 1, len);

				message = proto_item_add_subtree(
					ti, ett_airhook_message);
			}

			offset += len + 1;

			if (low_port && dissector_try_port(
				airhook_dissector_table, low_port,
				next_tvb, pinfo, message)) continue;
			if (high_port && dissector_try_port(
				airhook_dissector_table, high_port,
				next_tvb, pinfo, message)) continue;
			if (dissector_try_heuristic(
				heur_dissector_list, 
				next_tvb, pinfo, message)) continue;

			if (check_col(pinfo->cinfo, COL_INFO))
				col_append_fstr(pinfo->cinfo, COL_INFO,
					" (%d bytes)", len);
			
			call_dissector(data_handle, 
				next_tvb, pinfo, message);
		}
	}

	return TRUE;
}

G_MODULE_EXPORT 
void plugin_init(plugin_address_table_t *pat) {
	static int *ett[] = { 
	    &ett_airhook, 
	    &ett_airhook_flags, 
	    &ett_airhook_missed,
	    &ett_airhook_header,
	    &ett_airhook_message 
	};

	static const true_false_string tfs_sess = 
           { "Session identifier present",
             "Session identifier NOT present" };

	static const true_false_string tfs_obss = 
           { "Observed session identifier present",
             "Observed session identifier NOT present" };

	static const true_false_string tfs_missed = 
           { "List of missed message identifiers present",
             "List of missed message identifiers NOT present" };

	static const true_false_string tfs_unsent = 
           { "Next message identifier present",
             "Next message identifier NOT present" };

	static const true_false_string tfs_interval = 
           { "Interval delay present",
             "Interval delay NOT present" };

	static hf_register_info hf[] = {
	   { &hf_airhook_flags, 
		{ "Flags", "airhook.flags",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Flags indicating which packet components are present" }},
	   { &hf_airhook_flags_observed_session,
		{ "O", "airhook.flags.obss",
		  FT_BOOLEAN, 8, TFS(&tfs_obss), 0x10,
		  "Is the observed session identifier present?" }},
	   { &hf_airhook_flags_session,
		{ "S", "airhook.flags.sess",
		  FT_BOOLEAN, 8, TFS(&tfs_sess), 0x08,
		  "Is the session identifier present?" }},
	   { &hf_airhook_flags_missed,
		{ "M", "airhook.flags.missed",
		  FT_BOOLEAN, 8, TFS(&tfs_missed), 0x04,
		  "Are missed message identifiers present?" }},
	   { &hf_airhook_flags_unsent,
		{ "E", "airhook.flags.unsent",
		  FT_BOOLEAN, 8, TFS(&tfs_unsent), 0x02,
		  "Is the next message identifier present?" }},
	   { &hf_airhook_flags_interval,
		{ "I", "airhook.flags.missed",
		  FT_BOOLEAN, 8, TFS(&tfs_interval), 0x01,
		  "Is the interval delay present?" }},
	   { &hf_airhook_sequence, 
		{ "Sequence number", "airhook.seq",
		  FT_UINT16, BASE_HEX, NULL, 0x0,
		  "Sequence number of this packet" }},
	   { &hf_airhook_observed_sequence, 
		{ "Observed sequence number", "airhook.obseq",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Greatest observed packet sequence number" }},
	    { &hf_airhook_session, 
		{ "Session ID", "airhook.sess",
		  FT_UINT32, BASE_HEX, NULL, 0x0,
		  "Current endpoint session identifier" }},
	    { &hf_airhook_observed_session, 
		{ "Oberved session ID", "airhook.obss",
		  FT_UINT32, BASE_HEX, NULL, 0x0,
		  "Most recent observed session identifier" }},
	    { &hf_airhook_interval, 
		{ "Timing interval", "airhook.interval",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Delay interval for rate-based congestion control" }},
	    { &hf_airhook_unsent, 
		{ "Current message ID", "airhook.unsent",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Next message identifier that will be used" }},
	    { &hf_airhook_missed_count, 
		{ "Missed message count", "airhook.missed-count",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Number of missed message identifiers" }},
	    { &hf_airhook_missed_id, 
		{ "Missed message ID", "airhook.missed",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Identifier of message which was lost" }},
	    { &hf_airhook_message_id,
		{ "Payload message ID", "airhook.message",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Identifier of message included in packet" }},
	    { &hf_airhook_message_length, 
		{ "Length", "airhook.message.length",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Message length in octets" }},
	};

	if (proto_airhook != -1) return;
	proto_airhook = proto_register_protocol("Airhook","Airhook","airhook");
	proto_register_field_array(proto_airhook, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	airhook_dissector_table = register_dissector_table("airhook.port",
		"Airhook UDP port", FT_UINT16, BASE_DEC);
	register_heur_dissector_list("airhook", &heur_dissector_list);
}

G_MODULE_EXPORT 
void plugin_reg_handoff(void) {
	create_dissector_handle((dissector_t) dissect_airhook, proto_airhook);
	heur_dissector_add("udp", dissect_airhook, proto_airhook);
	data_handle = find_dissector("data");
}
