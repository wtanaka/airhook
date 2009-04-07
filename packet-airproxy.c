/* Airhook proxy packet dissector module for Ethereal, copyright 2002 Dan Egnor.
 * This software comes with ABSOLUTELY NO WARRANTY.  You may redistribute it
 * under the terms of the GNU General Public License, version 2.
 * See the file COPYING for more details. */

#include <gmodule.h>
#include <stdlib.h>
#include <sys/time.h>

#define HAVE_STDARG_H

#include "plugins/plugin_api.h"
#include "epan/packet.h"
#include "airhook.h"
#include "airhook-private.h"

G_MODULE_EXPORT
const gchar version[] = "1";

static int proto_airproxy = -1;

static int ett_airproxy = -1;
static int ett_airproxy_flags = -1;

static int hf_airproxy_handle = -1;
static int hf_airproxy_flags = -1;
static int hf_airproxy_flags_output = -1;
static int hf_airproxy_flags_input = -1;
static int hf_airproxy_next = -1;
static int hf_airproxy_id = -1;

static dissector_handle_t data_handle;

enum { escape_value = airhook_size - 1 };

static
gboolean dissect_airproxy(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
	const gint16 handle = tvb_get_ntohs(tvb, 0);
	const guint8 id = tvb_get_guint8(tvb, 2);
	const char *dir;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "Airproxy");

	if (pinfo->srcport < pinfo->destport
	||  pinfo->srcport == pinfo->destport
	&&  CMP_ADDRESS(&pinfo->src, &pinfo->dst) < 0)
		dir = (handle < 0) ? "L" : "R";
	else
		dir = (handle < 0) ? "R" : "L";

	if (check_col(pinfo->cinfo, COL_INFO)) {
		if (escape_value == id) {
			const guint8 flags = tvb_get_guint8(tvb, 3);
			const guint8 next = tvb_get_guint8(tvb, 4);
			const char * const status =
				(flags == 1 ? "input closed, send me" :
				 flags == 2 ? "output closed, don't send" :
				 flags == 3 ? "fully closed, don't send" : 
				 "send me");
			if (handle < 0)
				col_append_fstr(pinfo->cinfo, COL_INFO,
					": [%d%s] %s %02X", 
					handle, dir, status, next);
			else
				col_append_fstr(pinfo->cinfo, COL_INFO,
					": %s %02X  [%d%s]", 
					status, next, handle, dir);
		}
		else {
			if (handle < 0)
				col_append_fstr(pinfo->cinfo, COL_INFO,
					": here is %02X [%d%s]", 
					id, handle, dir);
			else
				col_append_fstr(pinfo->cinfo, COL_INFO,
					":  [%d%s] here is %02X",
					handle, dir, id);
		}
	}

	if (tree) {
		proto_item * const item = proto_tree_add_item(
			tree, proto_airproxy, tvb, 0, -1, FALSE);
		proto_tree * const subtree = proto_item_add_subtree(
			item, ett_airproxy);

		proto_tree_add_item(
			subtree, hf_airproxy_handle, 
			tvb, 0, 2, FALSE);

		if (escape_value == id) {
			const guint8 flags = tvb_get_guint8(tvb, 3);
			const char * const status = 
				(flags == 0 ? "Normal" :
				 flags == 1 ? "Input closed" :
				 flags == 2 ? "Output closed" :
				 flags == 3 ? "Fully closed" : 
				 "Unknown/Invalid");
			proto_tree * const flagtree = proto_item_add_subtree(
				proto_tree_add_uint_format(
					subtree, hf_airproxy_flags,
					tvb, 3, 1, flags, 
					"Flags: 0x%02x (%s)", flags, status),
				ett_airproxy_flags);

			if (flags > 3) 
				return FALSE;

			proto_tree_add_item(
				flagtree, hf_airproxy_flags_output,
				tvb, 3, 1, FALSE);
			proto_tree_add_item(
				flagtree, hf_airproxy_flags_input,
				tvb, 3, 1, FALSE);
			proto_tree_add_item(
				subtree, hf_airproxy_next,
				tvb, 4, 1, FALSE);

			proto_item_append_text(item, 
				", Please Send: 0x%02x, Stream: %d%s", 
				tvb_get_guint8(tvb, 4), handle, dir);
			if (flags > 0)
				proto_item_append_text(item, ", %s", status);
		}
		else {
			tvbuff_t * const next_tvb = 
				tvb_new_subset(tvb, 3, -1, -1);
			proto_tree_add_item(
				subtree, hf_airproxy_id,
				tvb, 2, 1, FALSE);
			proto_item_append_text(item, 
				", Segment: 0x%02x, Stream: %d%s", 
				tvb_get_guint8(tvb, 2), handle, dir);
			proto_item_set_len(item, 3);
			call_dissector(data_handle, next_tvb, pinfo, tree);
		}
	}
}

G_MODULE_EXPORT
void plugin_init(plugin_address_table_t *pat) {
	static int *ett[] = {
		&ett_airproxy,
		&ett_airproxy_flags
	};

	static const true_false_string tfs_output =
	   { "CLOSED, do NOT send me data ever again on this stream",
	     "OPEN, you may send me data on this stream" };

	static const true_false_string tfs_input =
	   { "CLOSED, I will NEVER send you more data on this stream",
	     "OPEN, I may send you more data on this stream" };

	static hf_register_info hf[] = {
	   { &hf_airproxy_handle,
		{ "Stream Handle", "airproxy.handle",
		  FT_INT16, BASE_DEC, NULL, 0x0,
		  "Handle associating this packet with a proxy stream" }},
	   { &hf_airproxy_flags,
		{ "Flags", "airproxy.flags",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Flags indicating which stream endpoints have shut down" }},
	   { &hf_airproxy_flags_output,
		{ "Output", "airproxy.flags.output",
		  FT_BOOLEAN, 8, TFS(&tfs_output), 0x2,
		  "Has stream output been closed?" }},
	   { &hf_airproxy_flags_input,
		{ "Input", "airproxy.flags.input",
		  FT_BOOLEAN, 8, TFS(&tfs_input), 0x1,
		  "Has stream input been closed?" }},
	   { &hf_airproxy_next,
		{ "Please send segment ID", "airproxy.request",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Next incoming segment ID available for reuse" }},
	   { &hf_airproxy_id,
		{ "Segment ID", "airproxy.segment",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  "ID of this outgoing segment" }},
	};

	if (proto_airproxy != -1) return;
	proto_airproxy = proto_register_protocol(
		"Airhook TCP Proxy","Airproxy","airproxy");
	proto_register_field_array(proto_airproxy, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

G_MODULE_EXPORT
void plugin_reg_handoff(void) {
	data_handle = find_dissector("data");
	heur_dissector_add("airhook", dissect_airproxy, proto_airproxy);
}
