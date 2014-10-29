#include "ecode_names.h"
#include "hex.h"
#include "jsonrpc.h"
#include "peer.h"
#include "pkt_names.h"
#include "state.h"
#include <ccan/io/io.h>
#include <poll.h>

/*    {
        "addr" : "54.69.232.231:8968",
        "addrlocal" : "128.199.137.156:18333",
        "services" : "00000001",
        "lastsend" : 1413765750,
        "lastrecv" : 1413764032,
        "bytessent" : 398206,
        "bytesrecv" : 485,
        "conntime" : 1413763882,
        "pingtime" : 0.00000000,
        "version" : 70002,
        "subver" : "/Satoshi:0.9.2/",
        "inbound" : true,
        "startingheight" : 324500,
        "banscore" : 0,
        "syncnode" : false
    }
*/

static char *json_getpeerinfo(struct json_connection *jcon,
			      const jsmntok_t *params,
			      struct json_result *response)
{
	struct peer *peer;
	struct state *state = jcon->state;

	json_array_start(response, NULL);
	list_for_each(&state->peers, peer, list) {
		const struct protocol_net_hdr *pkt;
		struct pollfd fds;

		assert(peer->state == state);
		json_object_start(response, NULL);
		json_add_num(response, "peer_num", peer->peer_num);
		assert(bitmap_test_bit(state->peer_map, peer->peer_num));

		json_add_string(response, "uuid",
				to_hex(response, &peer->welcome->uuid,
				       sizeof(peer->welcome->uuid)));

		json_add_bool(response, "we_are_syncing", peer->we_are_syncing);
		json_add_bool(response, "they_are_syncing", peer->they_are_syncing);

		/* These should be the same. */
		json_add_num(response, "fd", peer->fd);
		json_add_num(response, "conn_fd", io_conn_fd(peer->conn));

		json_add_string(response, "error",
				peer->error_pkt ?
				ecode_name(le32_to_cpu(peer->error_pkt->error)) :
				ecode_name(PROTOCOL_ECODE_NONE));

		json_add_num(response, "last-input-time",
			     peer->last_time_in.ts.tv_sec);
		json_add_string(response, "last-input-type",
				pkt_name(peer->last_type_in));
		json_add_num(response, "last-input-length", peer->last_len_in);

		/* Examining incoming is unreliable! */
		pkt = peer->incoming;
		json_add_bool(response, "input-pending", peer->in_pending);
		json_add_num(response, "incoming-len",
			     pkt ? le32_to_cpu(pkt->len) : -1);
		json_add_string(response, "incoming-type",
				pkt ? pkt_name(le32_to_cpu(pkt->type)) : "NONE");

		json_add_num(response, "last-output-time",
			     peer->last_time_out.ts.tv_sec);
		json_add_string(response, "last-output-type",
				pkt_name(peer->last_type_out));
		json_add_num(response, "last-output-length", peer->last_len_out);
		json_add_bool(response, "output-pending", peer->out_pending);

		pkt = peer->outgoing;
		json_add_num(response, "outgoing-len",
			     pkt ? le32_to_cpu(pkt->len) : -1);
		json_add_string(response, "outgoing-type",
				pkt ? pkt_name(le32_to_cpu(pkt->type)) : "NONE");

		fds.fd = peer->fd;
		fds.events = POLLIN|POLLOUT;

		poll(&fds, 1, 0);
		json_add_bool(response, "fd-ok", !(fds.revents & POLLNVAL));
		json_add_bool(response, "fd-readable", fds.revents & POLLIN);
		json_add_bool(response, "fd-writable", fds.revents & POLLOUT);

		json_object_end(response);
	}
	json_array_end(response);

	return NULL;
}

const struct json_command getpeerinfo_command = {
	"getpeerinfo", json_getpeerinfo,
	"Get information about our peers",
	""
};
