#include "packet.h"
#include "protocol_net.h"
#include "peer.h"
#include "marshall.h"
#include "block.h"
#include "proof.h"
#include <ccan/tal/tal.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <poll.h>

static int do_read_packet(int fd, struct io_plan *plan)
{
	char *len_start, *len_end;
	char **pkt = plan->u1.vp;
	int ret;
	u32 max;

	/* We store len in the second union */
	len_start = plan->u2.c;
	len_end = len_start + sizeof(le32);

	/* Now we have the actual plan, we can point into it to store len. */
	if (*pkt == NULL)
		*pkt = len_start;

	/* Still reading len? */
	if (*pkt >= len_start && *pkt < len_end) {
		ret = read(fd, *pkt, len_end - *pkt);
		if (ret <= 0)
			return -1;
		*pkt += ret;
		return 0;
	}

	/* Just finished reading len?  Allocate. */
	if (*pkt == len_end) {
		le32 len;

		memcpy(&len, len_start, sizeof(le32));

		/* Too big for protocol. */ 
		if (le32_to_cpu(len) > PROTOCOL_MAX_PACKET_LEN) {
			errno = ENOSPC;
			return -1;
		}
		if (le32_to_cpu(len) < sizeof(struct protocol_net_hdr)) {
			errno = EINVAL;
			return -1;
		}

		*pkt = tal_arr(NULL, char, le32_to_cpu(len));
		*(le32 *)*pkt = len;

		/* Store offset in plan.u2.s */
		plan->u2.s = sizeof(le32);
	}

	/* Read length from packet header. */
	max = le32_to_cpu(*(le32 *)*pkt);

	ret = read(fd, *pkt + plan->u2.s, max - plan->u2.s);
	if (ret <= 0)
		return -1;

	plan->u2.s += ret;
	return (plan->u2.s == max);
}

struct io_plan io_read_packet_(void *ppkt,
			       struct io_plan (*cb)(struct io_conn *, void *),
			       void *arg)
{
	struct io_plan plan;

	assert(cb);
	/* We'll start pointing into a scratch buffer, until we have len. */
	plan.u1.vp = ppkt;
	*(void **)ppkt = NULL;
	plan.io = do_read_packet;
	plan.next = cb;
	plan.next_arg = arg;
	plan.pollflag = POLLIN;

	return plan;
}

/* Frees pkt on next write! */
struct io_plan io_write_packet_(struct peer *peer, const void *pkt,
				struct io_plan (*next)(struct io_conn *,
						       void *))
{
	le32 len;

	tal_free(peer->outgoing);
	peer->outgoing = pkt;

	/* Packet header contains 32-bit little-endian length */
	memcpy(&len, pkt, sizeof(len));
	assert(le32_to_cpu(len) >= sizeof(struct protocol_net_hdr));
	assert(le32_to_cpu(len) <= PROTOCOL_MAX_PACKET_LEN);

	return io_write(pkt, le32_to_cpu(len), next, peer);
}

void *tal_packet_(const tal_t *ctx, size_t len, int type)
{
	struct protocol_net_hdr *hdr;

	assert(len >= sizeof(*hdr));
	assert(len < PROTOCOL_MAX_PACKET_LEN);

	/* Must be a char array so that tal_count() is in bytes */
	hdr = (void *)tal_arr(ctx, char, len);

	hdr->len = cpu_to_le32(len);
	hdr->type = cpu_to_le32(type);

	return hdr;
}

void tal_packet_append(void *ppkt, const void *mem, size_t len)
{
	struct protocol_net_hdr **hdr = ppkt;
	u32 orig_len = le32_to_cpu((*hdr)->len);

	tal_resize((char **)ppkt, orig_len + len);
	memcpy((char *)*hdr + orig_len, mem, len);
	(*hdr)->len = cpu_to_le32(orig_len + len);
}

void tal_packet_append_trans(void *ppkt,
			     const union protocol_transaction *trans)
{
	tal_packet_append(ppkt, trans, marshall_transaction_len(trans));
}

void tal_packet_append_trans_with_refs(void *ppkt,
				       const union protocol_transaction *trans,
				       const struct protocol_input_ref *refs)
{
	tal_packet_append_trans(ppkt, trans);
	tal_packet_append(ppkt, refs, marshall_input_ref_len(trans));
}

void tal_packet_append_proof(void *ppkt, const struct block *block, u32 txnum)
{
	struct protocol_trans_with_proof proof;

	proof.block = block->sha;
	proof.tnum = cpu_to_le32(txnum);
	create_proof(&proof.proof, block, txnum);

	tal_packet_append(ppkt, &proof, sizeof(proof));
	tal_packet_append_trans_with_refs(ppkt, block_get_trans(block, txnum),
					  block_get_refs(block, txnum));
}
