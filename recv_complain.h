#ifndef PETTYCOIN_RECV_COMPLAIN_H
#define PETTYCOIN_RECV_COMPLAIN_H
#include "config.h"
#include "protocol_ecode.h"
#include "protocol_net.h"

struct peer;

enum protocol_ecode
verify_problem_input(struct state *state,
		     const union protocol_tx *tx, u32 input_num,
		     const union protocol_tx *in,
		     enum input_ecode *ierr,
		     u32 *total);

enum protocol_ecode
unmarshal_and_check_bad_amount(struct state *state, const union protocol_tx *tx,
			       const char *p, size_t len);

enum protocol_ecode
recv_complain_tx_misorder(struct peer *peer,
			  const struct protocol_pkt_complain_tx_misorder *pkt);

enum protocol_ecode
recv_complain_tx_invalid(struct peer *peer,
			 const struct protocol_pkt_complain_tx_invalid *pkt);

enum protocol_ecode
recv_complain_tx_bad_input(struct peer *peer,
		   const struct protocol_pkt_complain_tx_bad_input *pkt);

enum protocol_ecode
recv_complain_tx_bad_amount(struct peer *peer,
		    const struct protocol_pkt_complain_tx_bad_amount *pkt);

enum protocol_ecode
recv_complain_doublespend(struct peer *peer,
			  const struct protocol_pkt_complain_doublespend *pkt);

enum protocol_ecode
recv_complain_bad_input_ref(struct peer *peer,
		    const struct protocol_pkt_complain_bad_input_ref *pkt);

enum protocol_ecode
recv_complain_claim_input_invalid(struct peer *peer,
		  const struct protocol_pkt_complain_claim_input_invalid *pkt);


#endif /* PETTYCOIN_RECV_COMPLAIN_H */
