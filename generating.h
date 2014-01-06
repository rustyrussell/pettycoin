#ifndef PETTYCOIN_GENERATING_H
#define PETTYCOIN_GENERATING_H

struct state;
struct block;
void start_generating(struct state *state);
void restart_generating(struct state *state);

const struct protocol_address *generating_address(struct state *state);

void tell_generator_new_pending(struct state *state, unsigned int num);
#endif
