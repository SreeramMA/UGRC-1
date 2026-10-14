#ifndef __RUNAHEAD_EXT_H__
#define __RUNAHEAD_EXT_H__

#include "globals/global_types.h"
#include "op.h"

/* Runahead model after "H2P-Brain: Hard-to-predict Branch Analysis Infrastructure" (ISPASS 2026), sec. V-C.
 *
 * Eligibility: a conditional branch is a Runahead candidate if more than RUNAHEAD_ELIGIBLE_PCT percent of its
 * executions have a backward dependence slice ("backslice") of fewer than RUNAHEAD_BACKSLICE_LIMIT uops.
 *
 * Backslice (sec. III-B): scan the program-order uop stream backwards from the branch with an active register set
 * (initially the branch's sources) and a store-index set. A uop that writes a register in the active set joins the
 * slice, replaces that register by its own sources; a load forwarded from an earlier store joins the slice and
 * hands over to that store (which joins the slice and contributes its sources). The scan stops at the previous
 * instance of the same branch.
 *
 * Model: every instance of an eligible branch whose slice fits is predicted correctly, and a shadow twin of each
 * slice uop is pushed through the pipeline just before the real uop, competing for ROB, RS, functional-unit, port,
 * dcache and load-queue resources. Twins never retire architecturally and share the fate of their real uop.
 *
 * Requires the look-ahead buffer (--lookahead_buf_size): slices are computed on the future on-path stream, which
 * is what lets a twin be pushed before its real uop. */

#ifdef __cplusplus
extern "C" {
#endif

void runahead_ext_init(void);

// Called for every on-path uop as the look-ahead buffer builds the stream, in program order
void runahead_ext_on_built_op(Op* op);

// Statistics for the offline H2P-Brain analysis (runahead_branches.csv): the normal predictor's verdict on an on-path conditional branch (before any oracle
// override), and the uops a recovery caused by `pc` flushed from the ROB
void runahead_ext_note_prediction(Op* op, Flag normal_pred);
void runahead_ext_note_flush(Addr pc, uns flush_uops);

// The measured region starts: restart the statistics above (the eligibility statistics keep their history)
void runahead_ext_reset_measured(void);

// Map stage: create and map the twins of `real` just before it, and queue them for the node stage
void runahead_ext_map_twins(Op* real);

// Node stage: the oldest queued twin, if it belongs to `real` (twins enter the ROB right before their real uop)
Op* runahead_ext_peek_twin(const Op* real);
void runahead_ext_pop_twin(void);

// A recovery flushes the twins of the real uops it flushes (twins carry their real uop's op_num); this drops the
// ones that have not reached the ROB yet
void runahead_ext_on_recovery(Counter recovery_op_num);

void runahead_ext_dump(void);

#ifdef __cplusplus
}
#endif

#endif  // __RUNAHEAD_EXT_H__
