#include "bp/runahead_ext.h"

#include "globals/assert.h"
#include "globals/global_defs.h"
#include "globals/global_types.h"
#include "globals/global_vars.h"

#include "isa/isa.h"
#include "libs/hash_lib.h"

#include "bp/bp.h"
#include "core.param.h"
#include "lsq.h"
#include "map.h"
#include "model.h"
#include "op_pool.h"
#include "statistics.h"
#include "thread.h"

/**************************************************************************************/
/* Program-order uop ring (the "RETIRED UOPS ARRAY" of the Branch Characterizer, filled in program order as the
 * look-ahead buffer builds the on-path stream) */

#define UOP_RING_SIZE 1024
#define RECENT_STORES_SIZE (1 << 14)
#define TWIN_QUEUE_SIZE 256
#define MAX_TWINS_PER_UOP 3
#define MAX_BACKSLICE 64  // upper bound for --runahead_backslice_limit

typedef struct Ring_Uop_struct {
  Op* op;
  Counter unique_num;  // identifies the op instance (ops are recycled by the pool)
  Addr pc;
  uns num_srcs;
  uns num_dests;
  uns16 srcs[MAX_SRCS];
  uns16 dests[MAX_DESTS];
  Flag is_cbr;
  Flag is_load;
  int64 forwarding_store_seq;  // for a load: ring sequence number of the store that forwards its data, or -1
} Ring_Uop;

typedef struct Recent_Store_struct {
  Addr granule;
  int64 seq;
} Recent_Store;

static Ring_Uop uop_ring[UOP_RING_SIZE];
static uint64_t next_ring_seq = 0;
static Recent_Store recent_stores[RECENT_STORES_SIZE];  // RECENT RETIRED STORES: 8-byte granule -> latest store

/* Per-branch-IP statistics that decide eligibility */
typedef struct Branch_Info_struct {
  Addr pc;
  uint64_t exec_count;
  uint64_t fit_count;     // executions whose backslice has fewer than RUNAHEAD_BACKSLICE_LIMIT uops
  uint64_t fit_size_sum;  // total backslice size over the executions whose slice fits
  uint64_t guided_count;  // instances that were predicted correctly / got twins
  // Statistics of the measured region only (reset when warmup ends), for the offline H2P-Brain analysis
  uint64_t measured_exec_count;
  uint64_t measured_fit_count;
  uint64_t measured_slice_uops;  // backslice uops over the executions whose slice fits
  uint64_t measured_mispreds;    // on-path executions the normal predictor mispredicted (before any oracle override)
  uint64_t measured_flush_uops;  // uops flushed from the ROB by the recoveries those mispredictions caused
  uint64_t measured_recoveries;  // number of those recoveries
} Branch_Info;

static Hash_Table branch_info_table;
static Hash_Table excluded_branch_table;  // branch IPs the offline H2P-Brain analysis excluded

/* Twins created by the map stage and waiting for the node stage */
static Op* twin_queue[TWIN_QUEUE_SIZE];
static uns twin_queue_head = 0;
static uns twin_queue_count = 0;

/**************************************************************************************/

void runahead_ext_init(void) {
  ASSERT(0, RUNAHEAD_BACKSLICE_LIMIT <= MAX_BACKSLICE);
  ASSERT(0, !RUNAHEAD_ENABLE || LOOKAHEAD_BUF_SIZE);  // slices are computed on the look-ahead buffer's future stream
  init_hash_table(&branch_info_table, "Runahead Branch Table", 4096, sizeof(Branch_Info));
  init_hash_table(&excluded_branch_table, "Runahead Exclude Table", 1024, sizeof(Addr));
  if (RUNAHEAD_EXCLUDE_DIR && RUNAHEAD_EXCLUDE_DIR[0])
    // <dir>/<workload>/<simpoint>.txt, written by the offline H2P-Brain analysis
    bp_load_pc_list(RUNAHEAD_EXCLUDE_DIR, &excluded_branch_table, "Runahead exclude list");
  for (uns i = 0; i < RECENT_STORES_SIZE; i++)
    recent_stores[i].seq = -1;
}

static inline uns recent_store_index(Addr granule) {
  return (uns)((granule * 0x9E3779B97F4A7C15ull) >> 40) & (RECENT_STORES_SIZE - 1);
}

static inline Flag ring_uop_op_is_valid(const Ring_Uop* ring_uop) {
  return ring_uop->op->op_pool_valid && ring_uop->op->unique_num == ring_uop->unique_num;
}

/* Backward dependence slice of the branch at `branch_seq`, following the Branch Characterizer's algorithm.
 * Fills slice_seqs[] with the ring sequence numbers of the slice uops (up to RUNAHEAD_BACKSLICE_LIMIT of them) and
 * returns the slice size; a size >= RUNAHEAD_BACKSLICE_LIMIT means the slice does not fit. */
static uns compute_backslice(uint64_t branch_seq, uint64_t* slice_seqs) {
  const Ring_Uop* branch = &uop_ring[branch_seq % UOP_RING_SIZE];
  Flag needed_regs[NUM_REG_IDS];  // registers whose producer is still to be found
  memset(needed_regs, 0, sizeof(needed_regs));
  uns needed_reg_count = 0;
  uint64_t needed_stores[MAX_BACKSLICE];  // stores whose data a slice load needs
  uns needed_store_count = 0;
  uns slice_size = 0;

  for (uns i = 0; i < branch->num_srcs; i++) {
    uns16 reg = branch->srcs[i];
    if (reg < NUM_REG_IDS && !needed_regs[reg]) {
      needed_regs[reg] = TRUE;
      needed_reg_count++;
    }
  }

  uint64_t oldest_seq = branch_seq >= UOP_RING_SIZE ? branch_seq - UOP_RING_SIZE + 1 : 0;
  for (uint64_t seq = branch_seq; seq-- > oldest_seq;) {
    const Ring_Uop* uop = &uop_ring[seq % UOP_RING_SIZE];

    // The scan stops at the previous instance of the same branch
    if (uop->is_cbr && uop->pc == branch->pc)
      break;

    Flag in_slice = FALSE;
    Flag add_sources = FALSE;

    for (uns i = 0; i < needed_store_count; i++) {  // a store that forwards to a slice load
      if (needed_stores[i] == seq) {
        in_slice = TRUE;
        add_sources = TRUE;
        needed_stores[i] = needed_stores[--needed_store_count];
        break;
      }
    }

    if (!in_slice) {
      Flag writes_needed_reg = FALSE;
      for (uns i = 0; i < uop->num_dests; i++) {
        uns16 reg = uop->dests[i];
        if (reg > 0 && reg < NUM_REG_IDS && needed_regs[reg]) {
          writes_needed_reg = TRUE;
          needed_regs[reg] = FALSE;
          needed_reg_count--;
        }
      }
      if (writes_needed_reg) {
        in_slice = TRUE;
        int64 store_seq = uop->forwarding_store_seq;
        if (uop->is_load && store_seq >= 0 && (uint64_t)store_seq >= oldest_seq && (uint64_t)store_seq < seq) {
          if (needed_store_count < RUNAHEAD_BACKSLICE_LIMIT)
            needed_stores[needed_store_count++] = (uint64_t)store_seq;  // the value comes from the store: follow it
        } else {
          add_sources = TRUE;
        }
      }
    }

    if (add_sources) {
      for (uns i = 0; i < uop->num_srcs; i++) {
        uns16 reg = uop->srcs[i];
        if (reg < NUM_REG_IDS && !needed_regs[reg]) {
          needed_regs[reg] = TRUE;
          needed_reg_count++;
        }
      }
    }

    if (in_slice) {
      if (slice_size < RUNAHEAD_BACKSLICE_LIMIT)
        slice_seqs[slice_size] = seq;
      slice_size++;
      if (slice_size >= RUNAHEAD_BACKSLICE_LIMIT)
        break;  // too long to be a candidate: no need to look further
    }

    if (needed_reg_count == 0 && needed_store_count == 0)
      break;  // nothing left to produce
  }
  return slice_size;
}

static Flag is_eligible(const Branch_Info* branch_info) {
  return branch_info->exec_count >= RUNAHEAD_MIN_EXECS &&
         branch_info->fit_count * 100 > branch_info->exec_count * RUNAHEAD_ELIGIBLE_PCT;
}

static void handle_branch(Op* branch_op, uint64_t branch_seq) {
  uint64_t slice_seqs[MAX_BACKSLICE];
  uns slice_size = compute_backslice(branch_seq, slice_seqs);
  Flag slice_fits = slice_size < RUNAHEAD_BACKSLICE_LIMIT;

  Flag is_new;
  Branch_Info* branch_info =
      (Branch_Info*)hash_table_access_create(&branch_info_table, branch_op->inst->addr, &is_new);
  if (is_new) {
    memset(branch_info, 0, sizeof(*branch_info));
    branch_info->pc = branch_op->inst->addr;
  }
  branch_info->exec_count++;
  branch_info->measured_exec_count++;
  if (slice_fits) {
    branch_info->fit_count++;
    branch_info->measured_fit_count++;
    branch_info->fit_size_sum += slice_size;
    branch_info->measured_slice_uops += slice_size;
  }

  if (RUNAHEAD_PROFILE_ONLY)
    return;  // statistics only: nothing is predicted or injected
  if (RUNAHEAD_OFF_IN_WARMUP && FULL_WARMUP && !warmup_dump_done[0])
    return;  // the characterizer keeps learning during warmup, but nothing is guided until it ends

  // Candidate: the slice fits in more than RUNAHEAD_ELIGIBLE_PCT percent of this branch's executions so far
  if (!is_eligible(branch_info) || !slice_fits)
    return;

  // Branches the offline H2P-Brain analysis excluded (see runahead_ext.h)
  if (hash_table_access(&excluded_branch_table, branch_op->inst->addr)) {
    STAT_EVENT(branch_op->proc_id, RUNAHEAD_H2P_EXCLUDED);
    return;
  }

  branch_info->guided_count++;
  branch_op->runahead_oracle = TRUE;
  STAT_EVENT(branch_op->proc_id, RUNAHEAD_BRANCH_INSTANCES);
  INC_STAT_EVENT(branch_op->proc_id, RUNAHEAD_SLICE_UOPS, slice_size);

  for (uns i = 0; i < slice_size; i++) {
    const Ring_Uop* slice_uop = &uop_ring[slice_seqs[i] % UOP_RING_SIZE];
    Op* op = slice_uop->op;
    if (!ring_uop_op_is_valid(slice_uop) || op_get_map_cycle(op) != MAX_CTR) {
      STAT_EVENT(branch_op->proc_id, RUNAHEAD_TWIN_TOO_LATE);  // already past the map stage: cannot twin it
      continue;
    }
    if (op->runahead_twins < MAX_TWINS_PER_UOP)
      op->runahead_twins++;
  }
}

static void reset_measured_stats(void* data, void* arg) {
  Branch_Info* branch_info = (Branch_Info*)data;
  branch_info->measured_exec_count = branch_info->measured_fit_count = branch_info->measured_slice_uops = 0;
  branch_info->measured_mispreds = branch_info->measured_flush_uops = branch_info->measured_recoveries = 0;
}

void runahead_ext_reset_measured(void) {
  if (RUNAHEAD_ENABLE)
    hash_table_scan(&branch_info_table, reset_measured_stats, NULL);
}

void runahead_ext_note_prediction(Op* op, Flag normal_pred) {
  if (!RUNAHEAD_ENABLE || op->off_path)
    return;
  Branch_Info* branch_info = (Branch_Info*)hash_table_access(&branch_info_table, op->inst->addr);
  if (branch_info && normal_pred != op->oracle_info.dir)
    branch_info->measured_mispreds++;
}

void runahead_ext_note_flush(Addr pc, uns flush_uops) {
  if (!RUNAHEAD_ENABLE)
    return;
  Branch_Info* branch_info = (Branch_Info*)hash_table_access(&branch_info_table, pc);
  if (branch_info) {
    branch_info->measured_flush_uops += flush_uops;
    branch_info->measured_recoveries++;
  }
}

void runahead_ext_on_built_op(Op* op) {
  if (!RUNAHEAD_ENABLE || op->off_path)
    return;

  uint64_t seq = next_ring_seq++;
  Ring_Uop* ring_uop = &uop_ring[seq % UOP_RING_SIZE];
  ring_uop->op = op;
  ring_uop->unique_num = op->unique_num;
  ring_uop->pc = op->inst->addr;
  ring_uop->num_srcs = op->uop->num_src_regs;
  ring_uop->num_dests = op->uop->num_dest_regs;
  for (uns i = 0; i < ring_uop->num_srcs; i++)
    ring_uop->srcs[i] = op->uop->srcs[i].id;
  for (uns i = 0; i < ring_uop->num_dests; i++)
    ring_uop->dests[i] = op->uop->dests[i].id;
  ring_uop->is_cbr = (op->uop->cf_type == CF_CBR);
  ring_uop->is_load = (op->uop->mem_type == MEM_LD);
  ring_uop->forwarding_store_seq = -1;

  if (op->uop->mem_type == MEM_ST) {
    Addr granule = op->oracle_info.va >> 3;
    Recent_Store* store = &recent_stores[recent_store_index(granule)];
    store->granule = granule;
    store->seq = (int64)seq;
  } else if (ring_uop->is_load) {
    Addr granule = op->oracle_info.va >> 3;
    const Recent_Store* store = &recent_stores[recent_store_index(granule)];
    if (store->seq >= 0 && store->granule == granule)
      ring_uop->forwarding_store_seq = store->seq;  // forwarded load: the data comes from this store
  }

  if (ring_uop->is_cbr)
    handle_branch(op, seq);
}

/**************************************************************************************/
/* Twins */

static Op* make_twin(const Op* real) {
  Op* twin = alloc_op(real->proc_id);
  unique_count++;  // alloc_op stamped the current values; keep them unique like the fetch path does
  unique_count_per_core[real->proc_id]++;

  twin->runahead_shadow = TRUE;
  twin->runahead_twin_of = real->unique_num;
  twin->op_num = real->op_num;  // shares the fate of its real uop: flushed by exactly the recoveries that flush it
  twin->inst = real->inst;
  twin->uop = (Static_Op_Info*)malloc(sizeof(Static_Op_Info));
  *twin->uop = *real->uop;
  twin->oracle_info = real->oracle_info;
  twin->oracle_info.dcmiss = FALSE;
  twin->oracle_info.l1_miss = FALSE;
  twin->oracle_info.l1_miss_satisfied = FALSE;
  twin->oracle_info.dep_on_l1_miss = FALSE;
  twin->oracle_info.was_dep_on_l1_miss = FALSE;

  // A twin only has to occupy the pipeline like its real uop: it reads the same sources (so it waits for the
  // same producers) but writes nothing, never alters control flow and never writes memory
  twin->uop->num_dest_regs = 0;
  twin->uop->cf_type = NOT_CF;
  twin->uop->bar_type = 0;
  if (twin->uop->mem_type == MEM_ST)
    twin->uop->mem_type = NOT_MEM;

  // The memory system reads op->bp_pred_info (global history) when training prefetchers
  twin->bp_pred_info = &twin->bp_pred_main;
  twin->btb_pred_info = &twin->btb_pred;
  twin->bom = TRUE;
  twin->eom = TRUE;
  op_set_fetch_cycle(twin, cycle_count);
  op_set_decode_cycle(twin, cycle_count);
  return twin;
}

void runahead_ext_map_twins(Op* real) {
  for (uns i = 0; i < real->runahead_twins; i++) {
    if (twin_queue_count == TWIN_QUEUE_SIZE) {
      STAT_EVENT(real->proc_id, RUNAHEAD_TWIN_DROPPED);
      break;
    }
    Op* twin = make_twin(real);
    op_set_map_cycle(twin, cycle_count);

    // Mapped before the real uop so that it reads the same register / memory state the real uop will read
    thread_map_op(twin);
    thread_map_mem_dep(twin);
    add_to_wake_up_lists(twin, model->wake_hook);

    twin_queue[(twin_queue_head + twin_queue_count++) % TWIN_QUEUE_SIZE] = twin;
    STAT_EVENT(real->proc_id, RUNAHEAD_SHADOW_OPS_MAPPED);
  }
}

Op* runahead_ext_peek_twin(const Op* real) {
  while (twin_queue_count > 0) {
    Op* twin = twin_queue[twin_queue_head];
    if (twin->runahead_twin_of == real->unique_num)
      return twin;
    // belongs to a real uop that is no longer in the machine
    twin_queue_head = (twin_queue_head + 1) % TWIN_QUEUE_SIZE;
    twin_queue_count--;
    STAT_EVENT(twin->proc_id, RUNAHEAD_SHADOW_OPS_FLUSHED);
    free_op(twin);
  }
  return NULL;
}

void runahead_ext_pop_twin(void) {
  ASSERT(0, twin_queue_count > 0);
  twin_queue_head = (twin_queue_head + 1) % TWIN_QUEUE_SIZE;
  twin_queue_count--;
}

void runahead_ext_on_recovery(Counter recovery_op_num) {
  // Twins that have not reached the ROB yet are flushed with the real uops younger than the recovering op (the
  // queue is in program order, so those are at its tail); the rest go on
  while (twin_queue_count > 0) {
    Op* twin = twin_queue[(twin_queue_head + twin_queue_count - 1) % TWIN_QUEUE_SIZE];
    if (twin->op_num <= recovery_op_num)
      break;
    twin_queue_count--;
    STAT_EVENT(twin->proc_id, RUNAHEAD_SHADOW_OPS_FLUSHED);
    free_op(twin);
  }
}

/**************************************************************************************/

static void dump_branch(void* data, void* arg) {
  const Branch_Info* branch_info = (const Branch_Info*)data;
  FILE* fp = (FILE*)arg;
  double avg_fit_size = branch_info->fit_count ? (double)branch_info->fit_size_sum / branch_info->fit_count : 0.0;
  fprintf(fp, "0x%llx,%llu,%llu,%.2f,%d,%llu,%llu,%llu,%llu,%llu,%llu,%llu\n", (unsigned long long)branch_info->pc,
          (unsigned long long)branch_info->exec_count, (unsigned long long)branch_info->fit_count, avg_fit_size,
          is_eligible(branch_info), (unsigned long long)branch_info->guided_count,
          (unsigned long long)branch_info->measured_exec_count, (unsigned long long)branch_info->measured_fit_count,
          (unsigned long long)branch_info->measured_slice_uops, (unsigned long long)branch_info->measured_mispreds,
          (unsigned long long)branch_info->measured_flush_uops, (unsigned long long)branch_info->measured_recoveries);
}

void runahead_ext_dump(void) {
  if (!RUNAHEAD_ENABLE)
    return;
  FILE* fp = fopen("runahead_branches.csv", "w");
  if (!fp)
    return;
  fprintf(fp,
          "PC,Executions,SmallBackslice,AvgSmallBackslice,Eligible,GuidedInstances,MExecutions,MSmallBackslice,"
          "MSliceUops,MMispredicts,MFlushedUops,MRecoveries\n");
  hash_table_scan(&branch_info_table, dump_branch, fp);
  fclose(fp);
}
