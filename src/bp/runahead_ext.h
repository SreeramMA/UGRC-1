#ifndef __RUNAHEAD_EXT_H__
#define __RUNAHEAD_EXT_H__

#include "globals/global_types.h"
#include "libs/hash_lib.h"
#include "op.h"
#include "isa/isa.h"

#define HBT_SIZE 64
#define HBT_COUNTER_MAX 31
#define HBT_DECREMENT_AMOUNT 15
#define HBT_DECREMENT_PERIOD 1000

// Hard Branch Table Entry
typedef struct HBT_Entry_struct {
  uns8 mispred_counter; // 5-bit saturating counter (0-31)
} HBT_Entry;

void runahead_ext_init(void);
void runahead_ext_update_hbt(Op* op);

// --- Dependence Chain Cache (DCC) & Local Register File (LRF) ---
#define DCC_SIZE 32
#define MAX_CHAIN_LENGTH 16
#define LRF_SIZE 8 // 8 physical registers per local register file (Table 2)

typedef struct DCC_Entry_struct {
  Addr branch_pc;           // Tag: Terminating Branch PC
  Flag branch_outcome;      // Tag: Terminating Branch Outcome (Taken/Not Taken)
  Addr target_branch_pc;    // Target branch being predicted by this chain
  Flag valid;               
  uint64_t last_used;       // For LRU replacement
  
  uns chain_length;         
  Addr chain_pcs[MAX_CHAIN_LENGTH]; // The extracted slice
  Flag live_ins[NUM_REGS];  // Required registers from the main pipeline
} DCC_Entry;

void runahead_ext_dcc_init(void);
void runahead_ext_dcc_insert(Addr branch_pc, Flag branch_outcome, Addr target_branch_pc, uns chain_length, Addr* chain_pcs, Flag* live_ins);
DCC_Entry* runahead_ext_dcc_lookup(Addr branch_pc, Flag branch_outcome);

// --- Chain Extraction Buffer (CEB) ---
#define CEB_SIZE 512

typedef struct CEB_Entry_struct {
  Addr pc;
  Cf_Type cf_type;
  Op_Type op_type;
  Flag branch_dir;
  
  uns num_src_regs;
  uns num_dest_regs;
  uns16 srcs[MAX_SRCS]; 
  uns16 dests[MAX_DESTS];
  
  Mem_Type mem_type;
  Addr mem_addr;
} CEB_Entry;

void runahead_ext_update_ceb(Op* op);
void runahead_ext_extract_chain(Op* branch_op);
void runahead_ext_dump_chain_lengths(void);

#endif // __RUNAHEAD_EXT_H__
