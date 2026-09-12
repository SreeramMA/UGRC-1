#ifndef __RUNAHEAD_EXT_H__
#define __RUNAHEAD_EXT_H__

#include "globals/global_types.h"
#include "libs/hash_lib.h"
#include "op.h"

#define HBT_COUNTER_MAX 31
#define HBT_DECREMENT_AMOUNT 15
#define HBT_DECREMENT_PERIOD 1000

// Hard Branch Table Entry
typedef struct HBT_Entry_struct {
  uns8 mispred_counter; // 5-bit saturating counter (0-31)
} HBT_Entry;

void runahead_ext_init(void);
void runahead_ext_update_hbt(Op* op);

#endif // __RUNAHEAD_EXT_H__

// --- Chain Extraction Buffer (CEB) ---
#define CEB_SIZE 512

typedef struct CEB_Entry_struct {
  Addr pc;
  Cf_Type cf_type;
  
  uns num_src_regs;
  uns num_dest_regs;
  uns16 srcs[MAX_SRCS]; 
  uns16 dests[MAX_DESTS];
  
  Mem_Type mem_type;
  Addr mem_addr;
} CEB_Entry;

void runahead_ext_update_ceb(Op* op);

void runahead_ext_extract_chain(Op* branch_op);
