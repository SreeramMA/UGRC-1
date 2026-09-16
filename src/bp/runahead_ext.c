#include "bp/runahead_ext.h"
#include "isa/isa.h"
#include "globals/assert.h"

static Hash_Table hbt;
static uns retired_branch_count = 0;

// Structure to track chain lengths per target PC
typedef struct Chain_Length_Stats_struct {
  Addr target_pc;
  uns min_length;
  uns max_length;
  uint64_t total_length;
  uint64_t count;
} Chain_Length_Stats;

static Hash_Table chain_stats_table;

static void decrement_hbt_entry(void* data, void* unused) {
  HBT_Entry* entry = (HBT_Entry*)data;
  if (entry->mispred_counter > HBT_DECREMENT_AMOUNT) {
    entry->mispred_counter -= HBT_DECREMENT_AMOUNT;
  } else {
    entry->mispred_counter = 0;
  }
}

void runahead_ext_init(void) {
  init_hash_table(&hbt, "Hard Branch Table", HBT_SIZE, sizeof(HBT_Entry));
  init_hash_table(&chain_stats_table, "Chain Length Stats Table", 1024, sizeof(Chain_Length_Stats));
  runahead_ext_dcc_init();
}

void runahead_ext_update_hbt(Op* op) {
  // Only track conditional branches
  if (!op || op->uop->cf_type != CF_CBR) return;
  
  retired_branch_count++;

  // Check if it was mispredicted
  // In Scarab, oracle_info.dir is actual direction, and bp_pred_info->pred is predicted direction
  Flag mispredicted = (op->oracle_info.dir != op->bp_pred_info->pred);

  if (mispredicted) {
    Flag new_entry;
    HBT_Entry* entry = (HBT_Entry*)hash_table_access_create(&hbt, op->inst->addr, &new_entry);
    
    if (new_entry) {
      entry->mispred_counter = 0;
    }
    
    if (entry->mispred_counter < HBT_COUNTER_MAX) {
      entry->mispred_counter++;
    }

    if (entry->mispred_counter == HBT_COUNTER_MAX) {
      runahead_ext_extract_chain(op);
      // Reset or halve the counter so we don't spam extraction every single time
      entry->mispred_counter = HBT_COUNTER_MAX / 2;
    }
  }

  // Periodically decrement HBT counters
  if (retired_branch_count >= HBT_DECREMENT_PERIOD) {
    hash_table_scan(&hbt, decrement_hbt_entry, NULL);
    retired_branch_count = 0;
  }
}

// --- Chain Extraction Buffer (CEB) Implementation ---
static CEB_Entry ceb[CEB_SIZE];
static uns ceb_head = 0;

void runahead_ext_update_ceb(Op* op) {
  if (!op || !op->inst || !op->uop) return;

  CEB_Entry* entry = &ceb[ceb_head];

  // 1. Copy basic info
  entry->pc = op->inst->addr;
  entry->cf_type = op->uop->cf_type;
  entry->op_type = op->uop->op_type;
  entry->branch_dir = op->oracle_info.dir;
  
  // 2. Copy source registers
  entry->num_src_regs = op->uop->num_src_regs;
  for (uns i = 0; i < op->uop->num_src_regs; i++) {
    entry->srcs[i] = op->uop->srcs[i].id;
  }

  // 3. Copy destination registers
  entry->num_dest_regs = op->uop->num_dest_regs;
  for (uns i = 0; i < op->uop->num_dest_regs; i++) {
    entry->dests[i] = op->uop->dests[i].id;
  }

  // 4. Copy memory info (virtual address)
  entry->mem_type = op->uop->mem_type;
  if (entry->mem_type == MEM_LD || entry->mem_type == MEM_ST) {
    entry->mem_addr = op->oracle_info.va;
  } else {
    entry->mem_addr = 0;
  }

  // Move the head of the circular buffer forward
  ceb_head = (ceb_head + 1) % CEB_SIZE;
}


typedef struct {
  Addr pc;
  uns num_src_regs;
  uns num_dest_regs;
  uns16 srcs[MAX_SRCS];
  uns16 dests[MAX_DESTS];
  Flag is_load;
  Addr mem_addr;
} Extracted_Producer;

void runahead_ext_extract_chain(Op* branch_op) {
  if (!branch_op || !branch_op->uop) return;

  // Initialize the Live-In set (boolean array)
  Flag live_ins[NUM_REGS];
  memset(live_ins, 0, sizeof(live_ins));

  // Add the branch's source registers to the initial Live-In set
  uns live_in_count = 0;
  for (uns i = 0; i < branch_op->uop->num_src_regs; i++) {
    uns16 reg_id = branch_op->uop->srcs[i].id;
    if (reg_id < NUM_REGS && !live_ins[reg_id]) {
      live_ins[reg_id] = TRUE;
      live_in_count++;
    }
  }

  // Buffer to hold the extracted chain
  Extracted_Producer chain_buffer[MAX_CHAIN_LENGTH];
  uns chain_length = 0;
  Flag found_terminating_branch = FALSE;
  Addr terminating_pc = 0;
  Flag terminating_outcome = FALSE;

  // Walk backwards through the CEB
  uns current_idx = (ceb_head == 0) ? (CEB_SIZE - 1) : (ceb_head - 1);
  
  for (uns steps = 0; steps < CEB_SIZE; steps++) {
    CEB_Entry* entry = &ceb[current_idx];

    // Paper rule: Chain extraction terminates when a second instance of the same branch is found
    if (entry->pc == branch_op->inst->addr) {
      found_terminating_branch = TRUE;
      terminating_pc = entry->pc;
      terminating_outcome = entry->branch_dir;
      break; 
    }

    // Check if this instruction produces any Live-In
    Flag is_producer = FALSE;
    uns16 produced_reg_id = 0;
    
    for (uns i = 0; i < entry->num_dest_regs; i++) {
      uns16 reg_id = entry->dests[i];
      if (reg_id > 0 && reg_id < NUM_REGS && live_ins[reg_id]) {
        is_producer = TRUE;
        produced_reg_id = reg_id; // Just store the last one for logging
        
        // Remove from Live-Ins (it is now produced)
        live_ins[reg_id] = FALSE;
        live_in_count--;
      }
    }

    if (is_producer) {
      // Paper rule: "do not contain expensive operations such as integer divide or floating point operations, and do not contain any control flow instructions"
      if (entry->op_type == OP_IDIV || entry->op_type == OP_FDIV || entry->op_type == OP_CF ||
          (entry->op_type >= OP_FLD && entry->op_type <= OP_FCMP)) {
        return; // Discard chain entirely
      }

      if (chain_length >= MAX_CHAIN_LENGTH) {
        // Exceeded maximum allowable chain length (16 uops per Table 2)
        return; 
      }

      // Add to buffer
      chain_buffer[chain_length].pc = entry->pc;
      chain_buffer[chain_length].num_src_regs = entry->num_src_regs;
      chain_buffer[chain_length].num_dest_regs = entry->num_dest_regs;
      for (uns i = 0; i < entry->num_src_regs; i++) {
        chain_buffer[chain_length].srcs[i] = entry->srcs[i];
      }
      for (uns i = 0; i < entry->num_dest_regs; i++) {
        chain_buffer[chain_length].dests[i] = entry->dests[i];
      }
      chain_buffer[chain_length].is_load = (entry->mem_type == MEM_LD);
      chain_buffer[chain_length].mem_addr = entry->mem_addr;
      chain_length++;

      // Add its sources to Live-Ins
      for (uns i = 0; i < entry->num_src_regs; i++) {
        uns16 reg_id = entry->srcs[i];
        if (reg_id < NUM_REGS && !live_ins[reg_id]) {
          live_ins[reg_id] = TRUE;
          live_in_count++;
        }
      }
    }

    // Step backwards
    current_idx = (current_idx == 0) ? (CEB_SIZE - 1) : (current_idx - 1);
  }

  // Paper rule: If we did not encounter the terminating branch within the CEB, discard
  if (!found_terminating_branch || chain_length == 0) {
    return;
  }

  // Simulate Local Rename and LRF physical register reuse (Paper Section 4.3)
  int last_use[NUM_REGS];
  memset(last_use, -1, sizeof(last_use));

  // Find the last use of every register in execution order (forward)
  for (int i = 0; i < (int)chain_length; i++) {
    uns rev_idx = chain_length - 1 - i;
    for (uns j = 0; j < chain_buffer[rev_idx].num_src_regs; j++) {
      uns16 reg_id = chain_buffer[rev_idx].srcs[j];
      if (reg_id < NUM_REGS) {
        last_use[reg_id] = i;
      }
    }
  }

  // Simulate active registers in the LRF
  uns active_lrf = live_in_count;
  uns peak_lrf = active_lrf;

  for (int i = 0; i < (int)chain_length; i++) {
    uns rev_idx = chain_length - 1 - i;
    // Allocate destinations in LRF
    active_lrf += chain_buffer[rev_idx].num_dest_regs;
    if (active_lrf > peak_lrf) {
      peak_lrf = active_lrf;
    }

    // Free sources that die at this instruction (last use)
    for (uns j = 0; j < chain_buffer[rev_idx].num_src_regs; j++) {
      uns16 reg_id = chain_buffer[rev_idx].srcs[j];
      if (reg_id < NUM_REGS && last_use[reg_id] == i) {
        if (active_lrf > 0) active_lrf--;
      }
    }
  }

  // Discard chain if peak simultaneous register demand exceeds 8 LRF registers
  if (peak_lrf > LRF_SIZE) {
    return;
  }

  // Record chain length statistics for this target branch PC
  Flag new_stat;
  Chain_Length_Stats* s = (Chain_Length_Stats*)hash_table_access_create(&chain_stats_table, branch_op->inst->addr, &new_stat);
  if (new_stat) {
    s->target_pc = branch_op->inst->addr;
    s->min_length = chain_length;
    s->max_length = chain_length;
    s->total_length = chain_length;
    s->count = 1;
  } else {
    if (chain_length < s->min_length) s->min_length = chain_length;
    if (chain_length > s->max_length) s->max_length = chain_length;
    s->total_length += chain_length;
    s->count++;
  }

  // Convert Extracted_Producer array to an array of PCs in execution order
  Addr extracted_pcs[MAX_CHAIN_LENGTH];
  for (uns i = 0; i < chain_length; i++) {
    // The chain was extracted backwards, so we reverse it to store it in execution order
    extracted_pcs[i] = chain_buffer[chain_length - 1 - i].pc;
  }

  // Tag with terminating branch's PC and outcome and install into DCC with target branch PC
  runahead_ext_dcc_insert(terminating_pc, terminating_outcome, branch_op->inst->addr, chain_length, extracted_pcs, live_ins);
  printf("\n[RUNAHEAD] Successfully Installed Chain into DCC for Terminating Branch PC: 0x%llx (Outcome: %u, Target: 0x%llx, Length: %u)\n", 
         (unsigned long long)terminating_pc, terminating_outcome, (unsigned long long)branch_op->inst->addr, chain_length);
}

// --- Dependence Chain Cache (DCC) Implementation ---
static DCC_Entry dcc[DCC_SIZE];
static uint64_t dcc_global_counter = 0;

void runahead_ext_dcc_init(void) {
  for (uns i = 0; i < DCC_SIZE; i++) {
    dcc[i].valid = FALSE;
    dcc[i].last_used = 0;
  }
}

void runahead_ext_dcc_insert(Addr branch_pc, Flag branch_outcome, Addr target_branch_pc, uns chain_length, Addr* chain_pcs, Flag* live_ins) {
  dcc_global_counter++;
  
  // Try to find an empty slot or replace the LRU entry
  uns lru_idx = 0;
  uint64_t oldest_time = (uint64_t)-1;
  
  for (uns i = 0; i < DCC_SIZE; i++) {
    // If it's already in the cache, just update it
    if (dcc[i].valid && dcc[i].branch_pc == branch_pc && dcc[i].branch_outcome == branch_outcome) {
      lru_idx = i;
      break;
    }
    
    // Track LRU
    if (!dcc[i].valid) {
      oldest_time = 0;
      lru_idx = i;
    } else if (dcc[i].last_used < oldest_time) {
      oldest_time = dcc[i].last_used;
      lru_idx = i;
    }
  }
  
  // Insert into LRU slot
  dcc[lru_idx].branch_pc = branch_pc;
  dcc[lru_idx].branch_outcome = branch_outcome;
  dcc[lru_idx].target_branch_pc = target_branch_pc;
  dcc[lru_idx].chain_length = chain_length;
  dcc[lru_idx].valid = TRUE;
  dcc[lru_idx].last_used = dcc_global_counter;
  
  memcpy(dcc[lru_idx].chain_pcs, chain_pcs, sizeof(Addr) * chain_length);
  memcpy(dcc[lru_idx].live_ins, live_ins, sizeof(Flag) * NUM_REGS);
}

DCC_Entry* runahead_ext_dcc_lookup(Addr branch_pc, Flag branch_outcome) {
  for (uns i = 0; i < DCC_SIZE; i++) {
    if (dcc[i].valid && dcc[i].branch_pc == branch_pc && dcc[i].branch_outcome == branch_outcome) {
      dcc_global_counter++;
      dcc[i].last_used = dcc_global_counter;
      return &dcc[i];
    }
  }
  return NULL;
}

void runahead_ext_dump_chain_lengths(void) {
  FILE* fp = fopen("runahead_Chain_length", "w");
  if (!fp) {
    printf("[RUNAHEAD] Could not open runahead_Chain_length for writing!\n");
    return;
  }

  fprintf(fp, "Target_PC,Average_Length,Min_Length,Max_Length,Count,Total_Length\n");

  uint64_t global_total_length = 0;
  uint64_t global_count = 0;

  for (uns b = 0; b < chain_stats_table.buckets; b++) {
    Hash_Table_Entry* cur = chain_stats_table.entries[b];
    while (cur) {
      Chain_Length_Stats* s = (Chain_Length_Stats*)cur->data;
      if (s && s->count > 0) {
        double avg = (double)s->total_length / s->count;
        fprintf(fp, "0x%llx,%.2f,%u,%u,%llu,%llu\n",
                (unsigned long long)s->target_pc,
                avg,
                s->min_length,
                s->max_length,
                (unsigned long long)s->count,
                (unsigned long long)s->total_length);
        global_total_length += s->total_length;
        global_count += s->count;
      }
      cur = cur->next;
    }
  }

  double global_avg = (global_count > 0) ? ((double)global_total_length / global_count) : 0.0;
  fprintf(fp, "# Overall Average Chain Length: %.2f (Total Chains Extracted: %llu)\n", global_avg, (unsigned long long)global_count);
  fclose(fp);
  printf("\n[RUNAHEAD] Successfully wrote chain length statistics to runahead_Chain_length (Overall Avg: %.2f, Total Chains: %llu)\n", 
         global_avg, (unsigned long long)global_count);
}
