#include "bp/runahead_ext.h"
#include "isa/isa.h"
#include "globals/assert.h"

static Hash_Table hbt;
static uns retired_branch_count = 0;

static void decrement_hbt_entry(void* data, void* unused) {
  HBT_Entry* entry = (HBT_Entry*)data;
  if (entry->mispred_counter > HBT_DECREMENT_AMOUNT) {
    entry->mispred_counter -= HBT_DECREMENT_AMOUNT;
  } else {
    entry->mispred_counter = 0;
  }
}

void runahead_ext_init(void) {
  init_hash_table(&hbt, "Hard Branch Table", 1024, sizeof(HBT_Entry));
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

#define MAX_CHAIN_LENGTH 16

typedef struct {
  Addr pc;
  uns16 produced_reg;
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

  // Walk backwards through the CEB
  uns current_idx = (ceb_head == 0) ? (CEB_SIZE - 1) : (ceb_head - 1);
  
  for (uns steps = 0; steps < CEB_SIZE; steps++) {
    if (live_in_count == 0) {
      break; // Successfully fully extracted
    }

    CEB_Entry* entry = &ceb[current_idx];

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
        // Do NOT break! An x86 instruction might produce multiple registers 
        // that are both in our Live-In set (e.g., RAX and Flags).
      }
    }

    if (is_producer) {
      if (chain_length >= MAX_CHAIN_LENGTH) {
        // Exceeded max length, discard chain entirely
        return; 
      }

      // Add to buffer
      chain_buffer[chain_length].pc = entry->pc;
      chain_buffer[chain_length].produced_reg = produced_reg_id;
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

  // the chain was fully extracted and is <= MAX_CHAIN_LENGTH! Print it.
  printf("\n[RUNAHEAD] Successfully Extracted Chain for H2P Branch PC: 0x%llx (Length: %u)\n", (unsigned long long)branch_op->inst->addr, chain_length);
  for (uns i = 0; i < chain_length; i++) {
    printf("  -> Found Producer PC: 0x%llx (Produced Reg %u)\n", (unsigned long long)chain_buffer[i].pc, chain_buffer[i].produced_reg);
    if (chain_buffer[i].is_load) {
      printf("     (This producer is a Load from address 0x%llx)\n", (unsigned long long)chain_buffer[i].mem_addr);
    }
  }
}
