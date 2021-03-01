use crate::corenode::{HTree, Prefix, RecordID};
use drop::crypto::Digest;
use std::mem;
use std::sync::Arc;

pub struct MemoryReport {
    pub o_h_tree: usize,
    pub o_touches_queue: usize,
    pub o_touches_hashset: usize,
    pub o_touches_data: usize,
    pub o_history_queue: usize,
    pub o_prefix_list: usize,
    pub o_tree_serialized: usize,
}

impl std::fmt::Display for MemoryReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let o_sum_data_independent = self.o_h_tree
            + self.o_touches_queue
            + self.o_touches_hashset
            + self.o_touches_data
            + self.o_history_queue
            + self.o_prefix_list;

        let o_sum_data_dependent = self.o_tree_serialized;

        write!(
            f,
            "Memory usage decomposition:
        Data independent overhead total: ------ {} B
          - History tree (structs) ------------ {} B
          - Touched records queue: ------------ {} B
          - Touched records hashset: ---------- {} B
          - Touched records data: ------------- {} B
          - Tree root history queue: ---------- {} B
          - Prefix list ----------------------- {} B
          
        Data overhead total: ------------------ {} B
          - Merkle tree (serialized) ---------- {} B
        
        Total memory: ------------------------- {} B",
            o_sum_data_independent,
            self.o_h_tree,
            self.o_touches_queue,
            self.o_touches_hashset,
            self.o_touches_data,
            self.o_history_queue,
            self.o_prefix_list,
            o_sum_data_dependent,
            self.o_tree_serialized,
            o_sum_data_independent + self.o_tree_serialized
        )
    }
}

impl MemoryReport {
    pub fn new(htree: &HTree) -> Self {
        let o_h_tree = mem::size_of::<HTree>();
        let mut o_touches_queue = 0;
        for k in &htree.touches {
            o_touches_queue += k.len() * mem::size_of::<Arc<RecordID>>();
        }
        let o_touches_hashset =
            &htree.counts.len() * mem::size_of::<Arc<RecordID>>();
        let mut o_touches_data = 0;
        for k in &htree.counts {
            o_touches_data += (**k).len();
        }
        let o_history_queue = &htree.history.len() * mem::size_of::<Digest>();
        let o_prefix_list = &htree.prefix_list.len() * mem::size_of::<Prefix>();

        let o_tree_serialized = bincode::serialize(&htree.tree).unwrap().len();

        MemoryReport {
            o_h_tree,
            o_touches_queue,
            o_touches_hashset,
            o_touches_data,
            o_history_queue,
            o_prefix_list,
            o_tree_serialized,
        }
    }
}
