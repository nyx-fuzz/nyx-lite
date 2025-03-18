use std::{collections::HashMap, sync::Arc};

use vmm::persist::MicrovmState;

use crate::{mem::PAGE_SIZE, vm_continuation_statemachine::VMContinuationState};

#[derive(Debug,Eq,PartialEq, Hash, Clone, Copy)]
pub enum SnapshotType{
    Incremental,
    Base
}
pub enum MemorySnapshot{
    Base(Vec<u8>),
    Incremental(HashMap<u64, Vec<u8>>),
}

impl MemorySnapshot{

    pub fn is_incremental(&self) -> bool {
        matches!(self, Self::Incremental(_))
    }

    pub fn get_page(&self, paddr: usize) -> Option<&[u8]> {
        let end = paddr + PAGE_SIZE as usize;
        match self{
            MemorySnapshot::Base(vec) => { 
                if end <= vec.len() {
                    // Get the slice and convert it into an array
                    Some(vec[paddr..end].try_into().unwrap())
                } else {
                    // Return None if the range is out of bounds
                    None
                }
            },
            MemorySnapshot::Incremental(map) => map.get(&(paddr as u64)).map(|v| v.as_ref())
        }
    }
}

pub struct NyxSnapshot {
    pub parent: Option<Arc<NyxSnapshot>>,
    pub depth: usize, // 0 for root snapshots, n+1 for each child incremental snapshot
    pub memory: MemorySnapshot,
    pub state: MicrovmState,
    pub tsc: u64,
    pub continuation_state: VMContinuationState
}

impl NyxSnapshot{
    pub fn get_page<Callback>(&self, paddr: usize, mut callback: Callback) where Callback: FnMut(&[u8; PAGE_SIZE as usize]){
        if let Some(page) = self.memory.get_page(paddr) {
            return callback(page.try_into().unwrap());
        }
        assert!(self.memory.is_incremental());
        assert!(self.parent.is_some());
        self.parent.as_ref().expect("Incremental Snapshots should always have a parent").get_page(paddr, callback)
    }

    pub fn iter_delta(&self) -> impl Iterator<Item = (u64, &Vec<u8>)> {
       if let MemorySnapshot::Incremental(ref map) = self.memory {
        return map.iter().map(|(p,s)| (*p,s))
       }
       panic!("can't iter delta on a root snapshot");
    }
}
