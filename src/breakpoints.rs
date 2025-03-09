use std::collections::BTreeMap;

use vmm::Vmm;

use crate::mem::NyxMemExtension;

pub struct Breakpoint{
    pub cr3: u64,
    pub vaddr: u64,
    pub orig_val: Option<u8>
}

impl Breakpoint {
    pub fn new(cr3: u64, vaddr: u64) -> Self{
        return Self{cr3, vaddr, orig_val: None}
    }
}

// A trait so users can define their own logic for deciding which breakpoints to handle.
pub trait BreakpointManagerTrait{
    // should we forward the current breakpoint to the guest rather than handle it ourselfs?
    fn known_breakpoint(&self, cr3: u64, rip: u64) -> bool;
    fn disable_all_breakpoints(&mut self, vmm: &mut Vmm);
    fn enable_all_breakpoints(&mut self, vmm: &mut Vmm);
    fn add_breakpoint(&mut self, cr3: u64, vaddr: u64);
    fn remove_breakpoint(&mut self, cr3: u64, vaddr: u64);
    fn remove_all_breakpoints(&mut self);

    fn forward_guest_bp(&self, cr3: u64, rip: u64) -> bool {
        return !self.known_breakpoint(cr3, rip);
    }
}

pub struct BreakpointManager{
    pub breakpoints: BTreeMap<(u64,u64), Breakpoint>,
}

impl BreakpointManager{
    pub fn new() -> Self{
        return Self{breakpoints: BTreeMap::new()}
    }
}

impl BreakpointManagerTrait for BreakpointManager{
    fn known_breakpoint(&self, cr3: u64, rip: u64) -> bool {
        let known_bp = self.breakpoints.contains_key(&(cr3, rip));
        return known_bp;
    }
    fn disable_all_breakpoints(&mut self, vmm: &mut Vmm){
        for bp in self.breakpoints.values_mut(){
            vmm.write_virtual_u8(bp.cr3, bp.vaddr, bp.orig_val.unwrap()).unwrap();
        }
    }
    fn enable_all_breakpoints(&mut self, vmm: &mut Vmm){
        for bp in self.breakpoints.values_mut(){
            bp.orig_val = Some(vmm.read_virtual_u8(bp.cr3, bp.vaddr).unwrap());
            vmm.write_virtual_u8(bp.cr3, bp.vaddr, 0xcc).unwrap();
        }
    }

    fn add_breakpoint(&mut self, cr3: u64, vaddr: u64) {
        let breakpoint = Breakpoint::new(cr3, vaddr);
        self.breakpoints.insert((cr3,vaddr), breakpoint);
    }

    fn remove_breakpoint(&mut self, cr3: u64, vaddr: u64) {
        self.breakpoints.remove(&(cr3,vaddr));
    }
    fn remove_all_breakpoints(&mut self) {
       self.breakpoints.clear(); 
    }
}
