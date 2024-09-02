use std::sync::atomic::Ordering;

use vmm::{vstate::memory::{Bytes, GuestAddress, GuestMemoryMmap}, Vmm};


pub const M_PAGE_ALIGN: u64 = 0xffff_ffff_ffff_f000;
pub const M_PAGE_OFFSET: u64 = 0xfff;
pub const M_PTE_OFFSET: u64 = 0x1ff;
pub const M_PTE_PADDR: u64 = 0x000f_ffff_ffff_f000;
pub const PAGE_SIZE: u64 = 0x1000;
pub const BIT_PTE_PRESENT: u64 = 1;

pub fn read_phys_u64(mem: &GuestMemoryMmap, paddr: u64) -> u64 {
    assert!(paddr&M_PAGE_OFFSET <= PAGE_SIZE-(std::mem::size_of::<u64>() as u64));
    return mem.load(GuestAddress(paddr), Ordering::Relaxed).unwrap();
}

pub fn read_phys_u8(mem: &GuestMemoryMmap, paddr: u64) -> u64 {
    return mem.load(GuestAddress(paddr), Ordering::Relaxed).unwrap();
}

fn read_page_table_entry(mem: &GuestMemoryMmap, paddr: u64, offset: u64) -> u64{
    let entry = read_phys_u64(mem, paddr+ offset*8);
    println!("Got entry {:x} at {:x}+8*{:x}", entry, paddr, offset);
    return entry & M_PTE_PADDR;
}

pub fn resolve_addr(mem: &GuestMemoryMmap, cr3: u64, vaddr: u64) -> u64 {
    let mask = M_PAGE_ALIGN;
    let pml4_addr = read_page_table_entry(mem, cr3&mask ,   (vaddr >> 39) & M_PTE_OFFSET);
    let pdp_addr =  read_page_table_entry(mem, pml4_addr,   (vaddr >> 30) & M_PTE_OFFSET);
    let pd_addr =   read_page_table_entry(mem, pdp_addr ,   (vaddr >> 21) & M_PTE_OFFSET);
    let pt_addr =   read_page_table_entry(mem, pd_addr  ,   (vaddr >> 12) & M_PTE_OFFSET);
    let addr =      pt_addr + ((vaddr >>  0) & M_PAGE_OFFSET);
    return addr;
}

pub fn walk_page_tables(mem: &GuestMemoryMmap, cr3: u64, start:u64, end: u64) -> PageTableWalker{
    PageTableWalker::new(mem, cr3, start, end)
}


pub struct PageTableWalker<'mem>{
    mem: &'mem GuestMemoryMmap,
    end: u64,
    cr3: u64,
    pml4_offset: u64,
    pdp_offset: u64,
    pd_offset: u64,
    pt_offset: u64,
    pdp_base: u64,
    pd_base: u64,
    pt_base: u64,
    vaddr: u64,
}

impl<'mem> PageTableWalker<'mem>{
    pub fn new(mem: &'mem GuestMemoryMmap, cr3: u64, start: u64, end: u64) -> Self {
        assert!(start<=end);
        let pml4_offset = (start >> 39) & M_PTE_OFFSET;
        let pdp_offset =  (start >> 30) & M_PTE_OFFSET;
        let pd_offset =   (start >> 21) & M_PTE_OFFSET;
        let pt_offset =   (start >> 12) & M_PTE_OFFSET;
        let mut res = Self{
            mem,
            end,
            cr3,
            pml4_offset,
            pdp_offset,
            pd_offset,
            pt_offset,
            pdp_base :0,
            pd_base: 0,
            pt_base: 0,
            vaddr: start&M_PAGE_ALIGN,
        };
        res.update_pdp_base();
        res.update_pd_base();
        res.update_pt_base();
        return res;
    }

    fn update_pdp_base(&mut self){
        self.pdp_base = read_page_table_entry(self.mem, self.cr3&M_PAGE_ALIGN, self.pml4_offset);
    }
    fn update_pd_base(&mut self){
        self.pd_base = read_page_table_entry(self.mem, self.pdp_base,   self.pdp_offset);
    }
    fn update_pt_base(&mut self){
        self.pt_base = read_page_table_entry(self.mem, self.pd_base,   self.pd_offset);
    }
}

impl<'vmm> Iterator for PageTableWalker<'vmm>{
    type Item = (u64, GuestAddress);
    fn next(&mut self) -> Option<Self::Item>{
        if self.vaddr >= self.end {
            return None;
        }
        let res_vaddr = self.vaddr;
        let res_paddr = GuestAddress(read_page_table_entry(self.mem, self.pt_base, self.pt_offset));
        self.vaddr += 0x1000;
        self.pt_offset += 1;
        if self.pt_offset >= 0x1ff {
            self.pt_offset = 0;
            self.pd_offset += 1;
            if self.pd_offset >= 0x1ff {
                self.pd_offset = 0;
                self.pdp_offset += 1;
                if self.pdp_offset >= 0x1ff {
                    self.pdp_offset = 0;
                    self.pml4_offset += 1;
                    self.update_pdp_base();
                }
                self.update_pd_base();
            }
            self.update_pt_base();
        }
        return Some((res_vaddr, res_paddr))
    } 
}

#[cfg(test)]
mod tests {
    use vmm::{vmm_config::machine_config::HugePageConfig, vstate::memory::GuestMemoryExtension};

    use super::*;

    #[test]
    fn test_resolve_address() {
        let page_size = PAGE_SIZE as usize;

        let region_1_address = GuestAddress(0);
        let region_2_address = GuestAddress(PAGE_SIZE*8);
        let mem_regions = [
            (region_1_address, page_size*8),
            (region_2_address, page_size*8),
        ];
        let mem =
            GuestMemoryMmap::from_raw_regions(&mem_regions, true, HugePageConfig::None).unwrap();
        println!("Testing on {:#?}", mem.describe());
        let fake_cr3 = PAGE_SIZE*8;
        let vaddr = 0x400000;
        //let pml4_addr = read_page_table_entry(mem, cr3&mask ,   (vaddr >> 39) & M_PTE_OFFSET);
        //let pdp_addr =  read_page_table_entry(mem, pml4_addr,   (vaddr >> 30) & M_PTE_OFFSET);
        //let pd_addr =   read_page_table_entry(mem, pdp_addr ,   (vaddr >> 21) & M_PTE_OFFSET);
        //let pt_addr =   read_page_table_entry(mem, pd_addr  ,   (vaddr >> 12) & M_PTE_OFFSET);
        let l1_addr = fake_cr3 + PAGE_SIZE;
        println!("l1: 0x{:x}", l1_addr);
        let l2_addr = fake_cr3 + PAGE_SIZE*2;
        let l3_addr = fake_cr3 + PAGE_SIZE*3;
        let target_1 = PAGE_SIZE;
        let target_2 = PAGE_SIZE*3;
        let target_3 = PAGE_SIZE*5;

        store(&mem, l1_addr | BIT_PTE_PRESENT, GuestAddress(fake_cr3 + 8*((vaddr >> 39)&M_PTE_OFFSET)));
        store(&mem, l2_addr | BIT_PTE_PRESENT, GuestAddress(l1_addr +  8*((vaddr >> 30)&M_PTE_OFFSET)));
        store(&mem, l3_addr | BIT_PTE_PRESENT, GuestAddress(l2_addr +  8*((vaddr >> 21)&M_PTE_OFFSET)));
        store(&mem, target_1| BIT_PTE_PRESENT, GuestAddress(l3_addr +  8*(((vaddr+0*PAGE_SIZE) >> 12)&M_PTE_OFFSET)));
        store(&mem, target_2| BIT_PTE_PRESENT, GuestAddress(l3_addr +  8*(((vaddr+1*PAGE_SIZE) >> 12)&M_PTE_OFFSET)));
        store(&mem, target_3| BIT_PTE_PRESENT, GuestAddress(l3_addr +  8*(((vaddr+2*PAGE_SIZE) >> 12)&M_PTE_OFFSET)));
        println!("resolve: {:x} vs target: {:x}", resolve_addr(&mem, fake_cr3, vaddr), target);
        assert_eq!(resolve_addr(&mem, fake_cr3, vaddr), target);
        let walk = walk_page_tables(&mem, fake_cr3, vaddr, vaddr+PAGE_SIZE*3).collect::<Vec<_>>();
        assert_eq!(walk, vec![
            (vaddr+0*PAGE_SIZE, GuestAddress(target_1)), 
            (vaddr+1*PAGE_SIZE, GuestAddress(target_2)),
            (vaddr+2*PAGE_SIZE, GuestAddress(target_3)),
            ]);
    }

    fn test_walk_past_boundary(){

    }

    fn store(mem: &GuestMemoryMmap, val: u64, addr: GuestAddress){
        println!("Storing 0x{:x} at phys 0x{:x}", val, addr.0);
        mem.store(val, addr, Ordering::Relaxed).unwrap();
    }
}