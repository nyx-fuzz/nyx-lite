use core::fmt;
use std::{iter::Peekable, marker::PhantomData, ops::Range, sync::atomic::Ordering};

use vmm::vstate::memory::{Address, AtomicBitmap, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion, GuestRegionMmap, MemoryRegionAddress};
use vm_memory::{GuestUsize, VolatileSlice};
use vm_memory::bitmap::{Bitmap, BS, MS};
use crate::error::MemoryError;


pub const M_PAGE_ALIGN: u64 = 0xffff_ffff_ffff_f000;
pub const M_PAGE_OFFSET: u64 = 0xfff;
pub const FRAMES_PER_PAGE_TABLE: u64 = 0x1ff;
pub const M_PTE_OFFSET: u64 = FRAMES_PER_PAGE_TABLE;
pub const M_PTE_PADDR: u64 = 0x000f_ffff_ffff_f000;
pub const PAGE_SIZE: u64 = 0x1000;
pub const BIT_PTE_PRESENT: u64 = 1;

pub fn read_phys_u64(mem: &GuestMemoryMmap, paddr: u64) -> Result<u64, MemoryError> {
    assert!(paddr&M_PAGE_OFFSET <= PAGE_SIZE-(std::mem::size_of::<u64>() as u64));
    return mem.load(GuestAddress(paddr), Ordering::Relaxed).map_err(|_| MemoryError::CantAccessPhysicalPage(GuestAddress(paddr)));
}

pub fn read_phys_u8(mem: &GuestMemoryMmap, paddr: u64) -> u64 {
    return mem.load(GuestAddress(paddr), Ordering::Relaxed).unwrap();
}

fn read_page_table_entry(mem: &GuestMemoryMmap, paddr: u64, offset: u64) -> Result<u64, MemoryError>{
    let entry = read_phys_u64(mem, paddr+ offset*8)?;
    if (entry & BIT_PTE_PRESENT)!= 0{
        return Ok(entry&M_PTE_PADDR);
    }
    return Err(MemoryError::PageNotPresent(GuestAddress(paddr), offset));
}

pub fn resolve_addr(mem: &GuestMemoryMmap, cr3: u64, vaddr: u64) -> Result<u64, MemoryError> {
    let mask = M_PAGE_ALIGN;
    let(l1, l2, l3, l4, offset) = split_vaddr(vaddr);
    let pml4_addr = read_page_table_entry(mem, cr3&mask , l1)?;
    let pdp_addr =  read_page_table_entry(mem, pml4_addr, l2)?;
    let pd_addr =   read_page_table_entry(mem, pdp_addr , l3)?;
    let pt_addr =   read_page_table_entry(mem, pd_addr  , l4)?;
    let addr =      pt_addr + offset;
    return Ok(addr);
}

// Primary function to walk virtual address spaces. Will merge all adjacent
// unmapped/incalid pages & only return leave nodes of the page tables
pub fn walk_virtual_pages<'mem>(mem: &'mem GuestMemoryMmap, cr3: u64, start:u64, last_page: u64) -> impl Iterator<Item=PTE>+'mem{
    MergedPTEWalker::new(PTEWalker::new(mem, cr3, start, last_page).filter(|pte| pte.level==3))
}

// walks the page tables between start and end. Note: End is inclusive, not
// exclusive. I.e. the last page will be starting at end. Will return all node
// in the page tables (including not-presen & invalid phys address nodes)
pub fn walk_page_tables(mem: &GuestMemoryMmap, cr3: u64, start:u64, last_page: u64) -> PTEWalker{
    PTEWalker::new(mem, cr3, start, last_page)
}

pub fn walk_page_tables_merged<'mem>(mem: &'mem GuestMemoryMmap, cr3: u64, start: u64, last_page: u64) -> MergedPTEWalker<'mem, PTEWalker<'mem>>{
    MergedPTEWalker::new(PTEWalker::new(mem, cr3, start, last_page))
}


pub fn split_vaddr(vaddr: u64) -> (u64, u64, u64, u64, u64){
    let l1 = (vaddr >> 39) & M_PTE_OFFSET;
    let l2 = (vaddr >> 30) & M_PTE_OFFSET;
    let l3 = (vaddr >> 21) & M_PTE_OFFSET;
    let l4 = (vaddr >> 12) & M_PTE_OFFSET;
    let addr = (vaddr >>  0) & M_PAGE_OFFSET;
    return (l1,l2,l3,l4, addr);
}

pub fn join_vaddr(l1: u64, l2: u64, l3: u64, l4: u64, offset: u64) -> u64 {
    let l1= (l1 & M_PTE_OFFSET) << 39;
    let l2 = (l2 & M_PTE_OFFSET) << 30;
    let l3 = (l3 & M_PTE_OFFSET) << 21;
    let l4 = (l4 & M_PTE_OFFSET) << 12;
    return l1 | l2 | l3 | l4 | (offset & M_PAGE_OFFSET);
}
pub struct PTE{
    pub vaddrs: Range<u64>, 
    pub val: u64,
    pub level: u8,
    pub missing_page: bool,
}

impl<'mem> core::fmt::Debug for PTE {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("PTE")
            .field("level", &self.level)
            .field("val", &format_args!("{:X?}", self.val))
            .field("vaddrs", &format_args!("{:X?}", self.vaddrs))
            .finish()
    }
}

impl PTE{
    pub fn present(&self) -> bool {
        (self.val & BIT_PTE_PRESENT) != 0
    }
    pub fn phys_addr(&self) -> GuestAddress {
        GuestAddress(self.val & M_PTE_PADDR)
    }
    pub fn missing_page(&self) -> bool {
        self.missing_page
    }

    fn merge_with(&mut self, other: &PTE) -> bool {
        let same_level = self.level == other.level;
        let adjacent = self.vaddrs.end == other.vaddrs.start;
        if self.present() || !same_level || !adjacent {
            return false;
        }
        let both_missing_page = self.missing_page() && other.missing_page();
        let both_not_present = !self.present() && !other.present();
        if both_missing_page || both_not_present {
            self.vaddrs.end = other.vaddrs.end;
            return true;
        }
        return false
    }
}


pub struct PTEWalker<'mem>{
    mem: &'mem GuestMemoryMmap,
    offsets: [u64; 4],
    bases: [u64; 4],
    last_page: u64,
    level: usize,
}

impl<'mem> core::fmt::Debug for PTEWalker<'mem> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("PTEWalker")
            .field("level", &self.level)
            .field("offsets", &format_args!("{:?}", self.offsets))
            .field("bases", &format_args!("{:X?}", self.bases))
            .field("last_page", &format_args!("{:X?}", self.last_page))
            .finish()
    }
}



impl<'mem> Iterator for PTEWalker<'mem>{
    type Item = PTE;
    fn next(&mut self) -> Option<Self::Item>{
        let res = self.iter_next();
        return res;
    }
}

impl<'mem> PTEWalker<'mem>{

    pub fn new(mem: &'mem GuestMemoryMmap, cr3: u64, start: u64, last_page: u64) -> Self{
        let (l1, l2, l3, l4, offset) = split_vaddr(start);
        assert_eq!(offset,0);
        Self{
            mem,
            offsets: [l1,l2,l3,l4],
            bases: [cr3, 0,0,0],
            level: 0,
            last_page
        }
    }

    fn get_cur_pte(&self) -> PTE {
        let vaddrs = self.make_vaddr_range();
        let level = self.level.try_into().unwrap();
        let base = self.bases[self.level];
        let offset = self.offsets[self.level];
        if let Ok(val) = read_phys_u64(self.mem, base+ offset*8){
            PTE{vaddrs, val, level, missing_page: false}
        } else {
            PTE{vaddrs, val: 0, level, missing_page: true}
        }
    }

    fn advance_cursor_up(&mut self){
        loop {
            let cur = &mut self.offsets[self.level];
            *cur +=1;
            if *cur >= 0x1ff {
                if self.level == 0 {return;}
                *cur = 0;
                self.level-=1;
            } else{
                return;
            }
        }
    }

    fn advance_cursor_down(&mut self, new_base_addr: u64){
        assert_eq!(new_base_addr & M_PAGE_OFFSET, 0);
        self.level +=1;
        //This should be imlied as advance_cursor_up set's the offset[cur] to 0 before going up one level.
        //If we don't do this explicitly, we can initialliza the level to 0 and the offsets to a given vaddr to start iterating from that given vaddr
        //self.offsets[self.level]=0; 
        self.bases[self.level]=new_base_addr;
    }

    fn make_vaddr_range(&self) -> Range<u64>{
        let l1 = self.offsets[0];
        let l2 = if self.level >= 1 {self.offsets[1]} else {0};
        let l3 = if self.level >= 2 {self.offsets[2]} else {0};
        let l4 = if self.level >= 3 {self.offsets[3]} else {0};
        let start = join_vaddr(l1, l2, l3, l4, 0);
        let size = [PAGE_SIZE*512*512*512, PAGE_SIZE*512*512,PAGE_SIZE*512, PAGE_SIZE][self.level];
        start..start+size
    }

    fn iter_next(&mut self) -> Option<PTE>{
        if self.offsets[0]>=0x1ff{
            return None;
        }
        let res = self.get_cur_pte();
        if res.vaddrs.start > self.last_page {
            return None;
        }
        if res.present() && self.level < 3 {
            self.advance_cursor_down(res.phys_addr().0);
        }else{
            self.advance_cursor_up();
        }
        return Some(res);
    }
}

pub struct MergedPTEWalker<'mem, PTEIter: Iterator<Item = PTE>+'mem>
{
    inner: Peekable<PTEIter>,
    _phantom: PhantomData<&'mem PTEIter>
}

impl<'mem, BaseIter: Iterator<Item=PTE>> MergedPTEWalker<'mem, BaseIter> {
    pub fn new(iter: BaseIter) -> Self{
        let inner = iter.peekable();
        Self{inner, _phantom: PhantomData}
    }
}

impl<'mem, BaseIter: Iterator<Item=PTE>> Iterator for MergedPTEWalker<'mem, BaseIter>{
    type Item = PTE;
    fn next(&mut self) -> Option<Self::Item>{
        let mut cur = self.inner.next()?;
        while let Some(next) = self.inner.peek() { 
            println!("merging cur {:?} with {:?}", cur, next);
            if !cur.merge_with(next){
                println!("couldn't merge, break");
                break;
            }
            self.inner.next();
        }
        return Some(cur);
    }
}


pub struct VirtMappedRange{
    cr3: u64,
    start: u64,
    end: u64,
    tlb: Vec<GuestAddress>
}

impl VirtMappedRange{
    pub fn new(cr3: u64, start:u64, end:u64) -> Self{
        assert!(end >= start);
        assert!(start & M_PAGE_OFFSET == 0);
        assert!(end & M_PAGE_OFFSET == 0);
        Self{cr3, start, end, tlb: vec![]}
    }

    pub fn validate(&mut self, mem: &GuestMemoryMmap) -> Result<(), MemoryError> {
        self.tlb.reserve(((self.end-self.start) / PAGE_SIZE).try_into().unwrap());
        self.tlb.clear();
        for pte in walk_virtual_pages(mem, self.cr3, self.start & M_PAGE_OFFSET, self.end & M_PAGE_OFFSET){
            if !pte.present() {
                return Err(MemoryError::PageNotPresent(pte.phys_addr(), pte.vaddrs.start));
            }
            if !pte.missing_page() {
                return Err(MemoryError::CantAccessPhysicalPage(pte.phys_addr()));
            }
            self.tlb.push(pte.phys_addr());
        }
        return Ok(())
    }

    pub fn iter<'mem>(&'mem mut self, mem: &'mem GuestMemoryMmap) -> 
        impl Iterator<Item = (u64, VolatileSlice<'mem, BS<<GuestRegionMmap as GuestMemoryRegion>::B>>) > + 'mem {
        self.tlb.iter().enumerate().map(|(i, guest_phys_addr)| {
        if let Some(region) = mem.find_region(*guest_phys_addr) {
           let start = region.to_region_addr(*guest_phys_addr).unwrap();
           let cap = region.len() - start.raw_value();
           let len = std::cmp::min(cap, PAGE_SIZE as GuestUsize);
           assert_eq!(len, PAGE_SIZE as GuestUsize);
           let volatile_slice = region.as_volatile_slice().unwrap();
           return (self.start+(i as u64)*PAGE_SIZE, volatile_slice)
        }
        panic!("couldn't access memory for cr3: {:x}, addr: {:x} - region for physical {:x} not found ", 
        self.cr3, 
        self.start + (i as u64) * PAGE_SIZE, 
        guest_phys_addr.raw_value());
    })
}
}

#[cfg(test)]
mod tests {
    
    use std::collections::HashSet;

    use vmm::{vmm_config::machine_config::HugePageConfig, vstate::memory::{GuestMemory, GuestMemoryExtension, GuestMemoryRegion}};

    use super::*;

    #[test]
    fn test_resolve_address() {
        let mem = make_mem();
        let fake_cr3 = PAGE_SIZE*8;
        let vaddr = 0x400000;
        let l1_addr = fake_cr3 + PAGE_SIZE;
        let l2_addr = fake_cr3 + PAGE_SIZE*2;
        let l3_addr = fake_cr3 + PAGE_SIZE*3;
        let target_1 = PAGE_SIZE;
        let target_2 = PAGE_SIZE*3;
        let target_3 = PAGE_SIZE*5;

        store(&mem,  GuestAddress(fake_cr3 + 8*((vaddr >> 39)&M_PTE_OFFSET              )), l1_addr | BIT_PTE_PRESENT);
        store(&mem,  GuestAddress(l1_addr +  8*((vaddr >> 30)&M_PTE_OFFSET              )), l2_addr | BIT_PTE_PRESENT);
        store(&mem,  GuestAddress(l2_addr +  8*((vaddr >> 21)&M_PTE_OFFSET              )), l3_addr | BIT_PTE_PRESENT);
        store(&mem,  GuestAddress(l3_addr +  8*(((vaddr+0*PAGE_SIZE) >> 12)&M_PTE_OFFSET)), target_1| BIT_PTE_PRESENT);
        store(&mem,  GuestAddress(l3_addr +  8*(((vaddr+1*PAGE_SIZE) >> 12)&M_PTE_OFFSET)), target_2| BIT_PTE_PRESENT);
        store(&mem,  GuestAddress(l3_addr +  8*(((vaddr+2*PAGE_SIZE) >> 12)&M_PTE_OFFSET)), target_3| BIT_PTE_PRESENT);
        assert_eq!(resolve_addr(&mem, fake_cr3, vaddr).unwrap(), target_1);
        let walk = walk_virtual_pages(&mem, fake_cr3, vaddr, vaddr+PAGE_SIZE*2).map(|pte| (pte.vaddrs.start, pte.phys_addr()) ).collect::<Vec<_>>();
        assert_eq!(walk, vec![
            (vaddr+0*PAGE_SIZE, GuestAddress(target_1)), 
            (vaddr+1*PAGE_SIZE, GuestAddress(target_2)),
            (vaddr+2*PAGE_SIZE, GuestAddress(target_3)),
            ]);
    }

    #[test]
    fn test_make_pages(){
        let mem = make_mem();
        let mut allocated_pages = HashSet::new();
        let cr3 = PAGE_SIZE*8;
        allocated_pages.insert(cr3);
        let t1 = make_vpage(&mem, cr3, 0x41000, &mut allocated_pages);
        let t2 = make_vpage(&mem, cr3, 0x42000, &mut allocated_pages);
        let t3 = make_vpage(&mem, cr3, 0x43000, &mut allocated_pages);

        assert_eq!(resolve_addr(&mem, cr3, 0x41000).unwrap(), t1.0);
        assert_eq!(resolve_addr(&mem, cr3, 0x42000).unwrap(), t2.0);
        assert_eq!(resolve_addr(&mem, cr3, 0x43000).unwrap(), t3.0);
        let walk = walk_virtual_pages(&mem, cr3, 0x41000, 0x41000+PAGE_SIZE*2).map(|pte| (pte.vaddrs.start, pte.phys_addr())).collect::<Vec<_>>();
        assert_eq!(walk, vec![
            (0x41000+0*PAGE_SIZE, t1), 
            (0x41000+1*PAGE_SIZE, t2),
            (0x41000+2*PAGE_SIZE, t3),
            ]);
    }

    #[test]
    fn test_walk_past_boundary(){
        let mem = make_mem();
        let mut allocated_pages = HashSet::new();
        let cr3 = PAGE_SIZE*8;
        allocated_pages.insert(cr3);
        let boundary = 0x8000000000;
        let t1 = make_vpage(&mem, cr3, boundary-PAGE_SIZE, &mut allocated_pages);
        let t2 = make_vpage(&mem, cr3, boundary,           &mut allocated_pages);
        let t3 = make_vpage(&mem, cr3, boundary+PAGE_SIZE, &mut allocated_pages);
        let walk = walk_virtual_pages(&mem, cr3, boundary-PAGE_SIZE, boundary+PAGE_SIZE).map(|pte| (pte.vaddrs.start, pte.phys_addr())).collect::<Vec<_>>();
        assert_eq!(walk, vec![
            (boundary-PAGE_SIZE, t1), 
            (boundary          , t2),
            (boundary+PAGE_SIZE, t3),
            ]);
    }

    #[test]
    fn test_walk_missing_page(){
        let mem = make_mem();
        let mut allocated_pages = HashSet::new();
        let cr3 = PAGE_SIZE*8;
        allocated_pages.insert(cr3);
        let boundary = 0x8000000000;
        let t1 = make_vpage(&mem, cr3, boundary-PAGE_SIZE, &mut allocated_pages);
        // t2 is missing
        let t3 = make_vpage(&mem, cr3, boundary+PAGE_SIZE, &mut allocated_pages);
        let walk = walk_virtual_pages(&mem, cr3, boundary-PAGE_SIZE, boundary+3*PAGE_SIZE).map(|pte| (pte.vaddrs.start, pte.phys_addr(), pte.present(), pte.missing_page())).collect::<Vec<_>>();
        assert_eq!(walk, vec![
            (boundary-PAGE_SIZE, t1, true, false), 
            (boundary, GuestAddress(0), false, false), 
            (boundary+PAGE_SIZE, t3, true, false), 
            (boundary+PAGE_SIZE*2, GuestAddress(0), false, false), 
            ]);
    }

    #[test]
    fn test_pte_walker(){
        let mem = make_mem();
        let mut allocated_pages = HashSet::new();
        let cr3 = PAGE_SIZE*8;
        allocated_pages.insert(cr3);
        let boundary = 0x8000000000;
        let t1 = make_vpage(&mem, cr3, boundary-PAGE_SIZE, &mut allocated_pages);
        let t2 = make_vpage(&mem, cr3, boundary,           &mut allocated_pages);
        let t3 = make_vpage(&mem, cr3, boundary+PAGE_SIZE, &mut allocated_pages);
        let last_page = 0xffffffff_ffffffff;
        let walk = PTEWalker::new(&mem, cr3, boundary-PAGE_SIZE, last_page )
            .filter(|i| i.present())
            .map(|i| (i.level, i.vaddrs))
            .collect::<Vec<_>>();
        let expected = [
            (0, 0x0..0x8000000000), 
            (1, 0x7fc0000000..0x8000000000), 
            (2, 0x7fffe00000..0x8000000000), 
            (3, 0x7ffffff000..0x8000000000),
            (0, 0x8000000000..0x10000000000), 
            (1, 0x8000000000..0x8040000000), 
            (2, 0x8000000000..0x8000200000), 
            (3, 0x8000000000..0x8000001000), 
            (3, 0x8000001000..0x8000002000)
        ];
        assert_eq!(walk, expected);

        let walk = PTEWalker::new(&mem, cr3, boundary-PAGE_SIZE, boundary+PAGE_SIZE)
            .filter(|i| i.level==3 && i.present())
            .map(|i| (i.level, i.vaddrs.start, i.phys_addr()))
            .collect::<Vec<_>>();
        let expected = [
            (3, 0x7ffffff000, t1),
            (3, 0x8000000000, t2), 
            (3, 0x8000001000, t3)
        ];
        assert_eq!(walk, expected);
    }

  #[test]
    fn test_ptr_walker_missing_page(){
        let mem = make_mem();
        let mut allocated_pages = HashSet::new();
        let cr3 = PAGE_SIZE*8;
        allocated_pages.insert(cr3);
        let boundary = 0x8000000000;
        let t1 = make_vpage(&mem, cr3, boundary-PAGE_SIZE, &mut allocated_pages);
        // t2 is missing
        let t3 = make_vpage(&mem, cr3, boundary+PAGE_SIZE, &mut allocated_pages);

        let walk = PTEWalker::new(&mem, cr3, boundary-PAGE_SIZE, boundary+PAGE_SIZE)
            .filter(|i| i.level==3 && i.present())
            .map(|i| (i.level, i.vaddrs.start, i.phys_addr()))
            .collect::<Vec<_>>();
        let expected = [
            (3, 0x7ffffff000, t1),
            (3, 0x8000001000, t3)
        ];
        assert_eq!(walk, expected);
    }

  #[test]
    fn test_ptr_walker_missing_page_table(){
        let mem = make_mem();
        let mut allocated_pages = HashSet::new();
        let cr3 = PAGE_SIZE*8;
        allocated_pages.insert(cr3);
        let boundary = 0x8000000000;
        let t1 = make_vpage(&mem, cr3, boundary-PAGE_SIZE, &mut allocated_pages);
        //t2 and t3 are later invalidating by breaking the page table entry
        let _t2 = make_vpage(&mem, cr3, boundary,           &mut allocated_pages);
        let _t3 = make_vpage(&mem, cr3, boundary+PAGE_SIZE, &mut allocated_pages);
        let t4 = make_vpage(&mem, cr3, boundary+PAGE_SIZE*512, &mut allocated_pages);

        let (l1,l2,_l3,l4, _offset) = split_vaddr(boundary);
        let b2 = read_page_table_entry(&mem, cr3, l1).unwrap();
        let b3 = read_page_table_entry(&mem, b2, l2).unwrap();
        store_page_table_entry(&mem, GuestAddress(b3), l4, PAGE_SIZE*512); // store invalid pointer in page table

        let walk = PTEWalker::new(&mem, cr3, boundary-PAGE_SIZE, boundary+PAGE_SIZE*512)
            .filter(|i| i.present() || i.missing_page())
            .map(|i| (i.level, i.vaddrs.start, i.phys_addr(), i.missing_page()))
            .collect::<Vec<_>>();

        let mut expected = vec![
            (0, 0, GuestAddress(0x2000), false), 
            (1, 0x7fc0000000, GuestAddress(0x3000), false), 
            (2, 0x7fffe00000, GuestAddress(0x4000), false), 
            (3, 0x7ffffff000, t1 /*GuestAddress(0x1000)*/, false), 
            (0, 0x8000000000, GuestAddress(0x6000), false), 
            (1, 0x8000000000, GuestAddress(0x7000), false), 
            (2, 0x8000000000, GuestAddress(0x200000), false), 
        ];
        let mut missed_pages :Vec<(u8, u64, GuestAddress, bool)> = (boundary..(boundary+PAGE_SIZE*511)).step_by(PAGE_SIZE as usize).map(|addr| (3,addr, GuestAddress(0), true)).collect();
        expected.append(&mut missed_pages);
        expected.append(&mut vec![
            (2, 0x8000200000, GuestAddress(0xc000), false), 
            (3, 0x8000200000, t4, false)
        ]);
        //for (i,(real,expected)) in walk.iter().zip(expected.iter()).enumerate(){
        //    if real != expected {
        //        println!("at {} got {:X?}, expected {:X?}",i, real, expected);
        //        assert!(false);
        //    }
        //}
        assert_eq!(walk.len(), expected.len());
        assert_eq!(walk, expected);
    }

    fn allocate_page(mem: &GuestMemoryMmap, allocated_pages: &mut HashSet<u64>) -> GuestAddress{
        let mut selected_page = 0;
        'outer: for region in mem.iter(){
            for page in (region.start_addr().0 .. region.start_addr().0+(region.size() as u64)).step_by(PAGE_SIZE as usize){
                if page!= 0 && !allocated_pages.contains(&page){
                    selected_page = page;
                    break 'outer;
                }
            }
        }
        assert_ne!(selected_page, 0);
        allocated_pages.insert(selected_page);
        return GuestAddress(selected_page);
    }

    fn get_or_make_page_table_entry(mem: &GuestMemoryMmap, allocated_pages: &mut HashSet<u64>, page_table: GuestAddress, offset: u64) -> GuestAddress{
        if let Err(MemoryError::PageNotPresent(..)) = read_page_table_entry(mem, page_table.0, offset){
            let new_page = allocate_page(mem, allocated_pages);
            store_page_table_entry(mem, page_table, offset, new_page.0);
        }
        let page = read_page_table_entry(mem, page_table.0, offset).unwrap();
        return GuestAddress(page);
    }
    fn make_vpage(mem: &GuestMemoryMmap, cr3: u64, vaddr: u64, allocated_pages: &mut HashSet<u64>) -> GuestAddress {
        let target_page = allocate_page(mem, allocated_pages);
        let (l1, l2, l3, l4, offset) =split_vaddr(vaddr);
        assert_eq!(offset, 0);//page aligned;

        let l2_page = get_or_make_page_table_entry(mem,allocated_pages, GuestAddress(cr3), l1);
        let l3_page = get_or_make_page_table_entry(mem,allocated_pages, l2_page, l2);
        let l4_page = get_or_make_page_table_entry(mem,allocated_pages, l3_page, l3);
        store_page_table_entry(mem, l4_page, l4, target_page.0);
        return target_page;
    }

    fn make_mem() -> GuestMemoryMmap{
        let page_size = PAGE_SIZE as usize;

        let region_1_address = GuestAddress(0);
        let region_2_address = GuestAddress(PAGE_SIZE*8);
        let mem_regions = [
            (region_1_address, page_size*8),
            (region_2_address, page_size*8),
        ];
        let mem =
            GuestMemoryMmap::from_raw_regions(&mem_regions, true, HugePageConfig::None).unwrap();
        return mem;
    }

    fn store(mem: &GuestMemoryMmap, addr: GuestAddress, val: u64){
        mem.store(val, addr, Ordering::Relaxed).unwrap();
    }

    fn store_page_table_entry(mem: &GuestMemoryMmap, paddr: GuestAddress, offset: u64, value: u64) {
        store(mem, GuestAddress(paddr.0 + offset*8), value | BIT_PTE_PRESENT);
    }
}