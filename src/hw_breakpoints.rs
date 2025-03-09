#[derive(Debug,Clone,Copy,Eq,PartialEq,Hash)]
pub enum HwBreakpointMode{
    Exec,
    Write,
    ReadWrite,
}

impl HwBreakpointMode{
    pub fn bits(&self) -> u64{
        match self {
            Self::Exec => 0b00,
            Self::Write => 0b01,
            Self::ReadWrite => 0b11,
        }
    }
}

#[derive(Debug,Clone,Copy,Eq,PartialEq,Hash)]
pub struct HwBreakpoint{
    pub addr: u64,
    pub size: usize,
    pub mode: HwBreakpointMode
}

impl HwBreakpoint{
    pub fn apply_dr7(&self, bp_index: usize, dr7: u64) -> u64{
        assert!(bp_index< 4);
        const L : usize = 0;
        const G : usize = 1;
        const RW : usize = 16; // & 17
        const LEN : usize = 18; // & 19
        let mask = (1<<L | 1 << G) << (bp_index * 2) | ((3 << RW | 3<< LEN) << bp_index*4);
        let dr7 = dr7 & !(mask<<bp_index);
        let dr7 = dr7 | ((1<<L | 1<<G ) << bp_index*2 )| (self.mode.bits() << RW | self.size_bits()<<LEN)<<bp_index*4;
        const LE_AND_LG : usize = 8; // &9
        let dr7 = dr7 | 0b11 << LE_AND_LG; // LE and LG are set unconditionally
        return dr7;
    }
    pub fn size_bits(&self) -> u64{
        return match self.size {
            1 => 0b00,
            2 => 0b01,
            4 => 0b11,
            8 => 0b10,
            _ => panic!("invalid hw breakpoint size")
        }
    }
}

pub struct HwBreakpoints{
    pub bps: [Option<HwBreakpoint>; 4],
}

impl HwBreakpoints {
    pub fn new() -> Self{
        return Self{bps: [None, None, None, None]}
    }
    pub fn enable(&mut self, i: usize, addr: u64, size: usize, mode: HwBreakpointMode) {
        if mode == HwBreakpointMode::Exec {
            assert_eq!(size,1);
        }
        self.bps[i] = Some(HwBreakpoint{addr, size, mode})
    }
    pub fn enable_access(&mut self, i: usize, addr: u64, size: usize){
        self.enable(i, addr, size, HwBreakpointMode::ReadWrite);
    }
    pub fn enable_write(&mut self, i: usize, addr: u64, size: usize){
        self.enable(i, addr, size, HwBreakpointMode::Write);
    }
    pub fn enable_exec(&mut self, i: usize, addr: u64){
        self.enable(i, addr, 1, HwBreakpointMode::Exec);
    }

    pub fn disable(&mut self, i: usize) {
        self.bps[i] = None;
    }
    pub fn addr(&self, i: usize) -> u64 {
        if let Some(ref bp) = self.bps[i]{
            return bp.addr
        }
        return 0;
    }
    pub fn compute_dr7(&self) -> u64 {
        let mut dr7 = 0;
        for i in 0..4 {
            if let Some(ref bp) = self.bps[i]{
                dr7 = bp.apply_dr7(i, dr7);
            }
        }
        return dr7;
    }

    pub fn any_active(&self) -> bool {
        self.bps.iter().any(|b| b.is_some())
    }
}
