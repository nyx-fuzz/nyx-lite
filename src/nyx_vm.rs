use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{self, Duration};
use std::thread;

use anyhow::Result;

use event_manager::SubscriberOps;
use vmm::arch::DeviceType;
use vmm::arch_gen::x86::msr_index::{MSR_IA32_DEBUGCTLMSR, MSR_IA32_LASTBRANCHFROMIP, MSR_IA32_LASTBRANCHTOIP, MSR_IA32_LASTINTFROMIP, MSR_IA32_TSC, MSR_IA32_TSCDEADLINE, MSR_IA32_TSC_ADJUST, MSR_LBR_TOS};
use vmm::device_manager::mmio::MMIODeviceManager;
use vmm::devices::virtio::block::device::Block;
use vmm::devices::virtio::block::persist::BlockState;
use vmm::devices::virtio::block::virtio::persist::VirtioBlockState;
use vmm::devices::virtio::device::VirtioDevice;
use vmm::devices::virtio::queue::Queue;
use vmm::devices::virtio::TYPE_BLOCK;
use vmm::logger::debug;
use vmm::persist::MicrovmState;
use vmm::resources::VmResources;
use vmm::snapshot::Persist;
use vmm::vmm_config::instance_info::{InstanceInfo, VmState};
use vmm::vstate::memory::GuestMemoryExtension;
use vmm::vstate::memory::{
    Bitmap, Bytes, GuestAddress, GuestMemory, GuestMemoryRegion, MemoryRegionAddress,
};
use vmm::vstate::vcpu::VcpuEmulation;
use vmm::Vcpu;
use vmm::Vmm;
use vmm::{EventManager, FcExitCode, VcpuEvent};

use kvm_bindings::{kvm_guest_debug_arch, kvm_msr_entry, kvm_regs, kvm_sregs, Msrs, KVM_GUESTDBG_BLOCKIRQ, KVM_GUESTDBG_INJECT_BP, KVM_GUESTDBG_USE_HW_BP};
use kvm_bindings::kvm_guest_debug;
use kvm_bindings::KVM_GUESTDBG_ENABLE;
use kvm_bindings::KVM_GUESTDBG_USE_SW_BP;
use kvm_bindings::KVM_GUESTDBG_SINGLESTEP;

use crate::breakpoints::{BreakpointManager, BreakpointManagerTrait};
use crate::firecracker_wrappers::build_microvm_for_boot;
use crate::hw_breakpoints::HwBreakpoints;
use crate::timer_event::TimerEvent;
use crate::vm_continuation_statemachine::{VMExitUserEvent, VMContinuationState};
use crate::mem::{self, NyxMemExtension};

#[derive(Debug, Hash, Eq, PartialEq, Clone)]
pub enum DebugState{
    Breakpoint,
    SingleStep,
    Continue,
}

const EXECDONE: u64 = 0x656e6f6463657865;
const SNAPSHOT: u64 = 0x746f687370616e73;
const NYX_LITE: u64 = 0x6574696c2d78796e;
const SHAREMEM: u64 = 0x6d656d6572616873;
const DBGPRINT: u64 = 0x746e697270676264;
const DBG_EXCEPTION_BREAKPOINT : u32 = 3;
const DBG_EXCEPTION_SINGLESTEP : u32 = 1;
const DR6_BS : u64 = 1<<14 ; // Single-Step execution
const DR6_HWBP_0: u64 = 1 << 0;
const DR6_HWBP_1: u64 = 1 << 1;
const DR6_HWBP_2: u64 = 1 << 2;
const DR6_HWBP_3: u64 = 1 << 3;
pub struct NyxVM {
    pub vmm: Arc<Mutex<Vmm>>,
    pub vcpu: Vcpu,
    pub event_thread_handle: JoinHandle<Result<(), anyhow::Error>>,
    pub vm_resources: VmResources,
    pub block_devices: Vec<Arc<Mutex<Block>>>,
    pub timeout_timer: Arc<Mutex<TimerEvent>>,
    pub continuation_state: VMContinuationState,
    pub breakpoint_manager: Box<dyn BreakpointManagerTrait>,
    pub hw_breakpoints: HwBreakpoints,
}

pub struct BlockDeviceSnapshot {
    state: VirtioBlockState,
}

impl BlockDeviceSnapshot {
    pub fn from(blockdevice: &Arc<Mutex<Block>>) -> Self {
        let locked = blockdevice.lock().unwrap();
        if let BlockState::Virtio(state) = locked.save() {
            return Self { state };
        }
        panic!("taking snapshots only works for virtio block devices");
    }
    pub fn apply_to(&self, blockdevice: &Arc<Mutex<Block>>) {
        let mut locked = blockdevice.lock().unwrap();
        let dstate = &self.state.virtio_state;
        locked.set_acked_features(dstate.acked_features);
        for (queue, snap) in locked.queues_mut().iter_mut().zip(dstate.queues.iter()) {
            let new_queue = Queue::restore((), snap).unwrap();
            let _ = std::mem::replace(queue, new_queue);
        }
    }
}

pub struct BaseSnapshot {
    memory: Vec<u8>,
    state: MicrovmState,
    tsc: u64,
    continuation_state: VMContinuationState
}

#[derive(Debug)]
pub enum UnparsedExitReason {
    Shutdown,
    Hypercall,
    Timeout,
    NyxBreakpoint,
    GuestBreakpoint,
    SingleStep,
    Interrupted,
    HWBreakpoint(u8),
}

#[derive(Debug)]
pub enum ExitReason {
    Shutdown,
    Hypercall(u64, u64, u64, u64, u64),
    RequestSnapshot,
    ExecDone(u64),
    SharedMem(String, u64, usize),
    DebugPrint(String),
    Timeout,
    Breakpoint,
    HWBreakpoint(u8),
    SingleStep,
    Interrupted,
}

impl NyxVM {
    // NOTE: due to the fact that timeout timers are tied to the thread that
    // makes the NyxVM (see TimerEvent for more details), it's probably unsafe
    // to use a NyxVM in a different thread than the one that made it.
    pub fn new(instance_id: String, config_json: &str) -> Self {
        let mmds_size_limit = 0;

        let instance_info = InstanceInfo {
            id: instance_id.clone(),
            state: VmState::NotStarted,
            vmm_version: "0.1".to_string(),
            app_name: "Firecracker-Lite".to_string(),
        };

        let mut event_manager = EventManager::new().expect("Unable to create EventManager");

        // Build the microVm.
        let mut vm_resources =
            VmResources::from_json(&config_json, &instance_info, mmds_size_limit, None)
                .expect("couldn't parse config json");

        let block_devices = vm_resources
            .block
            .devices
            .iter()
            .cloned()
            .collect::<Vec<_>>();

        vm_resources.vm_config.track_dirty_pages = true;

        vm_resources.boot_timer = false;

        debug!("event_start: build microvm for boot");

        let (vmm, vcpu) = build_microvm_for_boot(&instance_info, &vm_resources, &mut event_manager)
            .expect("couldn't prepare vm");
        debug!("event_end: build microvm for boot");
        
        let timeout_timer = Arc::new(Mutex::new(TimerEvent::new()));
        event_manager.add_subscriber(timeout_timer.clone());
        // This will allow the timeout timer to send the signal that makes KVM exit immediatly
        Vcpu::register_kick_signal_handler();
        // Make the event thread that epolls all the event fd & calls their callbacks.
        // Note: we want to move as many things as possible away from this, as
        // the async nature of it messes with, snapshot & reproducibility of
        // executions
        let t_vmm = Arc::clone(&vmm);
        let event_thread_handle = thread::Builder::new()
            .name("event_thread".to_string())
            .spawn(move || {
                loop {
                    let _cnt = event_manager.run_with_timeout(500).unwrap();
                    match t_vmm.lock().unwrap().shutdown_exit_code() {
                        Some(FcExitCode::Ok) => break,
                        Some(exit_code) => {
                            return Err(anyhow::anyhow!(
                                "Shutting down with exit code: {:?}",
                                exit_code
                            ))
                        }
                        None => continue,
                    }
                }
                return Ok(());
            })
            .unwrap();
        return Self {
            vcpu,
            vmm,
            vm_resources,
            event_thread_handle,
            block_devices,
            timeout_timer,
            continuation_state: VMContinuationState::Main,
            breakpoint_manager: Box::new(BreakpointManager::new()),
            hw_breakpoints: HwBreakpoints::new(),
        };
    }

    pub fn take_snapshot(&mut self) -> BaseSnapshot {
        let vmm = self.vmm.lock().unwrap();

        let region = vmm.guest_memory().find_region(GuestAddress(0)).unwrap();
        let region_len: usize = region.len().try_into().unwrap();
        let mut memory = vec![0; region_len];
        region
            .read_slice(&mut memory, MemoryRegionAddress(0))
            .unwrap();

        vmm.guest_memory().reset_dirty();
        vmm.reset_dirty_bitmap();

        //let block_device_snapshots = self.block_devices.iter().map(|dev| {
        //    // This flushes all changes to the backing file
        //    // - however this should not be needed, as we aren't shutting downt
        //    // the process - For now, it's fine if the OS caches changes to the backing
        //    // file for us. Eventually we will store all updates in memory and
        //    // never change the backing file, so it won't be needed either
        //    // dev.prepare_save();
        //    BlockDeviceSnapshot::from(dev)
        //}).collect();

        let msrs = self
            .vcpu
            .kvm_vcpu
            .get_msrs(&vec![
                MSR_IA32_TSC,
                MSR_IA32_TSCDEADLINE,
                MSR_IA32_TSC_ADJUST,
            ])
            .unwrap();
        let tsc = msrs[&MSR_IA32_TSC];
        return BaseSnapshot {
            memory,
            state: self.save_vm_state(&vmm),
            tsc,
            continuation_state: self.continuation_state.clone()
        };
    }

    fn save_vm_state(&self, vmm: &Vmm) -> MicrovmState {
        let vm_state = vmm.vm.save_state().unwrap();
        let device_states = vmm.mmio_device_manager.save();
        let memory_state = vmm.guest_memory().describe();
        let acpi_dev_state = vmm.acpi_device_manager.save();
        let vcpu_state = self.vcpu.kvm_vcpu.save_state().unwrap();
        let vm_info = vmm::persist::VmInfo::from(&self.vm_resources);
        // this is missing pio device state - notably shutdown and serial devices
        return MicrovmState {
            vm_info: vm_info,
            memory_state,
            vm_state,
            vcpu_states: vec![vcpu_state],
            device_states,
            acpi_dev_state,
        };
    }

    fn apply_snapshot_mmio(mmio: &MMIODeviceManager, snap: &BaseSnapshot) {
        let ds = &snap.state.device_states;
        let blocks = &ds.block_devices;
        for block_snap in blocks.iter() {
            if let BlockState::Virtio(vio_block_snap_state) = &block_snap.device_state {
                let vstate = &vio_block_snap_state.virtio_state;
                let device_id = &block_snap.device_id;
                let bus_dev = mmio
                    .get_device(DeviceType::Virtio(TYPE_BLOCK), device_id)
                    .unwrap();
                let mut locked_bus_dev = bus_dev.lock().unwrap();
                let mmio_transport = locked_bus_dev.mmio_transport_mut().unwrap();
                let t_snap = &block_snap.transport_state;
                mmio_transport.features_select = t_snap.features_select;
                mmio_transport.queue_select = t_snap.queue_select;
                mmio_transport.device_status = t_snap.device_status;
                mmio_transport.config_generation = t_snap.config_generation;
                let mut locked_dev = mmio_transport.locked_device();
                let cow_file_engine = locked_dev.as_cow_file_engine().expect("Trying to apply a snapshot to a non-cow block device");
                cow_file_engine.reset_to(vio_block_snap_state.cow_state.id);
                locked_dev.set_acked_features(vstate.acked_features);
                locked_dev
                    .interrupt_status()
                    .store(vstate.interrupt_status, Ordering::Relaxed);

                for (queue, queue_snap) in
                    locked_dev.queues_mut().iter_mut().zip(vstate.queues.iter())
                {
                    let new_queue = Queue::restore((), queue_snap).unwrap();
                    let _ = std::mem::replace(queue, new_queue);
                }
            } else {
                panic!("trying to apply snapshot for a non-virtio block device. Not supported");
            }
        }
    }

    fn apply_tsc(&mut self, tsc: u64) {
        //let msrs = self.vcpu.kvm_vcpu.get_msrs(&vec![MSR_IA32_TSC, MSR_IA32_TSCDEADLINE, MSR_IA32_TSC_ADJUST]).unwrap();
        //println!("MSRS: TSC {:x} (snapshot: {:x}) TSCDEADLINE {:x} TSC_ADJUST {:x}", msrs[&MSR_IA32_TSC], snap.tsc, msrs[&MSR_IA32_TSCDEADLINE], msrs[&MSR_IA32_TSC_ADJUST]);
        let msrs_to_set = [
            // KVM "helpfully" tries to prevent us from updating TSC in small increments and ignores small delta updates.
            // update to an insane value first
            kvm_msr_entry {
                index: MSR_IA32_TSC,
                data: tsc.wrapping_add(0xdeadc0debeef),
                ..Default::default()
            },
            // then update to what we actually want it to be.
            kvm_msr_entry {
                index: MSR_IA32_TSC,
                data: tsc,
                ..Default::default()
            },
        ];
        let msrs_wrapper = Msrs::from_entries(&msrs_to_set).unwrap();
        let num_set = self.vcpu.kvm_vcpu.fd.set_msrs(&msrs_wrapper).unwrap();
        assert_eq!(num_set, msrs_to_set.len());
        //let msrs = self.vcpu.kvm_vcpu.get_msrs(&vec![MSR_IA32_TSC, MSR_IA32_TSCDEADLINE, MSR_IA32_TSC_ADJUST]).unwrap();
        //println!("MSRS: TSC {:x} (snapshot: {:x}) TSCDEADLINE {:x} TSC_ADJUST {:x}", msrs[&MSR_IA32_TSC], snap.tsc, msrs[&MSR_IA32_TSCDEADLINE], msrs[&MSR_IA32_TSC_ADJUST]);
    }

    pub fn apply_snapshot(&mut self, snapshot: &BaseSnapshot) {
        let mut vmm = self.vmm.lock().unwrap();

        let kvm_dirty_bitmap = vmm.get_dirty_bitmap().unwrap();
        let page_size: usize = mem::PAGE_SIZE as usize;

        for (slot, region) in vmm.guest_memory().iter().enumerate() {
            let kvm_bitmap = kvm_dirty_bitmap.get(&slot).unwrap(); // kvm tracks pages dirtied during execution in this bitmap
            let firecracker_bitmap = region.bitmap(); // firecracker device emulation etc tracks dirty pages in this bitmap

            for (i, v) in kvm_bitmap.iter().enumerate() {
                for j in 0..64 {
                    let is_kvm_page_dirty = ((v >> j) & 1u64) != 0u64;
                    let index: usize = (i * 64) + j;
                    let page_offset = index * page_size;
                    let is_firecracker_page_dirty = firecracker_bitmap.dirty_at(page_offset);

                    if is_kvm_page_dirty || is_firecracker_page_dirty {
                        let target_addr = MemoryRegionAddress(page_offset.try_into().unwrap());
                        let source_slice = &snapshot
                            .memory
                            .get(page_offset..page_offset + page_size)
                            .unwrap();
                        region.write_slice(source_slice, target_addr).unwrap();
                    }
                }
            }
        }

        vmm.guest_memory().reset_dirty();

        // The only ACPIDevice is the vmgenid device which we disable - no need to restore
        //println!("acpi state: {:#?}", &state.acpi_dev_state);
        //println!("vmm acpi_device_manager {:#?}", vmm.acpi_device_manager);

        self.vcpu
            .kvm_vcpu
            .restore_state(&snapshot.state.vcpu_states[0])
            .unwrap();

        // we currently can't restore the net mmio device, only the block one
        Self::apply_snapshot_mmio(&mut vmm.mmio_device_manager, snapshot);
        // cpu might need to restore piodevices, investigate
        //Self::apply_snapshot_pio(&mut vmm.pio_device_manager, snap);

        vmm.vm.restore_state(&snapshot.state.vm_state).unwrap();

        // this should be done last, because KVM keeps tsc running - even when
        // the VM isn't. Doing this early will introduce additional
        // noise/nondeterminism
        drop(vmm);
        self.apply_tsc(snapshot.tsc);
        self.continuation_state = snapshot.continuation_state.clone();
    }

    pub fn sregs(&self) -> kvm_sregs {
        return self.vcpu.kvm_vcpu.fd.get_sregs().unwrap();
    }
    pub fn regs(&self) -> kvm_regs {
        return self.vcpu.kvm_vcpu.fd.get_regs().unwrap();
    }

    pub fn set_regs(&mut self, regs: &kvm_regs) {
        self.vcpu.kvm_vcpu.fd.set_regs(regs).unwrap();
    }

    pub fn set_debug_state(&mut self, single_step: bool, vmexit_on_swbp: bool ){
        let mut control = KVM_GUESTDBG_ENABLE;
        if single_step {
            control |= KVM_GUESTDBG_SINGLESTEP;
            control |= KVM_GUESTDBG_BLOCKIRQ;
        };
        control |= if vmexit_on_swbp {KVM_GUESTDBG_USE_SW_BP} else {KVM_GUESTDBG_INJECT_BP};
        let mut arch  = kvm_guest_debug_arch::default();
        if self.hw_breakpoints.any_active() {
            control |= KVM_GUESTDBG_USE_HW_BP;
            arch.debugreg[0] = self.hw_breakpoints.addr(0);
            arch.debugreg[1] = self.hw_breakpoints.addr(1);
            arch.debugreg[2] = self.hw_breakpoints.addr(2);
            arch.debugreg[3] = self.hw_breakpoints.addr(3);
            arch.debugreg[7] = self.hw_breakpoints.compute_dr7();
        }
        let dbg_info = kvm_guest_debug {
            control,
            pad: 0,
            arch
        };
        self.vcpu.kvm_vcpu.fd.set_guest_debug(&dbg_info).unwrap();
    }

    pub fn is_nyx_hypercall(&self) -> bool {
        let regs = self.regs();
        return regs.rax == NYX_LITE;
    }

    pub fn is_nyx_swbp(&mut self) -> bool {
        return false;
    }

    pub fn parse_hypercall(&self) -> ExitReason{
        let regs = self.regs();
        if self.is_nyx_hypercall(){
            let hypercall = match regs.r8 {
                SHAREMEM => {
                    ExitReason::SharedMem(
                        String::from_utf8_lossy(&self.read_cstr_current(regs.r9)).to_string(),
                        regs.r10,
                        regs.r11.try_into().unwrap(),
                    )
                }
                DBGPRINT => {
                    ExitReason::DebugPrint(
                        String::from_utf8_lossy(&self.read_cstr_current(regs.r9)).to_string(),
                    )
                }
                SNAPSHOT => ExitReason::RequestSnapshot,
                EXECDONE => ExitReason::ExecDone(regs.r9),
                _ => ExitReason::Hypercall(regs.r8, regs.r9, regs.r10, regs.r11, regs.r12),
            };
            return hypercall;
        } 
        panic!("Don't call parse_hypercall on a non-hypercall vmexit!");
    }

    pub fn run_inner(&mut self, timeout: Duration) -> UnparsedExitReason{
        let start_time = time::Instant::now();
        self.timeout_timer.lock().unwrap().set_timeout(timeout);
        loop {
            let mut exit = None;
            match self.vcpu.run_emulation().unwrap() {
                // Emulation ran successfully, continue.
                VcpuEmulation::Handled => {}
                // Emulation was interrupted, check external events.
                VcpuEmulation::Interrupted => {
                    if time::Instant::now().duration_since(start_time) >= timeout {
                        exit = Some(UnparsedExitReason::Timeout);
                    } else {
                        println!("[STOP] interrupt");
                        exit = Some(UnparsedExitReason::Interrupted);
                    }
                }
                VcpuEmulation::Stopped => {
                    exit = Some(UnparsedExitReason::Shutdown);
                }
                VcpuEmulation::DebugEvent(dbg) => {
                    let regs = self.regs();
                    let exc_reason = match dbg.exception {
                        DBG_EXCEPTION_BREAKPOINT if regs.rax == NYX_LITE => UnparsedExitReason::Hypercall,
                        DBG_EXCEPTION_BREAKPOINT if regs.rax != NYX_LITE => {
                            let sregs = self.sregs();
                            if self.breakpoint_manager.forward_guest_bp(sregs.cr3, regs.rip){
                                UnparsedExitReason::GuestBreakpoint
                            } else {
                                UnparsedExitReason::NyxBreakpoint
                            }
                        }
                        DBG_EXCEPTION_SINGLESTEP if (dbg.dr6 & DR6_BS)     != 0 =>  UnparsedExitReason::SingleStep,
                        DBG_EXCEPTION_SINGLESTEP if (dbg.dr6 & DR6_HWBP_0) != 0 =>  UnparsedExitReason::HWBreakpoint(0),
                        DBG_EXCEPTION_SINGLESTEP if (dbg.dr6 & DR6_HWBP_1) != 0 =>  UnparsedExitReason::HWBreakpoint(1),
                        DBG_EXCEPTION_SINGLESTEP if (dbg.dr6 & DR6_HWBP_2) != 0 =>  UnparsedExitReason::HWBreakpoint(2),
                        DBG_EXCEPTION_SINGLESTEP if (dbg.dr6 & DR6_HWBP_3) != 0 =>  UnparsedExitReason::HWBreakpoint(3),

                        excp => {panic!("Unexpected Debug Exception From KVM: {excp} {:x?} ", dbg);}
                    };
                    exit = Some(exc_reason)
                }
            }
            while let Ok(ev) = self.vcpu.event_receiver.try_recv() {
                match ev {
                    VcpuEvent::Finish => {
                        exit = Some(UnparsedExitReason::Shutdown);
                    }
                    event => {
                        println!(">== recieved event: {:?}", event);
                    }
                }
            }
            if let Some(exitreason) = exit {
                self.timeout_timer.lock().unwrap().disable();
                return exitreason;
            }
        }
    }

    pub fn parse_exit_reason(&self, unparsed: VMExitUserEvent) -> ExitReason{
        match unparsed {
            VMExitUserEvent::Hypercall => self.parse_hypercall(),
            VMExitUserEvent::Interrupted => ExitReason::Interrupted,
            VMExitUserEvent::Breakpoint => ExitReason::Breakpoint,
            VMExitUserEvent::SingleStep => ExitReason::SingleStep,
            VMExitUserEvent::Shutdown => ExitReason::Shutdown,
            VMExitUserEvent::Timeout => ExitReason::Timeout,
            VMExitUserEvent::HWBreakpoint(x) => ExitReason::HWBreakpoint(x),
        }
    }
    pub fn continue_vm(&mut self, single_step: bool, timeout: Duration) -> ExitReason {
        let unparsed = VMContinuationState::step(self, single_step, timeout);
        return self.parse_exit_reason(unparsed);
    }

    pub fn run(&mut self, timeout: Duration) -> ExitReason {
        let single_step = false;
        return self.continue_vm(single_step, timeout);
    }

    pub fn single_step(&mut self, timeout: Duration) -> ExitReason{
        let single_step = true;
        return self.continue_vm(single_step, timeout);
    }

    pub fn add_breakpoint(&mut self, cr3: u64, vaddr: u64) {
        self.breakpoint_manager.add_breakpoint(cr3,vaddr);
    }

    pub fn remove_all_breakpoints(&mut self){
        self.breakpoint_manager.remove_all_breakpoints();
    }

    pub fn read_cstr_current(&self, guest_vaddr: u64) -> Vec<u8> {
        let cr3 = self.sregs().cr3;
        let vmm = self.vmm.lock().unwrap();
        vmm.read_virtual_cstr(cr3, guest_vaddr)
    }
    pub fn read_current_u64(&self, vaddr: u64) -> u64 {
        let cr3 = self.sregs().cr3;
        let vmm = self.vmm.lock().unwrap();
        return vmm.read_virtual_u64(cr3, vaddr).unwrap();
    }
    pub fn write_current_u64(&self, vaddr: u64, val: u64) {
        let cr3 = self.sregs().cr3;
        let vmm = self.vmm.lock().unwrap();
        return vmm.write_virtual_u64(cr3, vaddr, val).unwrap();
    }

    pub fn read_current_bytes(&self, vaddr: u64, num_bytes: usize) -> Vec<u8> {
        let mut res = Vec::with_capacity(num_bytes);
        let cr3 = self.sregs().cr3;
        res.resize(num_bytes, 0);
        let vmm = self.vmm.lock().unwrap();
        let bytes_copied = vmm.read_virtual_bytes(cr3, vaddr, &mut res).unwrap();
        res.truncate(bytes_copied);
        //@TODO 
        // It appears that we see high kernel addresses sometimes (i.e.
        // rip = ffffffff823b1ad8 during the boot breakpoint vmexit, triggered when disassembly rip). Those aren't
        // handled correctly right now. Investigate expected behavior
        if vaddr < 0xffffffff00000000 {
            assert_eq!(bytes_copied, num_bytes); 
        }
        return res;
    }

    fn set_lbr(&mut self) {
        panic!("reading lbr doesn't seem to be supported by KVM");
        //let msrs_to_set = [
        //    kvm_msr_entry {
        //        index: MSR_IA32_DEBUGCTLMSR,
        //        data: 1,
        //        ..Default::default()
        //    },
        //];
        //let msrs_wrapper = Msrs::from_entries(&msrs_to_set).unwrap();
        //let num_set = self.vcpu.kvm_vcpu.fd.set_msrs(&msrs_wrapper).unwrap();
        //assert_eq!(num_set, msrs_to_set.len());
    }

    fn get_lbr(&mut self){
        panic!("None of this seems supported by KVM?");
        // it appears XSAVE nees AI32_XSS[15] to actually store LBR data, and we can't set AI32_XSS via kvm.
        // let xsave = self.vcpu.kvm_vcpu.fd.get_xsave().unwrap();
        // println!("got xsave: {:x?}",xsave);
        //
        // this is all even more broken. All of this only applies to AMD cpus:
        ////let lbr_tos = self.vcpu.kvm_vcpu.get_msrs(&[MSR_LBR_TOS]).unwrap()[&0];
        // let msrs_to_set = [
        //     kvm_msr_entry {
        //         index: 0x00000680,
        //         data: 1,
        //         ..Default::default()
        //     },
        // ];
        // let mut msrs_wrapper = Msrs::from_entries(&msrs_to_set).unwrap();
        // let lbr_tos = self.vcpu.kvm_vcpu.fd.get_msrs(&mut msrs_wrapper).unwrap();
        // assert_eq!(lbr_tos, 1);
        // msrs_wrapper.as_slice().iter().for_each(|msr| {
        //     println!("got MSR_IA32_DEBUGCTLMSR: {}, {:?} {:?}", lbr_tos, msr.index, msr.data);
        // });
        ////let mut lbr_stack = Vec::with_capacity(32);
        //
        //for i in 0..32 {
        //    let msrs_to_set = [
        //        kvm_msr_entry {
        //            index: MSR_IA32_LASTBRANCHFROMIP+i,
        //            data: 1338,
        //            ..Default::default()
        //        },
        //        kvm_msr_entry {
        //            index: MSR_IA32_LASTBRANCHTOIP+i,
        //            data: 1339,
        //            ..Default::default()
        //        },
        //        kvm_msr_entry {
        //            index: MSR_LBR_TOS,
        //            data: 1337,
        //            ..Default::default()
        //        },
        //    ];
        //    let mut msrs_wrapper = Msrs::from_entries(&msrs_to_set).unwrap();
        //    let lbr_tos = self.vcpu.kvm_vcpu.fd.get_msrs(&mut msrs_wrapper).unwrap();
        //    assert_eq!(lbr_tos, 3);
        //    msrs_wrapper.as_slice().iter().for_each(|msr| {
        //        println!("got MSR_IA#@_LASTBRANCHTOIP: {}, {:?} {:?}", lbr_tos, msr.index, msr.data);
        //    });
        //    //lbr_stack.push((
        //    //    self.vcpu.kvm_vcpu.get_msrs(&[MSR_IA32_LASTINTFROMIP+i]).unwrap()[&0],
        //    //    self.vcpu.kvm_vcpu.get_msrs(&[MSR_IA32_LASTBRANCHTOIP+i]).unwrap()[&0],
        //    //));
        //}
        ////println!("LBR: {:x?} top: {:?}", lbr_stack, lbr_tos);
    }


}
