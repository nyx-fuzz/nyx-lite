use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::{thread};
use std::sync::atomic::Ordering;

use anyhow::Result;

use vmm::logger::debug;
use vmm::persist::{MicrovmState};
use vmm::resources::VmResources;
use vmm::snapshot::{Persist};
use vmm::vmm_config::instance_info::{InstanceInfo, VmState};
use vmm::{EventManager, FcExitCode, VcpuEvent};
use vmm::vstate::memory::{Bitmap, Bytes, GuestAddress, GuestMemory, GuestMemoryRegion, MemoryRegionAddress};
use vmm::Vmm;
use vmm::Vcpu;
use vmm::vstate::memory::GuestMemoryExtension;
use vmm::vstate::vcpu::VcpuEmulation;

use kvm_bindings::{
    kvm_regs, kvm_sregs
};

use crate::firecracker_wrappers::build_microvm_for_boot;
use crate::mem;

const EXECDONE :u64 = 0x656e6f6463657865;
const SNAPSHOT :u64 = 0x746f687370616e73;
const NYX_LITE :u64 = 0x6574696c2d78796e;
const SHAREMEM :u64 = 0x6d656d6572616873;
pub struct NyxVM {
    vmm: Arc<Mutex<Vmm>>,
    vcpu: Vcpu,
    event_thread_handle: JoinHandle<Result<(), anyhow::Error>>,
    vm_resources: VmResources,
}

pub struct BaseSnapshot{
    memory: Vec<u8>,
    state: MicrovmState,
}

#[derive(Debug)]
pub enum ExitReason {
    Shutdown,
    Hypercall(u64, u64, u64, u64),
    RequestSnapshot,
    ExecDone(u64),
    SharedMem(String, u64, usize), 
    Timeout,
    Breakpoint,
    SingleStep,
    Interrupted,
}

impl NyxVM{
    pub fn new(instance_id: String, config_json: &str) -> Self{
        let mmds_size_limit = 0;

        let instance_info = InstanceInfo {
            id: instance_id.clone(),
            state: VmState::NotStarted,
            vmm_version: "0.1".to_string(),
            app_name: "Firecracker-Lite".to_string(),
        };

        let mut event_manager = EventManager::new().expect("Unable to create EventManager");

        // Build the microVm. We can ignore VmResources since it's not used without api.
        let mut vm_resources =
            VmResources::from_json(&config_json, &instance_info, mmds_size_limit, None).expect("couldn't parse config json");

        vm_resources.vm_config.track_dirty_pages = true;

        vm_resources.boot_timer = false;
    
        debug!("event_start: build microvm for boot");
    
        let (vmm, vcpu) = build_microvm_for_boot(&instance_info, &vm_resources, &mut event_manager).expect("couldn't prepare vm");
        debug!("event_end: build microvm for boot");
    
    
        // use std::thread;
        // let t_vmm = Arc::clone(&vmm);
        // let t = thread::spawn(move || 
        //     loop {
        //         if !continue_vm(&mut vcpu).unwrap(){
        //             break;
        //         }
        //         let vm_info = vmm::persist::VmInfo::from(&vm_resources);
        //         println!("saving");
        //         let (mem,state) = save_state(&mut t_vmm.lock().unwrap(), &vcpu, &vm_info).unwrap();
        //         restore_state(&mut t_vmm.lock().unwrap(), &mut vcpu, &state, &mem);
        //         println!("done saving");
        //     }
        // );
        let t_vmm = Arc::clone(&vmm);
        let event_thread_handle = thread::spawn(move ||{
            loop {
                event_manager.run_with_timeout(500).unwrap(); 
                match t_vmm.lock().unwrap().shutdown_exit_code() {
                    Some(FcExitCode::Ok) => break,
                    Some(exit_code) => return Err(anyhow::anyhow!("Shutting down with exit code: {:?}", exit_code)),
                    None => continue,
                }
            }
            return Ok(());
        });
        return Self{
            vcpu,
            vmm,
            vm_resources,
            event_thread_handle,
        }
    }

    pub fn take_snapshot(&mut self) -> BaseSnapshot {

        let vmm = self.vmm.lock().unwrap();

        let region = vmm.guest_memory().find_region(GuestAddress(0)).unwrap();
        let region_len: usize = region.len().try_into().unwrap();
        let mut memory = vec![0; region_len];
        region.read_slice(&mut memory, MemoryRegionAddress(0)).unwrap();
        //std::fs::write("/tmp/memory_dump", &memory).unwrap();

        vmm.guest_memory().reset_dirty();
        vmm.reset_dirty_bitmap();

        let vm_state = vmm.vm.save_state().unwrap();
        let device_states = vmm.mmio_device_manager.save();
        let memory_state = vmm.guest_memory().describe();
        let acpi_dev_state = vmm.acpi_device_manager.save();
        let vcpu_state = self.vcpu.kvm_vcpu.save_state().unwrap();
        let vm_info = vmm::persist::VmInfo::from(&self.vm_resources);


        return BaseSnapshot{
            memory,
            state: MicrovmState {
                vm_info: vm_info,
                memory_state,
                vm_state,
                vcpu_states: vec![vcpu_state],
                device_states,
                acpi_dev_state,
            }
        }
    }

    pub fn apply_snapshot(&mut self, snap: &BaseSnapshot) {
        let mut vmm = self.vmm.lock().unwrap();

        let kvm_dirty_bitmap = vmm.get_dirty_bitmap().unwrap();
        let page_size : usize = mem::PAGE_SIZE as usize;

        for (slot,region) in vmm.guest_memory().iter().enumerate() {
            let kvm_bitmap = kvm_dirty_bitmap.get(&slot).unwrap();
            let firecracker_bitmap = region.bitmap();

            for (i, v) in kvm_bitmap.iter().enumerate() {
                for j in 0..64 {
                    let is_kvm_page_dirty = ((v >> j) & 1u64) != 0u64;
                    let index : usize = (i * 64) + j;
                    let page_offset = index * page_size;
                    let is_firecracker_page_dirty = firecracker_bitmap.dirty_at(page_offset);

                    if is_kvm_page_dirty  || is_firecracker_page_dirty && (i %1000 == 0) {
                        region.write_slice(&snap.memory.get(page_offset..page_offset+page_size).unwrap(), MemoryRegionAddress(page_offset.try_into().unwrap())).unwrap();
                    }
                }
            }
        }

        self.vcpu.kvm_vcpu.restore_state(&snap.state.vcpu_states[0]).unwrap();
        // cpu might need to restore some devices, investigate
        vmm.vm.restore_state(&snap.state.vm_state).unwrap();

        vmm.guest_memory().reset_dirty();
        // we currently only have a block & a net mmio device - we don't restore either of those for now
        // println!("device states: {:#?}", state.device_states);
        // for device in vmm.mmio_device_manager.bus.devices.values(){
        //     match(&*device.lock().unwrap()){
        //         BusDevice::MmioTransport(x) => {
        //             println!("got device {:#?}", &*x.device().lock().unwrap());
        //         }
        //         x => {panic!("unhandled device {:#?}", x)}
        //     }
        // }
        //
        // The only ACPIDevice is the vmgenid device which we disable - no need to restore
        //println!("acpi state: {:#?}", &state.acpi_dev_state);
        //println!("vmm acpi_device_manager {:#?}", vmm.acpi_device_manager);
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

    pub fn run(&mut self) -> ExitReason {
        loop {
            let mut exit = None;
            match self.vcpu.run_emulation().unwrap() {
                // Emulation ran successfully, continue.
                VcpuEmulation::Handled => {},
                // Emulation was interrupted, check external events.
                VcpuEmulation::Interrupted => 
                {
                    //println!("[STOP] interrupt"); 
                    exit = Some(ExitReason::Interrupted);
                },
                VcpuEmulation::Stopped => {
                    //println!("[STOP] shutdown"); 
                    exit = Some(ExitReason::Shutdown);
                },
                VcpuEmulation::PausedBreakpoint => {
                    //println!("[STOP] breakpoint");
                    let regs = self.regs();
                    if regs.rax == NYX_LITE {
                        let hypercall = match regs.r8 {
                            SHAREMEM => ExitReason::SharedMem(
                                self.read_cstr_current(regs.r9), 
                                regs.r10, 
                                regs.r11.try_into().unwrap()
                            ),
                            SNAPSHOT => ExitReason::RequestSnapshot,
                            EXECDONE => ExitReason::ExecDone(regs.r9),
                            _ => ExitReason::Hypercall(regs.r8, regs.r9, regs.r10, regs.r11),
                        };
                        exit = Some(hypercall)
                    } else {
                        exit = Some(ExitReason::Breakpoint);
                    }
                }
            }
            while let Ok(ev) = self.vcpu.event_receiver.try_recv() {
                match ev {
                    VcpuEvent::Finish => { exit = Some(ExitReason::Shutdown); }
                    event => { println!(">== recieved event: {:?}", event); }
                }
            }
            if let Some(exitreason) = exit {
                return exitreason;
            }
        }
    } 

    pub fn read_cstr_current(&self, guest_addr: u64) -> String{
        return "FAKE".into();
    }

    pub fn read_current_u64(&self, vaddr: u64) -> u64 {
        let cr3 = self.sregs().cr3;
        return self.read_virtual_u64(cr3, vaddr);
    }



    pub fn read_virtual_u64(&self, cr3: u64, vaddr: u64) -> u64 {
        let vmm = &self.vmm.lock().unwrap();
        let mem = vmm.guest_memory();
        let paddr = mem::resolve_addr(mem, cr3, vaddr).unwrap();
        return mem::read_phys_u64(mem, paddr).unwrap();
    }

    pub fn write_current_u64(&self, vaddr: u64, val: u64) {
        let cr3 = self.sregs().cr3;
        return self.write_virtual_u64(cr3, vaddr, val);
    }
    pub fn write_virtual_u64(&self, cr3: u64, vaddr: u64, val: u64) {
        let vmm = &self.vmm.lock().unwrap();
        let mem = vmm.guest_memory();
        let paddr = mem::resolve_addr(mem, cr3, vaddr).unwrap();
        vmm.guest_memory().store(val, GuestAddress(paddr), Ordering::Relaxed).unwrap();
    }
}
