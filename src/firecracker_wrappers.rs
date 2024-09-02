use std::fs::{self};
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Instant;
use std::{io, panic, thread};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use anyhow::Result;

use event_manager::SubscriberOps;
use seccompiler::BpfThreadMap;
use utils::arg_parser::{ArgParser, Argument};
use utils::terminal::Terminal;
use utils::validators::validate_instance_id;
use utils::time::TimestampUs;
use vmm::builder::StartMicrovmError;
use vmm::devices::BusDevice;
use vmm::logger::{
    debug, error, info, LoggerConfig, LOGGER,
};
use vmm::persist::{MicrovmState, MicrovmStateError, VmInfo};
use vmm::resources::VmResources;
use vmm::signal_handler::register_signal_handlers;
use vmm::snapshot::Persist;
use vmm::vmm_config::instance_info::{InstanceInfo, VmState};
use vmm::vmm_config::metrics::{init_metrics, MetricsConfig};
use vmm::{EventManager, FcExitCode, VcpuEvent, VcpuHandle};
use vmm::vstate::memory::{Bytes, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion, MemoryRegionAddress};
use vmm::Vmm;
use vmm::Vcpu;
use vmm::vstate::memory::GuestMemoryExtension;
use vmm::cpu_config::templates::GetCpuTemplate;
use vmm::vstate::vcpu::VcpuEmulation;

use kvm_bindings::{
    KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_USE_SW_BP, kvm_guest_debug
};

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum ResizeFdTableError {
    /// Failed to get RLIMIT_NOFILE
    GetRlimit,
    /// Failed to call dup2 to resize fdtable
    Dup2(io::Error),
    /// Failed to close dup2'd file descriptor
    Close(io::Error),
}


/// Attempts to resize the processes file descriptor table to match RLIMIT_NOFILE or 2048 if no
/// RLIMIT_NOFILE is set (this can only happen if firecracker is run outside the jailer. 2048 is
/// the default the jailer would set).
///
/// We do this resizing because the kernel default is 64, with a reallocation happening whenever
/// the tabel fills up. This was happening for some larger microVMs, and reallocating the
/// fdtable while a lot of file descriptors are active (due to being eventfds/timerfds registered
/// to epoll) incurs a penalty of 30ms-70ms on the snapshot restore path.
pub fn resize_fdtable() -> Result<(), ResizeFdTableError> {
    let mut rlimit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };

    // SAFETY: We pass a pointer to a valid area of memory to which we have exclusive mutable access
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlimit as *mut libc::rlimit) } < 0 {
        return Err(ResizeFdTableError::GetRlimit);
    }

    // If no jailer is used, there might not be an NOFILE limit set. In this case, resize
    // the table to the default that the jailer would usually impose (2048)
    let limit: libc::c_int = if rlimit.rlim_cur == libc::RLIM_INFINITY {
        2048
    } else {
        rlimit.rlim_cur.try_into().unwrap_or(2048)
    };

    // Resize the file descriptor table to its maximal possible size, to ensure that
    // firecracker will not need to reallocate it later. If the file descriptor table
    // needs to be reallocated (which by default happens once more than 64 fds exist,
    // something that happens for reasonably complex microvms due to each device using
    // a multitude of eventfds), this can incur a significant performance impact (it
    // was responsible for a 30ms-70ms impact on snapshot restore times).
    if limit > 3 {
        // SAFETY: Duplicating stdin is safe
        if unsafe { libc::dup2(0, limit - 1) } < 0 {
            return Err(ResizeFdTableError::Dup2(io::Error::last_os_error()));
        }

        // SAFETY: Closing the just created duplicate is safe
        if unsafe { libc::close(limit - 1) } < 0 {
            return Err(ResizeFdTableError::Close(io::Error::last_os_error()));
        }
    }

    Ok(())
}



/// Builds and starts a microVM based on the current Firecracker VmResources configuration.
///
/// The built microVM and all the created vCPUs start off in the paused state.
/// To boot the microVM and run those vCPUs, `Vmm::resume_vm()` needs to be
/// called.
pub fn build_microvm_for_boot(
    instance_info: &InstanceInfo,
    vm_resources: &VmResources,
    event_manager: &mut EventManager,
) -> Result<(Arc<Mutex<Vmm>>, Vcpu), StartMicrovmError> {
    use self::StartMicrovmError::*;

    let boot_config = vm_resources
        .boot_source_builder()
        .ok_or(MissingKernelConfig)?;

    let track_dirty_pages = vm_resources.track_dirty_pages();

    let vhost_user_device_used = vm_resources
        .block
        .devices
        .iter()
        .any(|b| b.lock().expect("Poisoned lock").is_vhost_user());

    // Page faults are more expensive for shared memory mapping, including  memfd.
    // For this reason, we only back guest memory with a memfd
    // if a vhost-user-blk device is configured in the VM, otherwise we fall back to
    // an anonymous private memory.
    //
    // The vhost-user-blk branch is not currently covered by integration tests in Rust,
    // because that would require running a backend process. If in the future we converge to
    // a single way of backing guest memory for vhost-user and non-vhost-user cases,
    // that would not be worth the effort.
    let guest_memory = if vhost_user_device_used {
        GuestMemoryMmap::memfd_backed(
            vm_resources.vm_config.mem_size_mib,
            track_dirty_pages,
            vm_resources.vm_config.huge_pages,
        )
        .map_err(StartMicrovmError::GuestMemory)?
    } else {
        let regions = vmm::arch::arch_memory_regions(vm_resources.vm_config.mem_size_mib << 20);
        GuestMemoryMmap::from_raw_regions(
            &regions,
            track_dirty_pages,
            vm_resources.vm_config.huge_pages,
        )
        .map_err(StartMicrovmError::GuestMemory)?
    };

    let entry_addr = vmm::builder::load_kernel(boot_config, &guest_memory)?;
    let initrd = vmm::builder::load_initrd_from_config(boot_config, &guest_memory)?;
    // Clone the command-line so that a failed boot doesn't pollute the original.
    #[allow(unused_mut)]
    let mut boot_cmdline = boot_config.cmdline.clone();

    let cpu_template = vm_resources.vm_config.cpu_template.get_cpu_template()?;

    let (mut vmm, mut vcpus) = vmm::builder::create_vmm_and_vcpus(
        instance_info,
        event_manager,
        guest_memory,
        None,
        track_dirty_pages,
        vm_resources.vm_config.vcpu_count,
        cpu_template.kvm_capabilities.clone(),
    )?;

    /// BEGIN NYX-LITE PATCH
    assert_eq!(vcpus.len(), 1);
    let debug_struct = kvm_guest_debug {
        // Configure the vcpu so that a KVM_DEBUG_EXIT would be generated
        // when encountering a software breakpoint during execution
        control: KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP,
        pad: 0,
        // Reset all arch-specific debug registers
        arch: Default::default(),
    };
    
    vcpus[0].kvm_vcpu.fd.set_guest_debug(&debug_struct).unwrap();
    /// END NYX-LITE PATCH

    // The boot timer device needs to be the first device attached in order
    // to maintain the same MMIO address referenced in the documentation
    // and tests.
    // if vm_resources.boot_timer {
    //     vmm::builder::attach_boot_timer_device(&mut vmm, request_ts)?;
    // }

    vmm::builder::attach_block_devices(
        &mut vmm,
        &mut boot_cmdline,
        vm_resources.block.devices.iter(),
        event_manager,
    )?;
    vmm::builder::attach_net_devices(
        &mut vmm,
        &mut boot_cmdline,
        vm_resources.net_builder.iter(),
        event_manager,
    )?;

    // no need for nondeterminism - we don't like that anyway
    //#[cfg(target_arch = "x86_64")]
    //vmm::builder::attach_vmgenid_device(&mut vmm)?;

    vmm::builder::configure_system_for_boot(
        &mut vmm,
        vcpus.as_mut(),
        &vm_resources.vm_config,
        &cpu_template,
        entry_addr,
        &initrd,
        boot_cmdline,
    )?;

    let mut vcpu = vcpus.into_iter().next().unwrap();
    let event_sender = vcpu.event_sender.take().expect("vCPU already started");
    let response_receiver = vcpu.response_receiver.take().unwrap();
    let vcpu_join_handle = thread::Builder::new()
    .name(format!("fake vcpu thread")).spawn(||{}).unwrap();
    let handle = VcpuHandle::new(
        event_sender,
        response_receiver,
        vcpu_join_handle,
    );

    //END NYX-LITE PATCH
    vmm.vcpus_handles.push(handle);
    let vmm = Arc::new(Mutex::new(vmm));
    event_manager.add_subscriber(vmm.clone());

    vcpu.set_mmio_bus(vmm.lock().unwrap().mmio_device_manager.bus.clone());
    vcpu.kvm_vcpu.set_pio_bus(vmm.lock().unwrap().pio_device_manager.io_bus.clone());
    Ok((vmm, vcpu))
}