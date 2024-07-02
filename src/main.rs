extern crate vmm;
extern crate utils;
extern crate event_manager;
extern crate libc;
extern crate thiserror;
extern crate anyhow;
extern crate kvm_ioctls;
extern crate kvm_bindings;

use std::fs::{self};
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::{io, panic};

use anyhow::Result;

use event_manager::SubscriberOps;
use seccompiler::BpfThreadMap;
use utils::arg_parser::{ArgParser, Argument};
use utils::terminal::Terminal;
use utils::validators::validate_instance_id;
use utils::time::TimestampUs;
use vmm::builder::StartMicrovmError;
use vmm::logger::{
    debug, error, info, LoggerConfig, LOGGER,
};
use vmm::resources::VmResources;
use vmm::signal_handler::register_signal_handlers;
use vmm::vmm_config::instance_info::{InstanceInfo, VmState};
use vmm::vmm_config::metrics::{init_metrics, MetricsConfig};
use vmm::{EventManager};
use vmm::vstate::memory::GuestMemoryMmap;
use vmm::Vmm;
use vmm::Vcpu;
use vmm::vstate::memory::GuestMemoryExtension;
use vmm::cpu_config::templates::GetCpuTemplate;
use vmm::vstate::vcpu::VcpuEmulation;

use kvm_bindings::{
    KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_USE_SW_BP, kvm_guest_debug
};

fn main() -> ExitCode {
    let result = main_exec();
    if let Err(err) = result {
        error!("{err}");
        eprintln!("Error: {err:?}");
        error!("NYX-lite exiting with error.");
        ExitCode::FAILURE
    } else {
        info!("NYX-lite exiting successfully. exit_code=0");
        ExitCode::SUCCESS
    }
}

fn main_exec() -> Result<()> {
    // Initialize the logger.
    LOGGER.init()?;

    // We need this so that we can reset terminal to canonical mode if panic occurs.
    let stdin = io::stdin();

    // Start firecracker by setting up a panic hook, which will be called before
    // terminating as we're building with panic = "abort".
    // It's worth noting that the abort is caused by sending a SIG_ABORT signal to the process.
    panic::set_hook(Box::new(move |info| {
        // We're currently using the closure parameter, which is a &PanicInfo, for printing the
        // origin of the panic, including the payload passed to panic! and the source code location
        // from which the panic originated.
        error!("NYX-lite {}", info);
        if let Err(err) = stdin.lock().set_canon_mode() {
            error!(
                "Failure while trying to reset stdin to canonical mode: {}",
                err
            );
        }
    }));

    let mut arg_parser =
        ArgParser::new()
            .arg(
                Argument::new("config")
                    .takes_value(true)
                    .help("Path to a file that contains the microVM configuration in JSON format."),
            )
            .arg(
                Argument::new("log-path")
                    .takes_value(true)
                    .help("Path to a fifo or a file used for configuring the logger on startup."),
            )
            .arg(
                Argument::new("level")
                    .takes_value(true)
                    .help("Set the logger level."),
            )
            .arg(
                Argument::new("module")
                    .takes_value(true)
                    .help("Set the logger module filter."),
            )
            .arg(
                Argument::new("show-level")
                    .takes_value(false)
                    .help("Whether or not to output the level in the logs."),
            )
            .arg(Argument::new("show-log-origin").takes_value(false).help(
                "Whether or not to include the file path and line number of the log's origin.",
            ))
            .arg(
                Argument::new("metrics-path")
                    .takes_value(true)
                    .help("Path to a fifo or a file used for configuring the metrics on startup."),
            );

    arg_parser.parse_from_cmdline()?;
    let arguments = arg_parser.arguments();

    if arguments.flag_present("help") {
        println!("NYX-lite\n");
        println!("{}", arg_parser.formatted_help());
        return Ok(());
    }

    // It's safe to unwrap here because the field's been provided with a default value.
    let instance_id = vmm::logger::DEFAULT_INSTANCE_ID.to_string();
    validate_instance_id(instance_id.as_str()).expect("Invalid instance ID");

    // Apply the logger configuration.
    vmm::logger::INSTANCE_ID
        .set(String::from(instance_id.clone()))
        .unwrap();
    let log_path = arguments.single_value("log-path").map(PathBuf::from);
    let level = arguments
        .single_value("level")
        .map(|s| vmm::logger::LevelFilter::from_str(s))
        .transpose()?;
    let show_level = arguments.flag_present("show-level").then_some(true);
    let show_log_origin = arguments.flag_present("show-log-origin").then_some(true);
    let module = arguments.single_value("module").cloned();
    LOGGER
        .update(LoggerConfig {
            log_path,
            level,
            show_level,
            show_log_origin,
            module,
        })?;
    info!("Running NYX-lite");

    register_signal_handlers()?;

    if let Err(err) = resize_fdtable() {
        match err {
            // These errors are non-critical: In the worst case we have worse snapshot restore
            // performance.
            ResizeFdTableError::GetRlimit | ResizeFdTableError::Dup2(_) => {
                debug!("Failed to resize fdtable: {:?}", err)
            }
            // This error means that we now have a random file descriptor lying around, abort to be
            // cautious.
            ResizeFdTableError::Close(_) => Err(err)?
        }
    }

    // Display warnings for any used deprecated parameters.
    // Currently unused since there are no deprecated parameters. Uncomment the line when
    // deprecating one.
    // warn_deprecated_parameters(&arguments);

    let instance_info = InstanceInfo {
        id: instance_id.clone(),
        state: VmState::NotStarted,
        vmm_version: "0.1".to_string(),
        app_name: "Firecracker-Fuzz".to_string(),
    };

    if let Some(metrics_path) = arguments.single_value("metrics-path") {
        let metrics_config = MetricsConfig {
            metrics_path: PathBuf::from(metrics_path),
        };
        init_metrics(metrics_config)?;
    }

    let vmm_config_json = arguments
        .single_value("config")
        .map(fs::read_to_string)
        .map(|x| x.expect("Unable to open or read from the configuration file"));

    let seccomp_filters: BpfThreadMap = vmm::seccomp_filters::get_empty_filters();

    let mmds_size_limit = 0;
    let boot_timer_enabled = false;

    run_without_api(
        &seccomp_filters,
        vmm_config_json,
        instance_info,
        boot_timer_enabled,
        mmds_size_limit,
    )
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
enum ResizeFdTableError {
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
fn resize_fdtable() -> Result<(), ResizeFdTableError> {
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
    seccomp_filters: &BpfThreadMap,
) -> Result<(Arc<Mutex<Vmm>>, Vcpu), StartMicrovmError> {
    use self::StartMicrovmError::*;

    // Timestamp for measuring microVM boot duration.
    let request_ts = TimestampUs::default();

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


    #[cfg(target_arch = "x86_64")]
    vmm::builder::attach_vmgenid_device(&mut vmm)?;

    vmm::builder::configure_system_for_boot(
        &mut vmm,
        vcpus.as_mut(),
        &vm_resources.vm_config,
        &cpu_template,
        entry_addr,
        &initrd,
        boot_cmdline,
    )?;

    let vcpu = vcpus.into_iter().next().unwrap();

    // // Move vcpus to their own threads and start their state machine in the 'Paused' state.
    // vmm.start_vcpus(
    //     vcpus,
    //     seccomp_filters
    //         .get("vcpu")
    //         .ok_or_else(|| MissingSeccompFilters("vcpu".to_string()))?
    //         .clone(),
    // )
    // .map_err(VmmError::VcpuStart)
    // .map_err(Internal)?;

    // // Load seccomp filters for the VMM thread.
    // // Execution panics if filters cannot be loaded, use --no-seccomp if skipping filters
    // // altogether is the desired behaviour.
    // // Keep this as the last step before resuming vcpus.
    // seccompiler::apply_filter(
    //     seccomp_filters
    //         .get("vmm")
    //         .ok_or_else(|| MissingSeccompFilters("vmm".to_string()))?,
    // )
    // .map_err(VmmError::SeccompFilters)
    // .map_err(Internal)?;

    let vmm = Arc::new(Mutex::new(vmm));
    event_manager.add_subscriber(vmm.clone());

    Ok((vmm, vcpu))
}

fn continue_vm(vcpu: &mut Vcpu) -> Result<()> {
    println!("------------------------------------------------");
    loop {
        match vcpu.run_emulation()? {
            // Emulation ran successfully, continue.
            VcpuEmulation::Handled => (),
            // Emulation was interrupted, check external events.
            VcpuEmulation::Interrupted => 
            // If the guest was rebooted or halted:
            // - vCPU0 will always exit out of `KVM_RUN` with KVM_EXIT_SHUTDOWN or KVM_EXIT_HLT.
            // - the other vCPUs won't ever exit out of `KVM_RUN`, but they won't consume CPU.
            // So we pause vCPU0 and send a signal to the emulation thread to stop the VMM.
            {println!("[STOP] interrupt"); return Ok(())},
            VcpuEmulation::Stopped => 
            {println!("[STOP] shutdown"); return Ok(())},
            VcpuEmulation::PausedBreakpoint => 
            {println!("[STOP] bp"); return Ok(())},
        }
    }
    return Ok(())
}

fn run_without_api(
    seccomp_filters: &BpfThreadMap,
    config_json: Option<String>,
    instance_info: InstanceInfo,
    boot_timer_enabled: bool,
    mmds_size_limit: usize,
) -> Result<()> {
    let mut event_manager = EventManager::new().expect("Unable to create EventManager");

    // Build the microVm. We can ignore VmResources since it's not used without api.
    let mut vm_resources =
        VmResources::from_json(&config_json.expect("no config given"), &instance_info, mmds_size_limit, None)?;

    vm_resources.boot_timer = boot_timer_enabled;

    debug!("event_start: build microvm for boot");

    let (vmm, mut vcpu) = build_microvm_for_boot(&instance_info, &vm_resources, &mut event_manager, seccomp_filters)?;
    debug!("event_end: build microvm for boot");

    vcpu.set_mmio_bus(vmm.lock().unwrap().mmio_device_manager.bus.clone());
    #[cfg(target_arch = "x86_64")]
    vcpu.kvm_vcpu
        .set_pio_bus(vmm.lock().unwrap().pio_device_manager.io_bus.clone());

    use std::thread;
    thread::spawn(move || 
        loop {
            continue_vm(&mut vcpu);
        }
    );
        loop {event_manager.run(); }
    // Run the EventManager that drives everything in the microVM.
    // loop {
    //     event_manager
    //         .run()
    //         .expect("Failed to start the event manager");
    //     match vmm.lock().unwrap().shutdown_exit_code() {
    //         Some(FcExitCode::Ok) => break,
    //         Some(exit_code) => return Err(anyhow::anyhow!("Shutting down with exit code: {:?}", exit_code)),
    //         None => continue,
    //     }
    //     //use std::time::Duration;
    //     //println!("wait for breakpoint");
    //     //vmm.lock().unwrap().wait_for_hypercall(Duration::from_millis(10)).expect("was waiting for hypercall, wtf?");
    //     //println!("wait for breakpoint");
    // }
    Ok(())
}
