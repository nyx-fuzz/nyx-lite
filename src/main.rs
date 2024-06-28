extern crate vmm;
extern crate utils;
extern crate event_manager;
extern crate libc;
extern crate thiserror;
extern crate anyhow;

use std::fs::{self, File};
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
use vmm::builder::StartMicrovmError;
use vmm::logger::{
    debug, error, info, LoggerConfig, ProcessTimeReporter, StoreMetric, LOGGER,
};
use vmm::persist::SNAPSHOT_VERSION;
use vmm::resources::VmResources;
use vmm::signal_handler::register_signal_handlers;
use vmm::snapshot::{Snapshot, SnapshotError};
use vmm::vmm_config::instance_info::{InstanceInfo, VmState};
use vmm::vmm_config::metrics::{init_metrics, MetricsConfig, MetricsConfigError};
use vmm::{EventManager, FcExitCode, HTTP_MAX_PAYLOAD_SIZE};

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
                Argument::new("config-file")
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
        .single_value("config-file")
        .map(fs::read_to_string)
        .map(|x| x.expect("Unable to open or read from the configuration file"));

    let mut seccomp_filters: BpfThreadMap = vmm::seccomp_filters::get_empty_filters();

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


// Configure and start a microVM as described by the command-line JSON.
fn build_microvm_from_json(
    seccomp_filters: &BpfThreadMap,
    event_manager: &mut EventManager,
    config_json: String,
    instance_info: InstanceInfo,
    boot_timer_enabled: bool,
    mmds_size_limit: usize,
    metadata_json: Option<&str>,
) -> Result<(VmResources, Arc<Mutex<vmm::Vmm>>)> {
    let mut vm_resources =
        VmResources::from_json(&config_json, &instance_info, mmds_size_limit, metadata_json)?;
    vm_resources.boot_timer = boot_timer_enabled;
    let vmm = vmm::builder::build_and_boot_microvm(
        &instance_info,
        &vm_resources,
        event_manager,
        seccomp_filters,
    )?;

    info!("Successfully started microvm that was configured from one single json");

    Ok((vm_resources, vmm))
}

fn run_without_api(
    seccomp_filters: &BpfThreadMap,
    config_json: Option<String>,
    instance_info: InstanceInfo,
    bool_timer_enabled: bool,
    mmds_size_limit: usize,
) -> Result<()> {
    let mut event_manager = EventManager::new().expect("Unable to create EventManager");

    // Build the microVm. We can ignore VmResources since it's not used without api.
    let (_, vmm) = build_microvm_from_json(
        seccomp_filters,
        &mut event_manager,
        config_json.expect("expected --config-file"),
        instance_info,
        bool_timer_enabled,
        mmds_size_limit,
        None,
    )?;


    // Run the EventManager that drives everything in the microVM.
    loop {
        event_manager
            .run()
            .expect("Failed to start the event manager");

        match vmm.lock().unwrap().shutdown_exit_code() {
            Some(FcExitCode::Ok) => break,
            Some(exit_code) => return Err(anyhow::anyhow!("Shutting down with exit code: {:?}", exit_code)),
            None => continue,
        }
    }
    Ok(())
}
