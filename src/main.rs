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
use std::{io};

use anyhow::Result;

use nyx_lite::{ExitReason, NyxVM};
use nyx_lite::firecracker_wrappers::{resize_fdtable, ResizeFdTableError};
use utils::arg_parser::{ArgParser, Argument};
use utils::validators::validate_instance_id;
use vmm::logger::{
    debug, error, info, LoggerConfig, LOGGER,
};
use vmm::signal_handler::register_signal_handlers;
use vmm::vmm_config::metrics::{init_metrics, MetricsConfig};


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
    // panic::set_hook(Box::new(move |info| {
    //     // We're currently using the closure parameter, which is a &PanicInfo, for printing the
    //     // origin of the panic, including the payload passed to panic! and the source code location
    //     // from which the panic originated.
    //     error!("NYX-lite {}", info);
    //     if let Err(err) = stdin.lock().set_canon_mode() {
    //         error!(
    //             "Failure while trying to reset stdin to canonical mode: {}",
    //             err
    //         );
    //     }
    // }));

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

    let mut vm = NyxVM::new(instance_id.clone(), &vmm_config_json.unwrap());
    let mut snap = None;
    let mut apply_count = 0;
    let mut addr = 0;
    loop {
        //println!("-------------------[test]-----------------------------");
        let exit_reason = vm.run();
        match exit_reason {
            ExitReason::Hypercall(num, arg1, arg2, arg3) => {
                println!("got hypercall {}({:x}, {:x} {:x})", num, arg1, arg2, arg3);
            },
            ExitReason::RequestSnapshot => {
                snap = Some(vm.take_snapshot());
            },
            ExitReason::ExecDone(exit_code) => {
                if apply_count < 1000 {
                    println!(">>> RESTORE SNAPSHOT");
                    vm.apply_snapshot(snap.as_ref().unwrap());
                    vm.write_current_u64(addr, 0xabcdef12_34567890+apply_count);
                    apply_count += 1;
                }
            },
            ExitReason::SharedMem(name, saddr, size ) => {
                println!("Request to share memory {} at {:x} with size {}", name, addr, size);
                println!("Found: {:x}", vm.read_current_u64(addr));
                addr = saddr;
            },
            ExitReason::Shutdown => {
                break;
            },
            e => {
                println!("unhandled exit reason {:?}", e);
            }
        }
    }
    return Ok(())

}
