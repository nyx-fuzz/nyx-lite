extern crate anyhow;
extern crate event_manager;
extern crate kvm_bindings;
extern crate kvm_ioctls;
extern crate libc;
extern crate thiserror;
extern crate utils;
extern crate vmm;

use std::fs::{self};
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Result;

use libc::{pthread_t, SIGSTOP};
use nyx_lite::{BaseSnapshot, ExitReason, NyxVM};
use utils::arg_parser::{ArgParser, Argument};
use utils::signal::Killable;
use utils::validators::validate_instance_id;
use vmm::devices::virtio::device::VirtioDevice;
use vmm::logger::{error, info, LoggerConfig, LOGGER};

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

struct SuspendForDebugger{}

impl SuspendForDebugger{
    pub fn now(){
        SuspendForDebugger{}.kill(SIGSTOP).expect("failed to pause for debugger");
    }
}

unsafe impl Killable for SuspendForDebugger{
    fn pthread_handle(&self) -> pthread_t {
        let pid = unsafe{libc::getpid()};
        let target_thread = unsafe { libc::pthread_self() };
        println!("suspending current_thread_id :{:?} in pid {:?}", target_thread, pid);
        target_thread
    }
}

fn main_exec() -> Result<()> {
    // Initialize the logger.
    LOGGER.init()?;

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
            );


    arg_parser.parse_from_cmdline()?;
    let arguments = arg_parser.arguments();

    if arguments.flag_present("help") {
        println!("NYX-lite E2E test suite\n");
        println!("{}", arg_parser.formatted_help());
        return Ok(());
    }

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
    let show_level = Some(true);
    let show_log_origin = Some(true);
    let module = arguments.single_value("module").cloned();
    LOGGER.update(LoggerConfig {
        log_path,
        level,
        show_level,
        show_log_origin,
        module,
    })?;
    info!("Running NYX-lite");

    let vmm_config_json = arguments
        .single_value("config")
        .map(fs::read_to_string)
        .map(|x| x.expect("Unable to open or read from the configuration file"));

    let mut vm = NyxVM::new(instance_id.clone(), &vmm_config_json.unwrap());

    info!("TEST: Trying to boot VM to shared memory");
    let shared_vaddr = test_boot_shared_mem(&mut vm);
    info!("TEST: Trying to take a snapshot");
    let snapshot = test_make_snapshot(&mut vm, shared_vaddr);
    info!("TEST: Trying to read/write shared memory");
    test_rw_shared_mem(&mut vm, shared_vaddr);
    info!("TEST: Ensure snapshots handle tsc correctly");
    test_snapshot_tsc(&mut vm, shared_vaddr, &snapshot);
    info!("TEST: Ensure run handles timeouts correctly");
    test_timeout(&mut vm, shared_vaddr, &snapshot);
    info!("TEST: Ensure guest can run subprocesses");
    test_subprocess(&mut vm, shared_vaddr, &snapshot);
    info!("TEST: Ensure filesystem state is reset");
    test_filesystem_reset(&mut vm, shared_vaddr, &snapshot);
    info!("TEST: Ensure VM shuts down cleanly");
    test_shutdown(&mut vm, shared_vaddr, &snapshot);
    info!("RAN ALL TESTS SUCCESSFULLY");
    return Ok(());
}

const DBG_CODE: u64 = 0x65646f635f676264;
const FAILTEST: u64 = 0x747365746c696166;
const TEST_NUM :u64 = 0x7473657400000000;


fn run_vm_test(vm:&mut NyxVM, timeout_millis: u64, desc: &str) -> ExitReason{
    loop {
        let timeout = Duration::from_millis(timeout_millis);
        let exit_reason = vm.run(timeout);
        if let ExitReason::Hypercall(FAILTEST, err_ptr, _, _, _) = exit_reason {
            let err = String::from_utf8_lossy(&vm.read_cstr_current(err_ptr)).to_string();
            panic!("Test {desc} failed with error: {err}");
        }
        if let ExitReason::DebugPrint(val) = exit_reason {
            println!("DBGPRINT: {val}");
        } else {
            return exit_reason;
        }
    }
}

pub fn test_boot_shared_mem(vm: &mut NyxVM) -> u64 {
    let timeout = Duration::from_secs(2);
    let exit_reason = vm.run(timeout);
    match exit_reason {  
        ExitReason::SharedMem(name, saddr, size) => {
            assert_eq!(name, "shared\0", "expected the shared memory to be registered under the name 'shared'");
            assert_eq!(size, 4096, "expected to share exactly one page of memory");
            return saddr;
        },
        _ => {panic!("unexpected exit during boot {exit_reason:?}");}
    }
}

pub fn test_make_snapshot(vm: &mut NyxVM, saddr: u64) -> BaseSnapshot {
    let val = vm.read_current_u64(saddr);
    assert_eq!(val, 0x44434241);
    let timeout = Duration::from_millis(100);
    let exit_reason = vm.run(timeout);
    match exit_reason {
        ExitReason::RequestSnapshot => {
            return vm.take_snapshot();
        },
        _ => {panic!("unexpected exit {exit_reason:?}");}
    };
}

pub fn test_rw_shared_mem(vm: &mut NyxVM, saddr: u64) {
    vm.write_current_u64(saddr, TEST_NUM+1);
    vm.write_current_u64(saddr+8, 0xabcdef12_34567890);
    let exit_reason = run_vm_test(vm, 10, "test_rw_shared_mem: trying to read and write shared data");
    match exit_reason {  
        ExitReason::Hypercall(num, arg1, arg2, arg3, arg4) => {
            assert_eq!(num, DBG_CODE, "unexpected hypercall number: hypercall_dbg_code should use num {DBG_CODE:x}");
            assert_eq!(arg1, 1, "expect dbgcode 1");
            assert_eq!(arg2, 0xb3d4f51738597a91, "expected the memory to be forwarded by the dbg hypercall - got {arg2:x}.");
            assert_eq!(arg3, 0, "expected arg3 to be unused");
            assert_eq!(arg4, 0, "expected arg4 to be unused");
        }
        _ => {panic!("unexpected exit {exit_reason:?}");}
    }
    let val = vm.read_current_u64(saddr+8);
    assert_eq!(val, 0xb3d4f51738597a91, "expected the guest to increment memory, got {val:x}");
}

pub fn test_snapshot_tsc(vm: &mut NyxVM, shared_vaddr: u64, snapshot: &BaseSnapshot) {
    let mut pre_timestamps = vec![];
    let mut post_timestamps = vec![];
    // since tsc is quite noisy, we'll run a couple of times and assert that the
    // values aren't increasing monotonically (or all the same - which would be
    // nice, but for now kvm doesn't allow perfect tsc control).
    for _i in 0..10 {
        vm.apply_snapshot(snapshot);
        vm.write_current_u64(shared_vaddr, TEST_NUM+2);
        vm.write_current_u64(shared_vaddr+8, 0x1234567812345678);
        let exit_reason = run_vm_test(vm, 10, "test_snapshot_tsc: seeing how tsc responds to snapshot resets");
        match exit_reason {
            ExitReason::Hypercall(num, pre, post, _ ,_ ) => {
                assert_eq!(num, DBG_CODE);
                pre_timestamps.push(pre);
                post_timestamps.push(post);
            },
            _ => panic!("unexpected exit {exit_reason:?}")
        }
    }
    let mut last_post = 0;
    let mut post_monotonic  = true;
    let mut post_all_equal = true;
    for (pre,post) in pre_timestamps.iter().zip(post_timestamps.iter()) {
        assert_eq!(*pre, pre_timestamps[0], "all tsc values for pre snapshots should be the same");
        assert!(pre <= post, "post snapshot tsc values should be greater or equal to pre snapshot tsc values");
        if *post < last_post {
            post_monotonic = false;
        }
        if *post != post_timestamps[0]{
            post_all_equal = false;
        }
        last_post = *post;
    }
    assert!(!post_monotonic || post_all_equal, "tsc values shouldn't be increasing monotonically - this indicates the clock doesn't get set back properly")
}

pub fn test_timeout(vm: &mut NyxVM, shared_vaddr: u64, snapshot: &BaseSnapshot) {
    vm.apply_snapshot(snapshot);
    vm.write_current_u64(shared_vaddr, TEST_NUM+3);
    let start_time = Instant::now();
    let exit_reason = run_vm_test(vm, 100, "test_timeout: make sure we can interrupt blocked vm_runs");
    match exit_reason {
        ExitReason::Timeout => {
            assert!( (Instant::now()-start_time)<Duration::from_millis(200) );
        }, 
        _ => panic!("unexpected exit {exit_reason:?}")
    };
}

pub fn test_subprocess(vm: &mut NyxVM, shared_vaddr: u64, snapshot: &BaseSnapshot) {
    vm.apply_snapshot(snapshot);
    vm.write_current_u64(shared_vaddr, TEST_NUM+4);
    let exit_reason = run_vm_test(vm, 500, "test_subprocess: ensure the guest can spawn new processes");
    match exit_reason {
        ExitReason::ExecDone(code) => { assert_eq!(code, 23, "subprocess test should yield code 23")}, 
        _ => panic!("unexpected exit {exit_reason:?}")
    };
}

pub fn test_filesystem_reset(vm: &mut NyxVM, shared_vaddr: u64, snapshot: &BaseSnapshot) {
    // run twice to ensure the files get reset correctly
    // test writes
    for _ in 0..2 {
        vm.apply_snapshot(snapshot);
        vm.write_current_u64(shared_vaddr, TEST_NUM+5);
        let exit_reason = run_vm_test(vm, 100, "test_subprocess: ensure that the file system is reset on snapshots");
        match exit_reason {
            ExitReason::ExecDone(code) => { assert_eq!(code, 42, "filesystem test should yield code 42")}, 
            _ => {
                //SuspendForDebugger::now();
                panic!("unexpected exit {exit_reason:?}");
            }
        };
    }
    // test reads
    for _ in 0..2 {
        vm.apply_snapshot(snapshot);
        vm.write_current_u64(shared_vaddr, TEST_NUM+6);
        let exit_reason = run_vm_test(vm, 100, "test_subprocess: ensure that the file system is reset on snapshots");
        match exit_reason {
            ExitReason::ExecDone(code) => { assert_eq!(code, 42, "filesystem test should yield code 42")}, 
            _ => {
                panic!("unexpected exit {exit_reason:?}");
            }
        };
    }
}

pub fn test_shutdown(vm: &mut NyxVM, shared_vaddr: u64, snapshot: &BaseSnapshot) {
    vm.apply_snapshot(snapshot);
    vm.write_current_u64(shared_vaddr, TEST_NUM+9999);
    let exit_reason = run_vm_test(vm, 100, "test_shutdown: ensure that the vm can respond to shutdown cleanly");
    match exit_reason {
        ExitReason::Shutdown => {}, 
        _ => panic!("unexpected exit {exit_reason:?}")
    };
}
