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
use std::time::{Duration, Instant};

use anyhow::Result;

use libc::{pthread_t, SIGSTOP};
use nyx_lite::disassembly::{self, disassemble_print};
use nyx_lite::mem::{NyxMemExtension, PagePermission};
use nyx_lite::vm_continuation_statemachine::VMContinuationState;
use nyx_lite::{BaseSnapshot, ExitReason, NyxVM};
use utils::arg_parser::{ArgParser, Argument};
use utils::signal::Killable;
use utils::validators::validate_instance_id;
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
    info!("TEST: Ensure single steping works");
    test_single_step(&mut vm, shared_vaddr, &snapshot);
    //info!("TEST: Ensure branch steping works");
    //test_branch_step(&mut vm, shared_vaddr, &snapshot);
    info!("TEST: Ensure host bps are returned as exits");
    test_host_bp(&mut vm, shared_vaddr, &snapshot);
    info!("TEST: Ensure host code hw-bps are returned as exits");
    test_host_hw_bp(&mut vm, shared_vaddr, &snapshot);
    info!("TEST: Ensure guest bp are injected properly");
    test_guest_bp(&mut vm, shared_vaddr, &snapshot);
    info!("TEST: Ensure we can use hardware breakpoints for memory accesses");
    test_mem_bp(&mut vm, shared_vaddr, &snapshot);
    info!("TEST: Ensure we trigger vm exits by mprotect");
    test_mem_permissions(&mut vm, shared_vaddr, &snapshot);
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
    let timeout = Duration::from_secs(10);
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

pub fn test_single_step(vm: &mut NyxVM, shared_vaddr: u64, snapshot: &BaseSnapshot) {
    vm.apply_snapshot(snapshot);
    vm.write_current_u64(shared_vaddr, TEST_NUM+7);
    let exit_reason = run_vm_test(vm, 100, "test_single_step: test get to known code for singlestep");
    let (cr3, code_addr) = match exit_reason {
        ExitReason::Hypercall(num, arg1, _arg2, _arg3, _arg4) => {
            assert_eq!(num, DBG_CODE, "unexpected hypercall number: hypercall_dbg_code should use num {DBG_CODE:x}");
            assert_eq!(arg1, 3366, "expect dbgcode 3366");
            let cr3 = vm.sregs().cr3;
            let code_addr = vm.regs().rip;
            (cr3, code_addr)
        },
        _ => {
            panic!("unexpected exit {exit_reason:?}");
        }
    };
    // Code after the DBG_CODE hypercall is:
    // int 3         # cc <- rip is here
    // mov rax,1234  # 48 c7 c0 d2 04 00 00
    // add rax,1     # 48 83 c0 01
    // add rax,2     # 48 83 c0 02 
    // add rax,3     # 48 83 c0 03
    // add rax,4     # 48 83 c0 04
    let exit_reason = vm.single_step(Duration::from_millis(10));
    match exit_reason {
        ExitReason::SingleStep => {/* EXPECTED */},
        _ => { panic!("unexpected exit {exit_reason:?}"); }
    };
    // note this test sometimes fails for some reason
    assert_eq!(cr3, vm.sregs().cr3, "cr3 changed during singlestep");
    assert_eq!(vm.regs().rax, 1234);
    assert_eq!(vm.regs().rip, code_addr + 1 + 7); // 1 = sizeof(int 3), 7 = sizeof(mov rax,1234)
    let exit_reason = vm.single_step(Duration::from_millis(10));
    match exit_reason {
        ExitReason::SingleStep => {/* EXPECTED */},
        _ => { panic!("unexpected exit {exit_reason:?}"); }
    };
    assert_eq!(cr3, vm.sregs().cr3);
    assert_eq!(vm.regs().rax, 1235);
    assert_eq!(vm.regs().rip, code_addr + 1 + 7 + 4); // 1+ 7 + 4 = sizeof(int 3) + sizeof(mov rax,1234) + sizeof(add rax,1)
    let exit_reason = vm.single_step(Duration::from_millis(10));
    match exit_reason {
        ExitReason::SingleStep => {/* EXPECTED */},
        _ => { panic!("unexpected exit {exit_reason:?}"); }
    };
    assert_eq!(cr3, vm.sregs().cr3);
    assert_eq!(vm.regs().rax, 1237);
    assert_eq!(vm.regs().rip, code_addr + 1+ 7 + 2*4); // 1+ 7 + 2*4 = sizeof(int 3) + sizeof(mov rax,1234) + 2*sizeof(add rax,1)
}

/*
pub fn test_branch_step(vm: &mut NyxVM, shared_vaddr: u64, snapshot: &BaseSnapshot) {
    vm.apply_snapshot(snapshot);
    vm.write_current_u64(shared_vaddr, TEST_NUM+10);
    let exit_reason = run_vm_test(vm, 100, "test_single_step_branch: test code for singlestep in branch mode");
    let (cr3, code_addr) = match exit_reason {
        ExitReason::Hypercall(num, arg1, _arg2, _arg3, _arg4) => {
            assert_eq!(num, DBG_CODE, "unexpected hypercall number: hypercall_dbg_code should use num {DBG_CODE:x}");
            assert_eq!(arg1, 3366, "expect dbgcode 3366");
            let cr3 = vm.sregs().cr3;
            let code_addr = vm.regs().rip;
            (cr3, code_addr)
        },
        _ => {
            panic!("unexpected exit {exit_reason:?}");
        }
    };

    // disassemble_print(code_addr, &vm.read_current_bytes(code_addr, 128));
    // + 0 CC                  int3
    // + 1 48C7C0D2040000      mov       rax,4D2h
    // + 8 49C7C300000000      mov       r11,0
    // +15 4983FA2A            cmp       r10,2Ah
    // +19 7402                je        +21
    // +21 EB11                jmp       +40
    // +23 49C7C301000000      mov       r11,1
    // +30 4983FA64            cmp       r10,64h
    // +34 7D04                jge       +40
    // +36 4983C301            add       r11,1
    // +40 E96D060000          jmp       ...

    let exit_reason = vm.branch_step(Duration::from_millis(10));
    match exit_reason {
        ExitReason::SingleStep => {/* EXPECTED */},
        _ => { panic!("unexpected exit {exit_reason:?}"); }
    };
    assert_eq!(cr3, vm.sregs().cr3, "cr3 changed during singlestep");
    assert_eq!(vm.regs().rax, 1234);
    assert_eq!(vm.regs().rip, code_addr + 1 + 7); // 1 = sizeof(int 3), 7 = sizeof(mov rax,1234)

    let exit_reason = vm.branch_step(Duration::from_millis(10));
    match exit_reason {
        ExitReason::SingleStep => {/* EXPECTED */},
        _ => { panic!("unexpected exit {exit_reason:?}"); }
    };
    // note this test sometimes fails for some reason
    assert_eq!(cr3, vm.sregs().cr3, "cr3 changed during singlestep");
    assert_eq!(vm.regs().rax, 1234);
    assert_eq!(vm.regs().rip, code_addr + 15); 
} */

pub fn test_host_bp(vm: &mut NyxVM, shared_vaddr: u64, snapshot: &BaseSnapshot){
    vm.apply_snapshot(snapshot);
    vm.write_current_u64(shared_vaddr, TEST_NUM+7);

    let exit_reason = run_vm_test(vm, 100, "test_host_bp: test get to known code for host bps");
    let (cr3, code_addr) = match exit_reason {
        ExitReason::Hypercall(num, arg1, _arg2, _arg3, _arg4) => {
            assert_eq!(num, DBG_CODE, "unexpected hypercall number: hypercall_dbg_code should use num {DBG_CODE:x}");
            assert_eq!(arg1, 3366, "expect dbgcode 3366");
            let cr3 = vm.sregs().cr3;
            let code_addr = vm.regs().rip;
            (cr3, code_addr)
        },
        _ => {
            panic!("unexpected exit {exit_reason:?}");
        }
    };
    // Code after the DBG_CODE hypercall is:
    // +00 int 3         # cc <- rip is here
    // +01 mov rax,1234  # 48 c7 c0 d2 04 00 00
    // +08 add rax,1     # 48 83 c0 01 *BP
    // +12 add rax,2     # 48 83 c0 02 
    // +16 add rax,3     # 48 83 c0 03 *BP
    // +20 add rax,4     # 48 83 c0 04 *BP
    //disassemble_print(code_addr, &vm.read_current_bytes(code_addr, 24));
    vm.add_breakpoint(cr3, code_addr+8); // breakpoint `add rax,1`
    vm.add_breakpoint(cr3, code_addr+16); // breakpoint `add rax,3`
    vm.add_breakpoint(cr3, code_addr+20); // breakpoint `add rax,4`

    let exit_reason = run_vm_test(vm, 100, "test_host_bp: test get to next bps");
    match exit_reason {
        ExitReason::Breakpoint => assert_eq!(vm.regs().rip, code_addr+8),
        _ => panic!("unexpected exit {exit_reason:?}"),
    };
    let exit_reason = run_vm_test(vm, 100, "test_host_bp: test get to next bps");
    match exit_reason {
        ExitReason::Breakpoint => assert_eq!(vm.regs().rip, code_addr+16),
        _ => panic!("unexpected exit {exit_reason:?}"),
    };
    let exit_reason = run_vm_test(vm, 100, "test_host_bp: test get to next bps");
    match exit_reason {
        ExitReason::Breakpoint => assert_eq!(vm.regs().rip, code_addr+20),
        _ => panic!("unexpected exit {exit_reason:?}"),
    };
    let mut regs = vm.regs();
    regs.rip = code_addr+1; // jump back to mov rax, 1234
    vm.set_regs(&regs);

    let exit_reason = run_vm_test(vm, 100, "test_host_bp: test get to next bps");
    match exit_reason {
        ExitReason::Breakpoint => assert_eq!(vm.regs().rip, code_addr+8),
        _ => panic!("unexpected exit {exit_reason:?}"),
    };

    // test steping off a breakpoint
    let exit_reason = vm.single_step(Duration::from_millis(10));
    match exit_reason {
        ExitReason::SingleStep => assert_eq!(vm.regs().rip, code_addr+12),
        _ => { panic!("unexpected exit {exit_reason:?}"); }
    };
    // test stepping onto a breakpoint
    // NOTE: we are seeing a single_step vm exit, not a breakpoint VM exit.
    let exit_reason = vm.single_step(Duration::from_millis(10));
    match exit_reason {
        ExitReason::SingleStep => assert_eq!(vm.regs().rip, code_addr+16),
        _ => { panic!("unexpected exit {exit_reason:?}"); }
    };
    // we are currently on a breakpoint, after singlestepping on it (a similar state would be achieved by setting rip directly to this address)
    // we trigger a second VM exit, this time we see the breakpoint VM Exit.
    let exit_reason = run_vm_test(vm, 100, "test_host_bp: run off singlesteped bp");
    match exit_reason {
        ExitReason::Breakpoint => assert_eq!(vm.regs().rip, code_addr+16),
        _ => { panic!("unexpected exit {exit_reason:?}"); }
    };

    let exit_reason = run_vm_test(vm, 100, "test_host_bp: run off acknowledged bp");
    match exit_reason {
        ExitReason::Breakpoint => assert_eq!(vm.regs().rip, code_addr+20),
        _ => { panic!("unexpected exit {exit_reason:?}"); }
    };

    let exit_reason = run_vm_test(vm, 100, "test_host_bp: run off singlesteped bp");
    match exit_reason {
        ExitReason::ExecDone(code) => assert_eq!(code, 0),
        _ => { panic!("unexpected exit {exit_reason:?}"); }
    };

    // test jumping straight ontop of a breakpoint & continue running
    // NOTE when we change IP and don't want to miss the first breakpoint we need to reset the continueation state - TODO fix this!
    vm.continuation_state=VMContinuationState::Main; 
    let mut regs = vm.regs();
    regs.rax = 0; // currently rax is still the hypercall value because we teleported rip - so the breakpoint would be missclassified as hypercall
    regs.rip = code_addr+8;     // +08 add rax,1     # 48 83 c0 01 *BP
    vm.set_regs(&regs);
    let exit_reason = run_vm_test(vm, 100, "test_host_bp: run off teleported bp");
    match exit_reason {
        ExitReason::Breakpoint => assert_eq!(vm.regs().rip, code_addr+8),
        _ => { panic!("unexpected exit {exit_reason:?}"); }
    };
    let exit_reason = run_vm_test(vm, 100, "test_host_bp: run off teleported bp");
    match exit_reason {
        ExitReason::Breakpoint => assert_eq!(vm.regs().rip, code_addr+16),
        _ => { panic!("unexpected exit {exit_reason:?}"); }
    };

    // test jumping straight ontop of a breakpoint & continue running
    // NOTE when we change IP and don't want to miss the first breakpoint we need to reset the continueation state - TODO fix this!
    vm.continuation_state=VMContinuationState::Main; 
    let mut regs = vm.regs();
    regs.rax = 0; // currently rax is still the hypercall value because we teleported rip - so the breakpoint would be missclassified as hypercall
    regs.rip = code_addr+8;     // +08 add rax,1     # 48 83 c0 01 *BP
    vm.set_regs(&regs);
    let exit_reason = vm.single_step(Duration::from_millis(10));
    //println!("exit step onto {:?} at {:x?}", exit_reason, vm.regs().rip);
    match exit_reason {
        ExitReason::Breakpoint => assert_eq!(vm.regs().rip, code_addr+8),
        _ => { panic!("unexpected exit {exit_reason:?}"); }
    };
    let exit_reason = run_vm_test(vm, 100, "test_host_bp: run off teleported bp");
    match exit_reason {
        ExitReason::Breakpoint => assert_eq!(vm.regs().rip, code_addr+16),
        _ => { panic!("unexpected exit {exit_reason:?}"); }
    };
    vm.remove_all_breakpoints();
}

pub fn test_host_hw_bp(vm: &mut NyxVM, shared_vaddr: u64, snapshot: &BaseSnapshot){
    vm.apply_snapshot(snapshot);
    vm.write_current_u64(shared_vaddr, TEST_NUM+7);

    let exit_reason = run_vm_test(vm, 100, "test_host_hw_bp: test get to known code for host bps");
    let code_addr = match exit_reason {
        ExitReason::Hypercall(num, arg1, _arg2, _arg3, _arg4) => {
            assert_eq!(num, DBG_CODE, "unexpected hypercall number: hypercall_dbg_code should use num {DBG_CODE:x}");
            assert_eq!(arg1, 3366, "expect dbgcode 3366");
            let code_addr = vm.regs().rip;
            code_addr
        },
        _ => {
            panic!("unexpected exit {exit_reason:?}");
        }
    };
    // Code after the DBG_CODE hypercall is:
    // +00 int 3         # cc <- rip is here
    // +01 mov rax,1234  # 48 c7 c0 d2 04 00 00
    // +08 add rax,1     # 48 83 c0 01 *BP
    // +12 add rax,2     # 48 83 c0 02 
    // +16 add rax,3     # 48 83 c0 03 *BP
    // +20 add rax,4     # 48 83 c0 04 *BP
    //disassemble_print(code_addr, &vm.read_current_bytes(code_addr, 24));
    vm.hw_breakpoints.enable_exec(0, code_addr+8);
    vm.hw_breakpoints.enable_exec(1, code_addr+16);
    vm.hw_breakpoints.enable_exec(2, code_addr+20);
    let exit_reason = run_vm_test(vm, 100, "test_host_hw_bp: test get to next bps");
    match exit_reason {
        ExitReason::HWBreakpoint(0) => assert_eq!(vm.regs().rip, code_addr+8),
        _ => panic!("unexpected exit {exit_reason:?}"),
    };
    vm.hw_breakpoints.disable(0);
    let exit_reason = run_vm_test(vm, 100, "test_host_hw_bp: test get to next bps");
    match exit_reason {
        ExitReason::HWBreakpoint(1) => assert_eq!(vm.regs().rip, code_addr+16),
        _ => panic!("unexpected exit {exit_reason:?}"),
    };
    vm.hw_breakpoints.disable(1);
    let exit_reason = run_vm_test(vm, 100, "test_host_hw_bp: test get to next bps");
    match exit_reason {
        ExitReason::HWBreakpoint(2) => assert_eq!(vm.regs().rip, code_addr+20),
        _ => panic!("unexpected exit {exit_reason:?}"),
    };
}

pub fn test_guest_bp(vm: &mut NyxVM, shared_vaddr: u64, snapshot: &BaseSnapshot) {
    vm.apply_snapshot(snapshot);
    vm.write_current_u64(shared_vaddr, TEST_NUM+8);
    let exit_reason = run_vm_test(vm, 100, "test_guest_bp: run until first hypercall");
    match exit_reason {
        ExitReason::Hypercall(num, arg1, arg2, _arg3, _arg4) => {
            assert_eq!(num, DBG_CODE, "unexpected hypercall number: hypercall_dbg_code should use num {DBG_CODE:x}");
            assert_eq!(arg1, 1234, "expect dbgcode 1234");
            assert_eq!(arg2, 42, "expected the global to be 42 initially");
        },
        _ => {
            panic!("unexpected exit {exit_reason:?}");
        }
    };
    let exit_reason = run_vm_test(vm, 100, "test_subprocess: ensure that the breakpoints are triggering the signal handler");
    match exit_reason {
        ExitReason::Hypercall(num, arg1, arg2, _arg3, _arg4) => {
            assert_eq!(num, DBG_CODE, "unexpected hypercall number: hypercall_dbg_code should use num {DBG_CODE:x}");
            assert_eq!(arg1, 1234, "expect dbgcode 1234");
            assert_eq!(arg2, 42 + 2 * 13, "expect to call the signal handler twice");
        },
        _ => {
            panic!("unexpected exit {exit_reason:?}");
        }
    };
}

pub fn test_mem_bp(vm: &mut NyxVM, shared_vaddr: u64, snapshot: &BaseSnapshot){
    vm.apply_snapshot(snapshot);
    vm.write_current_u64(shared_vaddr, TEST_NUM+9); 
    let exit_reason = run_vm_test(vm, 100, "test_mem_bp: trying to get guest pointer");
    let (offset, data) = match exit_reason {
        ExitReason::Hypercall(num, arg1, arg2, _arg3, _arg4) => { 
            assert_eq!(num, DBG_CODE, "unexpected hypercall number: hypercall_dbg_code should use num {DBG_CODE:x}");
            (arg1, arg2)
        },
        _ => panic!("unexpected exit {exit_reason:?}")
    };
    vm.hw_breakpoints.enable_access(0, data+0x1000*8, 8);
    vm.write_current_u64(offset, 0x1000); // access data + 0x1000
    let exit_reason = run_vm_test(vm, 100, "test_mem_bp: read offset");
    match exit_reason {
        ExitReason::HWBreakpoint(0) => {},
        _ => panic!("unexpected exit {exit_reason:?}")
    };
    vm.hw_breakpoints.disable(0);
    let exit_reason = run_vm_test(vm, 100, "test_mem_bp: read offset");
    match exit_reason {
        ExitReason::Hypercall(num, arg1, arg2, _arg3, _arg4) => { 
            assert_eq!(num, DBG_CODE, "unexpected hypercall number: hypercall_dbg_code should use num {DBG_CODE:x}");
            assert_eq!(arg1, 0);
            assert_eq!(arg2, 42);
        },
        _ => panic!("unexpected exit {exit_reason:?}")
    };
    vm.hw_breakpoints.enable_access(1, data+0x1000*8, 8);
    let exit_reason = run_vm_test(vm, 100, "test_mem_bp: write offset");
    match exit_reason {
        ExitReason::HWBreakpoint(1) => {},
        _ => panic!("unexpected exit {exit_reason:?}")
    };
    vm.hw_breakpoints.disable(1);
    let exit_reason = run_vm_test(vm, 100, "test_mem_bp: write offset");
    match exit_reason {
        ExitReason::Hypercall(num, arg1, arg2, _arg3, _arg4) => { 
            assert_eq!(num, DBG_CODE, "unexpected hypercall number: hypercall_dbg_code should use num {DBG_CODE:x}");
            assert_eq!(arg1, 1);
            assert_eq!(arg2, 0);
        },
        _ => panic!("unexpected exit {exit_reason:?}")
    };
}
pub fn test_mem_permissions(vm: &mut NyxVM, shared_vaddr: u64, snapshot: &BaseSnapshot){
    vm.apply_snapshot(snapshot);
    vm.write_current_u64(shared_vaddr, TEST_NUM+9); // subprocess will do a bunch of branches
    let exit_reason = run_vm_test(vm, 100, "test_subprocess: trying to get guest pointer");
    let (offset, data) = match exit_reason {
        ExitReason::Hypercall(num, arg1, arg2, _arg3, _arg4) => { 
            assert_eq!(num, DBG_CODE, "unexpected hypercall number: hypercall_dbg_code should use num {DBG_CODE:x}");
            (arg1, arg2)
        },
        _ => panic!("unexpected exit {exit_reason:?}")
    };

    let cr3 = vm.sregs().cr3;
    vm.vmm.lock().unwrap().set_virtual_page_permission(cr3, data+0x1000*8, PagePermission::None);
    vm.write_current_u64(offset, 0x1000); // access data + 0x1000
    let exit_reason = run_vm_test(vm, 100, "test_subprocess: read offset");
    match exit_reason {
        ExitReason::BadMemoryAccess(vec) => {assert_eq!(vec, [(data+0x1000*8, disassembly::OpAccess::Read)])},
        _ => panic!("unexpected exit {exit_reason:?}")
    };
    vm.vmm.lock().unwrap().set_virtual_page_permission(cr3, data+0x1000*8, PagePermission::R);
    let exit_reason = run_vm_test(vm, 100, "test_subprocess: read offset");
    match exit_reason {
        ExitReason::Hypercall(num, arg1, arg2, _arg3, _arg4) => { 
            assert_eq!(num, DBG_CODE, "unexpected hypercall number: hypercall_dbg_code should use num {DBG_CODE:x}");
            assert_eq!(arg1, 0);
            assert_eq!(arg2, 42);
        },
        _ => panic!("unexpected exit {exit_reason:?}")
    };
    let exit_reason = run_vm_test(vm, 100, "test_subprocess: write offset");
    match exit_reason {
        ExitReason::BadMemoryAccess(vec) => {assert_eq!(vec, [(data+0x1000*8, disassembly::OpAccess::Write)])},
        _ => panic!("unexpected exit {exit_reason:?}")
    };
    vm.vmm.lock().unwrap().set_virtual_page_permission(cr3, data+0x1000*8, PagePermission::RW);
    let exit_reason = run_vm_test(vm, 100, "test_subprocess: write offset");
    match exit_reason {
        ExitReason::Hypercall(num, arg1, arg2, _arg3, _arg4) => { 
            assert_eq!(num, DBG_CODE, "unexpected hypercall number: hypercall_dbg_code should use num {DBG_CODE:x}");
            assert_eq!(arg1, 1);
            assert_eq!(arg2, 0);
        },
        _ => panic!("unexpected exit {exit_reason:?}")
    };
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
