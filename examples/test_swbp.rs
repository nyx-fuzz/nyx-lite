use std::arch::asm;
use std::ffi::CString;
use std::io::Write;
use std::process::ExitCode;
use std::time::Duration;

const EXECDONE: u64 = 0x656e6f6463657865;
const SNAPSHOT: u64 = 0x746f687370616e73;
const NYX_LITE: u64 = 0x6574696c2d78796e;
const SHAREMEM: u64 = 0x6d656d6572616873;

fn hypercall(hypercall_num: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64) {
    unsafe {
        asm!(
            "int 3",
            in("rax") NYX_LITE,
            in("r8") hypercall_num,
            in("r9") arg1,
            in("r10") arg2,
            in("r11") arg3,
            in("r12") arg4,
        );
    }
}

fn hypercall_register_region(name: &str, mem: &mut [u8]) {
    let c_name = CString::new(name).unwrap();
    //   hypercall_num, arg1,                 , arg2                   , arg3         , arg4
    hypercall(
        SHAREMEM,
        c_name.as_ptr() as u64,
        mem.as_mut_ptr() as u64,
        mem.len() as u64,
        0,
    );
}

fn hypercall_snapshot() {
    hypercall(SNAPSHOT, 0, 0, 0, 0);
}

fn hypercall_done(exit_code: u64) {
    let _ = std::io::stdout().flush();
    hypercall(EXECDONE, exit_code, 0, 0, 0);
}

fn hypercall_dbg_code(dbg_code: u64, arg1: u64) {
    hypercall(0x133742, dbg_code, arg1, 0, 0);
}

fn main() -> ExitCode {
    let mut shared = vec![0; 4096];
    println!(
        "***TEST TARGET***: Start setup {:x}",
        shared.as_ptr() as u64
    );
    shared[0] = 0x41;
    shared[1] = 0x42;
    shared[2] = 0x43;
    hypercall_register_region("shared", &mut shared);
    shared[0] = 0x30;
    shared[1] = 0x41;
    shared[2] = 0x31;
    shared[4] = 0x42;
    shared[5] = 0x32;
    shared[6] = 0x43;
    shared[7] = 0x33;
    shared[8] = 0x44;
    std::hint::black_box(&mut shared);
    let presnap_time = unsafe { core::arch::x86_64::_rdtsc() };
    hypercall_snapshot();
    let postsnap_time = unsafe { core::arch::x86_64::_rdtsc() };
    std::hint::black_box(&mut shared);
    //hypercall_dbg_code(1, postsnap_time-presnap_time);
    //println!("***TEST TARGET***: tsc delta: {}", postsnap_time-presnap_time);
    println!(
        "***TEST TARGET***: First byte in shared mem is: 0x{:x}",
        shared[0]
    );
    let _ = std::io::stdout().flush();
    if shared[0] > 0x95 {
        println!( "***TEST TARGET***: Going to Sleep for 100 seconds - test timeout",);
        let _ = std::io::stdout().flush();
        std::thread::sleep(Duration::from_secs(100));
    }
    shared[0] = 0x41;
    shared[1] = 0x42;
    shared[2] = 0x43;
    std::hint::black_box(&mut shared);
    hypercall_done(1);
    //println!("***TEST_TARGET***: finished, initiate syscall based shutdown");
    //let _ = std::io::stdout().flush();
    //shutdown();
    //println!("*** I GUESS SHUTDOWN RETURNED? WEIRD, VM SHOULD BE DEAD NOW");
    //use std::process::{Command, Stdio};

    //let _output = Command::new("ls")
    //    .arg("-lash")
    //    .stdout(Stdio::inherit())
    //    .stderr(Stdio::inherit())
    //    .output()
    //    .expect("Failed to execute command");

    //println!("***TEST_TARGET***: sleeping");
    //let _ = std::io::stdout().flush();
    //hypercall_dbg_code(2, 0);
    //use std::{thread, time};
    //let delay = time::Duration::from_secs(1);
    //thread::sleep(delay);
    //println!("***TEST_TARGET***: done");
    //let _ = std::io::stdout().flush();
    //hypercall_dbg_code(2, 1);

    //for i in (0..10){
    //    hypercall_dbg_code(3, i);
    //    println!("***TEST_TARGET***: finished, exit main");
    //    let _ = std::io::stdout().flush();
    //}
    //hypercall_dbg_code(4, 1);
    //let output = Command::new("reboot")
    //    //.arg("-f")
    //    .stdout(Stdio::inherit())
    //    .stderr(Stdio::inherit())
    //    .output();
    //println!("returned {:?}", output);
    //hypercall_dbg_code(4, 2);
    return ExitCode::SUCCESS;
}

fn shutdown() {
    //system call on 64-bit Linux, syscall number in rax, and args: rdi, rsi, rdx, r10, r8, and r9
    //int syscall(SYS_reboot, int magic, int magic2, int op, void *arg);
    let mut sys_reboot = 169_u64;
    let magic = 0xfee1dead_u64;
    let magic2 = 0x28121969_u64;
    let op = 0x1234567_u64;
    let arg = 0_u64;
    unsafe {
        asm!(
            "syscall",
            inout("rax") sys_reboot,
            in("rdi") magic,
            in("rsi") magic2,
            in("rdx") op,
            in("r10") arg,
        );
    }
    println!("syscall returned with exit code {sys_reboot:x}");
}
