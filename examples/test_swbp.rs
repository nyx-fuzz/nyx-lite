use std::ffi::CString;
use std::io::Write;
use std::process::ExitCode;
use std::arch::asm;

const EXECDONE :u64 = 0x656e6f6463657865;
const SNAPSHOT :u64 = 0x746f687370616e73;
const NYX_LITE :u64 = 0x6574696c2d78796e;
const SHAREMEM :u64 = 0x6d656d6572616873;


fn hypercall(hypercall_num: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64) {
    unsafe{
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

fn hypercall_register_region(name: &str, mem: &mut[u8]){
    let c_name = CString::new(name).unwrap();
    hypercall(SHAREMEM, c_name.as_ptr() as u64, mem.as_mut_ptr() as u64, mem.len() as u64, 0);
}

fn hypercall_snapshot(){
    hypercall(SNAPSHOT,0,0,0,0);
}

fn hypercall_done(exit_code: u64){
    let _ = std::io::stdout().flush();
    hypercall(EXECDONE,exit_code,0,0,0);
}

fn main() -> ExitCode {
    let mut shared = vec![0; 4096];
    println!("***TEST TARGET***: Start setup {:x}", shared.as_ptr() as u64);
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
    hypercall_snapshot();
    std::hint::black_box(&mut shared);
    println!("***TEST TARGET***: First byte in shared mem is: 0x{:x}", shared[0]);
    let _ = std::io::stdout().flush();
    shared[0] = 0x41;
    shared[1] = 0x42;
    shared[2] = 0x43;
    std::hint::black_box(&mut shared);
    hypercall_done(1);
    println!("***TEST_TARGET***: finished, exit main");
    return ExitCode::SUCCESS;
}