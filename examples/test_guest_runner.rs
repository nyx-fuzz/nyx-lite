use std::arch::asm;
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

const EXECDONE: u64 = 0x656e6f6463657865;
const SNAPSHOT: u64 = 0x746f687370616e73;
const NYX_LITE: u64 = 0x6574696c2d78796e;
const SHAREMEM: u64 = 0x6d656d6572616873;
const DBG_CODE: u64 = 0x65646f635f676264;
const FAILTEST: u64 = 0x747365746c696166;
const TEST_NUM :u64 = 0x7473657400000000;
const DBGPRINT: u64 = 0x746e697270676264;

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
    hypercall(DBG_CODE, dbg_code, arg1, 0, 0);
}

fn hypercall_dbg_print(val: &str){
    let c_name = CString::new(val).unwrap();
    //   hypercall_num, arg1,                 , arg2                   , arg3         , arg4
    hypercall(
        DBGPRINT,
        c_name.as_ptr() as u64,
        0,
        0,
        0,
    );
}

fn hypercall_fail_test(error: &str){
    let c_name = CString::new(error).unwrap();
    hypercall(
        FAILTEST,
        c_name.as_ptr() as u64,
        0,
        0,
        0,
    );
}

fn read_u64(arr: &[u8]) -> u64{
        (arr[0] as u64) << (0*8) | 
        (arr[1] as u64) << (1*8) |
        (arr[2] as u64) << (2*8) |
        (arr[3] as u64) << (3*8) |
        (arr[4] as u64) << (4*8) |
        (arr[5] as u64) << (5*8) |
        (arr[6] as u64) << (6*8) |
        (arr[7] as u64) << (7*8) 
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
    shared[3] = 0x44;
    std::hint::black_box(&mut shared);
    hypercall_register_region("shared", &mut shared);  // test_boot_shared_mem runs until here

    let presnap_time = unsafe { core::arch::x86_64::_rdtsc() };
    hypercall_snapshot(); // test_make_snapshot runs until here
    let postsnap_time = unsafe { core::arch::x86_64::_rdtsc() };

    std::hint::black_box(&mut shared);
    let test_id = read_u64(&shared);
    if test_id & 0xffffffff00000000 != TEST_NUM{
        hypercall_fail_test(&format!("expected valid test id. Got {test_id:x}, expected {TEST_NUM:x}+i"));
    }
    let mut data = &mut shared[8..];
    let test_id = test_id & 0xffffffff;
    match test_id {
        1 => test_rw_shared_mem(&mut data),
        2 => test_snapshot_tsc(presnap_time, postsnap_time),
        3 => test_timeout(),
        4 => test_run_subprocess(),
        5 => test_write_file(),
	6 => test_read_file(),
        9999=> test_shutdown(),
        _ => hypercall_fail_test(&format!("no test found for {test_id}")),
    }
    std::hint::black_box(&mut shared);
    return ExitCode::SUCCESS;
}

fn test_rw_shared_mem(shared: &mut[u8]){
    shared[0] += 1;
    shared[1] += 2;
    shared[2] += 3;
    shared[3] += 4;
    shared[4] += 5;
    shared[5] += 6;
    shared[6] += 7;
    shared[7] += 8;
    std::hint::black_box(&shared);
    hypercall_dbg_code(1, read_u64(shared)); // test_rw_shared_mem
}

fn test_snapshot_tsc(presnap_time: u64, postsnap_time: u64){
    hypercall_dbg_code(presnap_time, postsnap_time);
}

fn test_timeout(){
    thread::sleep(Duration::from_secs(2));
    hypercall_fail_test(&format!("This sleep should not have returned"));
}

fn test_run_subprocess(){
    use std::process::{Command, Stdio};

    let mut child = Command::new("ls").args(["-lash","/"]).spawn().unwrap();
    child.wait().unwrap();

    let mut child = Command::new("cat").args(["/proc/iomem"]).spawn().unwrap();
    child.wait().unwrap();

    //thread::sleep(Duration::from_secs(5));

    let mut child = Command::new("md5sum")
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .spawn().unwrap();

    let mut child_stdin = child.stdin.take().unwrap();
    child_stdin.write_all(b"Hello, world!\n").unwrap();
    drop(child_stdin);
    let output = child.wait_with_output().unwrap();
    let str = String::from_utf8_lossy(&output.stdout);
    let substr = &str[..32];
    let expected = "746308829575e17c3331bbcb00c0898b";
    if substr != expected {
        hypercall_fail_test(&format!("Expected md5 to print {expected}, but got {substr}"));
    }
    hypercall_done(23);
}

fn test_write_file(){
    let path = "foo.txt";
    let value =  b"TestString";
    let expected =  "TestString";
    if Path::new(path).exists(){
        hypercall_fail_test(&format!("File {path} should not exist")); 
    }
    let mut file = File::create(path).unwrap();
    file.write_all(value).unwrap();
    let mut file = File::open(path).unwrap();
    let mut buff = vec![];
    file.read_to_end(&mut buff).unwrap();
    let str = String::from_utf8_lossy(&buff);
    if &str != expected {
        hypercall_fail_test(&format!("Expected to read filecontent: {expected} but got {str}"));
    }
    hypercall_done(42);
}


fn test_read_file(){
    let mut file = File::open("/resources/.keepme").unwrap();
    let mut buff = vec![];
    file.read_to_end(&mut buff).unwrap();
    hypercall_dbg_print("=================> DONE");
    hypercall_done(42);
}


fn test_shutdown(){
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
    hypercall_fail_test(&format!("Syscall SYS_reboot should never return! err code: {sys_reboot}"));
}
