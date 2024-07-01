use std::process::ExitCode;
use std::arch::asm;

fn hypercall(hypercall_num: u64) {
    unsafe{
        asm!(
            "mov rax, 0x6e79782d6c697465",
            "int 3",
            in("rcx") hypercall_num,
            out("rax") _,
        );
    }
}

fn main() -> ExitCode {
    for i in 42..47 {
        println!("trigger hypercall bp {i}");
        hypercall(i);
        println!("done hypercall bp");
    }
    return ExitCode::SUCCESS;
}