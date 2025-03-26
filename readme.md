Nyx-lite
=========

Nyx-Lite is an implementation of many of the hypervisor features used by Nyx in a convenient library designed to make it as easy as possible to build and evalute hypervisor based fuzzing / program analysis tools. 
Nyx-Lite allow you to easily make firecacker/KVM VM's and perform various VMI operations. It supports:

1) A tree of an arbitrary number of incremental fast snapshots, including the full kernel, device and filesystem state.
2) A fully fledged debugger api, featuring single stepping, software and hardware breakpoints.
3) A way to remove page permissions to trap on memory reads/writes inside the guest.
4) A a clean api to access virtual memory from the view of any process.
5) A convenient, consistent API to handle VM exits.  
6) A consistent way to handle timeouts & force VM exits after a given time.
7) It should works out of the box on most random Linux distributions with any reasonable kernel version.
8) An easy way to turn docker files into usable vm images.

However, while nyx-lite's API & codebase is much friendlier to new usecases, there's always some tradeoffs. Unlike Nyx it's specifically designed to work on an unmodified host kernel. This obviously has some downsides: KVM does not provide all the VMI primitives we'd like to use. For example, nyx-lite doesn't support Intel-PT.     
Additionally it's based on Firecracker instead of Qemu. While this makes the codebase MUCH smaller and easy to hack on (Firecracker is about 5% of the size of Qemu), this prevents nyx-lite from being used with closed source operating systems such as windows and mac-os that won't run inside of firecracker VMs. 



Setup
=====

Clone nyx-lite with:
```
git clone --recurse-submodules 'git@github.com:nyx-fuzz/nyx-lite.git'
git clone --recurse-submodules 'https://github.com/nyx-fuzz/nyx-lite.git'
```

Get a firecracker compatible linux kernel:
```
cd vm_image
bash download_kernel.sh
```

and run tests with:
```
cd vm_image
export RUST_BACKTRACE=1 && cargo build --release && pushd dockerimage && bash build-img.sh && popd && ../target/release/e2e_test --config vmconfig.json
```

API
===
Check out (https://github.com/nyx-fuzz/nyx-lite/blob/main/src/e2e_test_main.rs) to see how NyxVM instances are used. 

To get a sense of how to use 
 
```rust
    // create a new VM from a config_json
    let mut vm = NyxVM::new(instance_id.clone(), &vmm_config_json.unwrap());

    // run the VM for a given time and handle the exit reason
    let exit_reason = vm.run(Duration::from_milis(10));
    let exit_reason = vm.single_step(Duration::from_millis(10));

    match exit_reason {
      ExitReason::Timeout => (),                     // execution timed out
      ExitReason::Breakpoint (),                     // hit a breakpoint
      ExitReason::SingleStep => (),                  // returned from single stepping
      ExitReason::HWBreakpoint(n) => (),             // triggered the n-th hardware breakpoint
      ExitReason::BadMemoryAccess(Vec<(u64, OpAccess)>), // The guest tried to access a page that we read/write protected previously

      ExitReason::Shutdown => (),              // The VM shut down
      ExitReason::Interrupted => (),                       // shouldn't really happen unless some device doesn't get emulated properly
      ExitReason::Hypercall(arg1, arg2, arg3, arg4, arg5), // A hypercall was issued by the guest. You can use it as you see fit.
      //  We also define some optional default hypercalls that you can use or ignore:
      ExitReason::RequestSnapshot,                         // informs the fuzzer that the agent would like to take a snapshot
      ExitReason::ExecDone(exit_code),                     // informs the fuzzer that the test case was finished.
      ExitReason::SharedMem(name, addr, size) => (),       // informs the fuzzer that current process would like to share memory [addr .. addr+size] with the fuzzer to be used for the usecase `name`.
      ExitReason::DebugPrint(String) => (),                // requests to print things for debug purposes
    };

    //take and reapply snapshots
    let snapshot = vm.take_snapshot();
    vm.apply_snapshot(snapshot);

    // use various debug features
    let cr3 = vm.sregs().cr3;
    vm.add_breakpoint(cr3, code_addr);
    vm.hw_breakpoints.enable_exec(0, code_addr); // enable hardware breakpoint 0 at the given addr
    vm.hw_breakpoints.enable_access(0, addr, size);
    vm.hw_breakpoints.disable(0);

    // cause VM exit when the page at page_addr is read/written
    vm.vmm.lock().unwrap().set_virtual_page_permission(cr3, page_addr, PagePermission::None);
    vm.vmm.lock().unwrap().set_virtual_page_permission(cr3, page_addr, PagePermission::RW);

    // various memory operations
    vm.write_current_u64(some_addr, some_value);
    let string = String::from_utf8_lossy(&vm.read_cstr_current(err_ptr)).to_string();
    disassemble_print(code_addr, &vm.read_current_bytes(code_addr, 128));

```

Caveats 
=======
Nyx-Lite is currently not a stable release - there's quite a few limitations and known issues:
1) Performance: The rust wrapper around KVM currently only exposes the dirty bitmap and not the dirty_ring interface, and as such incremental snapshot reset performance for large VM's can be dominate by the time to walk the bitmap (This is planned to change in the future) - ditto for the firecracker host side dirty memory tracking.
2) Performance: We currently don't allow to share root snapshots between different VM instances, and it's unclear if it's safe to make more than one VM instance per process. This limits usefullness in highly parallel settings (This is planned to change in the future)
3) Performance: Using lots of software breakpoints will make VM Entry/Exits slow as we remove/reapply all breakpoints to allow a clean view at the memory. This should be fixed by hiding breakpoints from memory accesses to allow to use millions of breakpoints with acceptable performance.
6) TTY emulation is currently semi-broken. Unfortunately rust doesn't handle nonblocking stdout, and firecracker set's stdin/stdout to nonblocking to allow it's async device emulation to handle a tty. This will crash the application whenever you try to print large amounts of data. As such, we currently disable stdin to the TTY to enable (printf) debugging (this is planned to change in the near future). 
5) Determinism: While using snapshots generally leads to somewhat deterministic behavior, KVM doesn't allow to make a fully deterministic VMM. In addition to not being able to easily control timing interrupts ourselfs, we can also not precisely control the value of tsc when resetting the snapshot, as KVM "helpfully" tries to account for time spend in the host, and will introduce jitter based on how long the host takes to reenter the VM. As such multithreading/highly timing sensitive applications might not behave deterministically.
6) Network devices are currently not supported when using snapshots. While you can boot the VM with a network device to perform a setup, they won't work in snapshot, likely resulting in crashes. Ideally, we'd like to allow real world network traffic during execution, and replay it after running a snapshot.\
7) A variety of known bugs and issues that will get fixed as we find time to address them. 
