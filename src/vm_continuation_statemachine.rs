use std::time::Duration;

pub use crate::nyx_vm::NyxVM;
use crate::UnparsedExitReason;

#[derive(Clone,Debug,Eq, PartialEq, Hash)]
pub enum VMExitUserEvent {
    Shutdown,
    Hypercall,
    Timeout,
    Breakpoint,
    HWBreakpoint(u8),
    SingleStep,
    Interrupted,
    BadMemoryAccess,
}

#[derive(Clone,Debug,Eq, PartialEq, Hash)]
pub enum VMContinuationState{
    Main,
    ForceSingleStep,
    EmulateHypercall,
    ForceSingleStepInjectBPs,
}

#[derive(Clone,Copy,Debug,Eq, PartialEq, Hash)]
pub enum RunMode{
    Run,
    SingleStep,
    BranchStep
}

impl RunMode{
    pub fn is_step(&self) -> bool {
        match self {
            RunMode::Run => false,
            RunMode::SingleStep => true,
            RunMode::BranchStep => true,
        }
    }
}

impl VMContinuationState{
    pub fn step(vm: &mut NyxVM, run_mode: RunMode, timeout: Duration) -> VMExitUserEvent{
        loop{
            //println!("LOOP {:?} requested singlestep {}", vm.continuation_state, single_step);
            let (new_state,res) = match vm.continuation_state{
                Self::Main => Self::run_main(vm, run_mode, timeout),
                Self::ForceSingleStep => Self::force_ss(vm, run_mode.is_step()),
                Self::ForceSingleStepInjectBPs => Self::force_ss_inject_bps(vm),
                Self::EmulateHypercall => Self::emulate_hypercall(vm),
            };
            vm.continuation_state = new_state;
            if let Some(user_event) = res {
                vm.breakpoint_manager.disable_all_breakpoints(&mut vm.vmm.lock().unwrap());
                return user_event;
            }
        }
    }

    fn run_main(vm: &mut NyxVM, run_mode: RunMode, timeout: Duration) -> (Self, Option<VMExitUserEvent>){
        let vmexit_on_swbp = true;
        //vm.reapply_skipped_bps(); TODO add this once we actually support breakpoints
        vm.set_debug_state(run_mode, vmexit_on_swbp);
        vm.breakpoint_manager.enable_all_breakpoints(&mut vm.vmm.lock().unwrap());
        let exit = vm.run_inner(timeout);
        match exit {
            UnparsedExitReason::BadMemoryAccess => return (Self::Main, Some(VMExitUserEvent::BadMemoryAccess)),
            UnparsedExitReason::HWBreakpoint(x) => return (Self::Main, Some(VMExitUserEvent::HWBreakpoint(x))),
            UnparsedExitReason::GuestBreakpoint => return (Self::ForceSingleStepInjectBPs, None),
            UnparsedExitReason::NyxBreakpoint => return (Self::ForceSingleStep, Some(VMExitUserEvent::Breakpoint)),
            UnparsedExitReason::Hypercall => return  (Self::EmulateHypercall, Some(VMExitUserEvent::Hypercall)),
            UnparsedExitReason::Interrupted => return (Self::Main, None),
            UnparsedExitReason::Shutdown => return (Self::Main, Some(VMExitUserEvent::Shutdown)),
            UnparsedExitReason::SingleStep => {
                if run_mode.is_step() { 
                    return (Self::Main, Some(VMExitUserEvent::SingleStep))
                }
                panic!("We shouldn't see singlestep exceptions unless we asked for them");
            }
            UnparsedExitReason::Timeout => return (Self::Main, Some(VMExitUserEvent::Timeout)),
        };
    }
    fn force_ss(vm: &mut NyxVM, user_requested_singlestep: bool) -> (Self,Option<VMExitUserEvent>){
        let vmexit_on_swbp = true;
        vm.set_debug_state(RunMode::SingleStep, vmexit_on_swbp);
        vm.breakpoint_manager.disable_all_breakpoints(&mut vm.vmm.lock().unwrap()); // step over the breakpoint(s)
        let no_timeout = Duration::MAX;
        let exit = vm.run_inner(no_timeout);
        match exit {
            UnparsedExitReason::SingleStep => {
                // happy case: we just got to single step & can now reapply
                // breakpoints and continue as is
                Self::assert_made_progress(vm); 
                if user_requested_singlestep{
                    return (Self::Main, Some(VMExitUserEvent::SingleStep))
                }
                return (Self::Main, None)
            }
            UnparsedExitReason::BadMemoryAccess => {
                // TODO: I no longer understand what we are doing here - check this actually works
                return (Self::ForceSingleStep, Some(VMExitUserEvent::BadMemoryAccess))
            }
            UnparsedExitReason::GuestBreakpoint => {
                // To get here, we triggered a nyx-bp at address X (which we removed). IF there was a breakpoint under
                // the nyx-bp, it's a guest BP that we need to inject. In that case we should have made no progress.
                Self::assert_made_no_progress(vm);
                return (Self::ForceSingleStepInjectBPs, None);
            }
            UnparsedExitReason::HWBreakpoint(x) => return (Self::Main, Some(VMExitUserEvent::HWBreakpoint(x))),
            UnparsedExitReason::NyxBreakpoint => {
                //To get here, we triggered a nyx-bp at address X. Then we removed the breakpoints from that address.
                //Singlestep shouldn't trigger the next instruction. So IF we trigger a breakpoint ad X, AFTER we
                //removed the breakpoint at X, it's because the BP is a guest BP
                panic!("We shouild never see a nyx bp when single stepping over a previous BP");
            }
            UnparsedExitReason::Hypercall => {
                // while we made no progress, we no longer need to singlestep,
                // as EmualteHypercall will emulate single stepping past the
                // hypercall instruction
                Self::assert_made_no_progress(vm);
                return  (Self::EmulateHypercall, Some(VMExitUserEvent::Hypercall));
            }
            UnparsedExitReason::Interrupted => return (Self::ForceSingleStep, None),
            UnparsedExitReason::Shutdown => return (Self::Main, Some(VMExitUserEvent::Shutdown)),
            UnparsedExitReason::Timeout => return (Self::ForceSingleStep, Some(VMExitUserEvent::Timeout)),
        };
    }


    fn force_ss_inject_bps(vm: &mut NyxVM) -> (Self,Option<VMExitUserEvent>){
        let vmexit_on_swbp = false;
        vm.set_debug_state(RunMode::SingleStep, vmexit_on_swbp);
        vm.breakpoint_manager.disable_all_breakpoints(&mut vm.vmm.lock().unwrap()); // step over nyx breakpoint(s), but not guest breakpoints
        let no_timeout = Duration::MAX;
        let exit = vm.run_inner(no_timeout);
        match exit {
            UnparsedExitReason::SingleStep => {
                // happy case: we just got to single step & can now reapply
                // breakpoints and continue as is
                Self::assert_made_progress(vm); 
                return (Self::Main, None)
            }
            UnparsedExitReason::HWBreakpoint(x) => return (Self::Main, Some(VMExitUserEvent::HWBreakpoint(x))),
            UnparsedExitReason::BadMemoryAccess => {
                // TODO: I no longer understand what we are doing here - check this actually works
                return (Self::Main, Some(VMExitUserEvent::BadMemoryAccess))
            }
            UnparsedExitReason::GuestBreakpoint => {
                panic!("We shouild never see a breakpoint based vm exit while injecting breakpoints interrupts");
            }
            UnparsedExitReason::NyxBreakpoint => {
                panic!("We shouild never see a breakpoint based vm exit while injecting breakpoints interrupts");
            }
            UnparsedExitReason::Hypercall => {
                panic!("We shouild never see a breakpoint based vm exit while injecting breakpoints interrupts");
            }
            UnparsedExitReason::Interrupted => return (Self::ForceSingleStepInjectBPs, None),
            UnparsedExitReason::Shutdown => return (Self::Main, Some(VMExitUserEvent::Shutdown)),
            UnparsedExitReason::Timeout => return (Self::ForceSingleStepInjectBPs, Some(VMExitUserEvent::Timeout)),
        };
    }
    fn emulate_hypercall(vm: &mut NyxVM) -> (Self,Option<VMExitUserEvent>){
        let mut regs = vm.regs();
        regs.rax = 0; // reset rax to prevent us from accidentially misinterpreting int 3 as hypercall in the future.
        regs.rip += 1;
        vm.set_regs(&regs);
        return (Self::Main, None);
    }
    fn assert_made_progress(_vm: &mut NyxVM){
        // note: needs to handle self loops, str instructions etc
    }
    fn assert_made_no_progress(_vm: &mut NyxVM){}
}
