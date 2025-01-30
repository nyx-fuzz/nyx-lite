use std::{sync::{Arc, Mutex}, time::Duration};

use event_manager::{EventOps, EventSet, Events, MutEventSubscriber};
use timerfd::{SetTimeFlags, TimerFd, TimerState};
use utils::signal::{sigrtmin, Killable};
use vmm::{vstate::vcpu::VCPU_RTSIG_OFFSET, Vmm};

use libc::pthread_t;

pub struct TimerEvent{
    timer: TimerFd,
    target_thread: pthread_t,
}

impl TimerEvent{
    pub fn new() -> Self{


        // Send the SIGTERM signal to the current thread that makes the TimerEvent
        let target_thread = unsafe { libc::pthread_self() };
        println!("current_thread_id :{:?}", target_thread);

        Self{timer: TimerFd::new().unwrap(), target_thread}
    }
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timer.set_state(TimerState::Oneshot(timeout), SetTimeFlags::Default);
    }
    pub fn disable(&mut self){
        self.timer.set_state(TimerState::Disarmed, SetTimeFlags::Default);
    }
}


impl MutEventSubscriber for TimerEvent {
    // Handle an event for queue or rate limiter.
    fn process(&mut self, event: Events, ops: &mut EventOps) {
        let source = event.data();
        let event_set = event.event_set();

        let supported_events = EventSet::IN;
        if !supported_events.contains(event_set) {
            panic!(
                "Block: Received unknown event: {:?} from source: {:?}",
                event_set, source
            );
        }
        println!(" -----> RECIEVED TIMER EVENT");
        self.timer.set_state(TimerState::Disarmed, SetTimeFlags::Default);
        let sig_num_kick = sigrtmin() + VCPU_RTSIG_OFFSET;
        self.kill(sig_num_kick).unwrap();
    }

    fn init(&mut self, ops: &mut EventOps) {
        ops.add(Events::new(
            &self.timer,
            EventSet::IN,
        )).unwrap();
    }
}

// This actually needs to make sure that self.target_thread is still running &
// valid. Since target_thread SHOULD be the main thread for this VM, this should
// be mostly true. However, if the user was making multiple VM objects in
// multiple threads, this might no longer be true - it's unclear how the timer
// event would be drop'ed for now. So this is probably actually not safe.
unsafe impl Killable for TimerEvent{
    fn pthread_handle(&self) -> pthread_t {
        self.target_thread
    }
}
