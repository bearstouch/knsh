//! Thread quality of service for background work (KNSH-079, decision 15).
//!
//! The shadow builder runs its clone threads at quality of service **utility**: observed on macOS 26.6 (KNSH-077, C3), a
//! 100,000-file shadow took 7.4 to 7.7 s there, inside NFR-PERF-06's 10 s. It must not use the background class or
//! `PRIO_DARWIN_BG`, whose throttled I/O stretched the same work to 33 to 51 s.

/// Lowers the calling thread to the utility class (`pthread_set_qos_class_self_np(QOS_CLASS_UTILITY, 0)`). Returns
/// whether the class was applied. Best effort: a thread that cannot change class keeps running at its own, which is
/// never slower than utility.
#[must_use]
pub fn set_current_thread_utility_qos() -> bool {
    // SAFETY: the call takes two plain values and changes only the calling thread's scheduling class; it touches no
    // memory of ours.
    let status = unsafe { libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_UTILITY, 0) };
    status == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_thread_can_lower_itself_to_utility() {
        let applied = std::thread::spawn(set_current_thread_utility_qos).join().unwrap();
        assert!(applied);
    }
}
