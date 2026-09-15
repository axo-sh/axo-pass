//! Process information obtained via `sysctl(KERN_PROC_PID)`.
//!
//! Unlike `proc_pidinfo`/`PROC_PIDTBSDINFO` (what `libproc::proc_pid::pidinfo`
//! wraps), this is not gated by the target process's uid: it is what `ps`
//! itself uses, and it works when querying a process owned by another user
//! (e.g. `login`, which runs as uid 0) from an unprivileged caller.
//!
//! The raw structures are defined here rather than relying on the `libc`
//! crate, because `libc` does not expose `kinfo_proc` for Apple targets. They
//! mirror the layout in `<sys/sysctl.h>` exactly so that `sysctl` fills them
//! correctly.
//!
//! 2026-09-15: Based on unreleased code in libproc
//! https://github.com/andrewdavidmackenzie/libproc-rs/pull/173

use std::os::raw::c_void;

/// `struct timeval` (mirrored to avoid depending on a `libc` alias).
#[repr(C)]
#[derive(Copy, Clone, Default)]
struct Timeval {
    tv_sec: i64,
    tv_usec: i32,
}

/// `struct itimerval` (mirrored).
#[repr(C)]
#[derive(Copy, Clone, Default)]
struct Itimerval {
    it_interval: Timeval,
    it_value: Timeval,
}

/// Mirror of macOS `struct extern_proc` (the `kp_proc` member of `kinfo_proc`).
#[repr(C)]
#[derive(Copy, Clone)]
struct ExternProc {
    // `union p_un` from the system header (process start time / scheduling
    // links). Represented by its 16-byte, 8-byte-aligned `timeval` member;
    // never read here.
    p_un: Timeval,
    p_vmspace: *mut c_void,
    p_sigacts: usize,
    p_flag: i32,
    p_stat: i8,
    p_pid: i32,
    p_oppid: i32,
    p_dupfd: i32,
    user_stack: *mut c_void,
    exit_thread: *mut c_void,
    p_debugger: i32,
    sigwait: i32,
    p_estcpu: u32,
    p_cpticks: i32,
    p_pctcpu: u32,
    p_wchan: *mut c_void,
    p_wmesg: *mut c_void,
    p_swtime: u32,
    p_slptime: u32,
    p_realtimer: Itimerval,
    p_rtime: Timeval,
    p_uticks: u64,
    p_sticks: u64,
    p_iticks: u64,
    p_traceflag: i32,
    p_tracep: *mut c_void,
    p_siglist: i32,
    p_textvp: *mut c_void,
    p_holdcnt: i32,
    p_sigmask: u32,
    p_sigignore: u32,
    p_sigcatch: u32,
    p_priority: u8,
    p_usrpri: u8,
    p_nice: i8,
    p_comm: [i8; 17],
    p_pgrp: *mut c_void,
    p_addr: *mut c_void,
    p_xstat: u16,
    p_acflag: u16,
    p_ru: *mut c_void,
}

/// Mirror of macOS `struct _pcred` (process credentials).
#[repr(C)]
#[derive(Copy, Clone)]
struct Pcred {
    pc_lock: [i8; 72],
    pc_ucred: *mut c_void,
    p_ruid: u32,
    p_svuid: u32,
    p_rgid: u32,
    p_svgid: u32,
    p_refcnt: i32,
}

/// Mirror of macOS `struct _ucred` (user credentials).
#[repr(C)]
#[derive(Copy, Clone)]
struct Ucred {
    cr_ref: i32,
    cr_uid: u32,
    cr_ngroups: i16,
    cr_groups: [u32; 16],
}

/// Mirror of macOS `struct vmspace` (opaque placeholder, as in the system
/// header).
#[repr(C)]
#[derive(Copy, Clone)]
struct Vmspace {
    dummy: i32,
    dummy2: *mut c_void,
    dummy3: [i32; 5],
    dummy4: [*mut c_void; 3],
}

/// Mirror of macOS `struct eproc` (the `kp_eproc` member of `kinfo_proc`).
#[repr(C)]
#[derive(Copy, Clone)]
struct Eproc {
    e_paddr: *mut c_void,
    e_sess: *mut c_void,
    e_pcred: Pcred,
    e_ucred: Ucred,
    e_vm: Vmspace,
    e_ppid: i32,
    e_pgid: i32,
    e_jobc: i16,
    e_tdev: i32,
    e_tpgid: i32,
    e_tsess: *mut c_void,
    e_wmesg: [i8; 8],
    e_xsize: i32,
    e_xrssize: i16,
    e_xccount: i16,
    e_xswrss: i16,
    e_flag: i32,
    e_login: [i8; 12],
    e_spare: [i32; 4],
}

/// Faithful `#[repr(C)]` mirror of the macOS `kinfo_proc` structure returned by
/// `sysctl(KERN_PROC_PID)`.
#[repr(C)]
#[derive(Copy, Clone)]
struct KinfoProc {
    kp_proc: ExternProc,
    kp_eproc: Eproc,
}

/// Get a process's parent pid via `sysctl(KERN_PROC_PID)`. See the module docs
/// for why this is used instead of `proc_pidinfo`.
pub fn get_parent_pid(pid: u32) -> anyhow::Result<u32> {
    let mut mib: [libc::c_int; 4] = [
        libc::CTL_KERN,
        libc::KERN_PROC,
        libc::KERN_PROC_PID,
        pid as libc::c_int,
    ];
    // KinfoProc is a plain repr(C) struct of scalars/pointers; a zeroed value
    // is a valid initial state and sysctl overwrites it on success.
    let mut info = unsafe { std::mem::zeroed::<KinfoProc>() };
    let mut size = std::mem::size_of::<KinfoProc>();

    let ret = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            4,
            std::ptr::addr_of_mut!(info).cast::<c_void>(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };

    if ret != 0 {
        anyhow::bail!(
            "sysctl(KERN_PROC_PID, {pid}) failed: {}",
            std::io::Error::last_os_error()
        );
    }
    if size == 0 {
        anyhow::bail!("sysctl(KERN_PROC_PID, {pid}): no such process");
    }
    Ok(info.kp_eproc.e_ppid as u32)
}

#[cfg(test)]
mod layout_tests {
    use std::mem::{align_of, offset_of, size_of};

    use super::{Itimerval, Timeval};

    // The mirrored `Timeval` / `Itimerval` must match the system's `struct
    // timeval` / `struct itimerval` exactly, otherwise every field after
    // `p_un` / `p_realtimer` in `extern_proc` is read at the wrong offset and
    // `sysctl` results are garbage. `libc` exposes these two types on macOS
    // (unlike `kinfo_proc`), so we use them as the authoritative reference.

    #[test]
    fn timeval_matches_libc() {
        assert_eq!(
            size_of::<Timeval>(),
            size_of::<libc::timeval>(),
            "Timeval size must match libc::timeval"
        );
        assert_eq!(
            align_of::<Timeval>(),
            align_of::<libc::timeval>(),
            "Timeval alignment must match libc::timeval"
        );
        assert_eq!(offset_of!(Timeval, tv_sec), 0);
        assert_eq!(
            offset_of!(Timeval, tv_usec),
            size_of::<libc::time_t>(),
            "tv_usec must follow the full-width tv_sec"
        );
    }

    #[test]
    fn itimerval_matches_libc() {
        assert_eq!(
            size_of::<Itimerval>(),
            size_of::<libc::itimerval>(),
            "Itimerval size must match libc::itimerval"
        );
        assert_eq!(align_of::<Itimerval>(), align_of::<libc::itimerval>());
        assert_eq!(offset_of!(Itimerval, it_interval), 0);
        assert_eq!(
            offset_of!(Itimerval, it_value),
            size_of::<Timeval>(),
            "it_value must follow it_interval"
        );
    }
}
