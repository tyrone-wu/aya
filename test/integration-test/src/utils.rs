//! Utilities to run tests

use std::{
    ffi::CString,
    fs::Metadata,
    io,
    path::Path,
    process,
    sync::atomic::{AtomicU64, Ordering},
};

use aya::{
    maps::MapError,
    netlink_set_link_up,
    programs::{links::LinkError, ProgramError},
};
use libc::if_nametoindex;
use netns_rs::{get_from_current_thread, NetNs};

pub struct NetNsGuard {
    name: String,
    old_ns: NetNs,
    ns: Option<NetNs>,
}

impl NetNsGuard {
    pub fn new() -> Self {
        let old_ns = get_from_current_thread().expect("Failed to get current netns");

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let pid = process::id();
        let name = format!("aya-test-{pid}-{}", COUNTER.fetch_add(1, Ordering::Relaxed));

        // Create and enter netns
        let ns = NetNs::new(&name).unwrap_or_else(|e| panic!("Failed to create netns {name}: {e}"));
        let netns = Self {
            old_ns,
            ns: Some(ns),
            name,
        };

        let ns = netns.ns.as_ref().unwrap();
        ns.enter()
            .unwrap_or_else(|e| panic!("Failed to enter network namespace {}: {e}", netns.name));
        println!("Entered network namespace {}", netns.name);

        // By default, the loopback in a new netns is down. Set it up.
        let lo = CString::new("lo").unwrap();
        unsafe {
            let idx = if_nametoindex(lo.as_ptr());
            if idx == 0 {
                panic!(
                    "Interface `lo` not found in netns {}: {}",
                    netns.name,
                    io::Error::last_os_error()
                );
            }
            netlink_set_link_up(idx as i32)
                .unwrap_or_else(|e| panic!("Failed to set `lo` up in netns {}: {e}", netns.name));
        }

        netns
    }

    /// Returns the file path of the created network namespace.
    pub(crate) fn path(&self) -> &Path {
        return self.ns.as_ref().unwrap().path();
    }

    /// Returns the file metadata object of the created namespace.
    pub(crate) fn file_metadata(&self) -> Option<Metadata> {
        return self.ns.as_ref().unwrap().file().metadata().ok();
    }
}

impl Drop for NetNsGuard {
    fn drop(&mut self) {
        // Avoid panic in panic
        if let Err(e) = self.old_ns.enter() {
            eprintln!("Failed to return to original netns: {e}");
        }
        if let Some(ns) = self.ns.take() {
            if let Err(e) = ns.remove() {
                eprintln!("Failed to remove netns {}: {e}", self.name);
            }
        }
        println!("Exited network namespace {}", self.name);
    }
}

/// Performs `assert!` macro. If the assertion fails and host kernel version
/// is above feature version, then fail test.
macro_rules! kernel_assert {
    ($cond:expr, $version:expr $(,)?) => {
        let pass: bool = $cond;
        if !pass {
            let feat_version: aya::util::KernelVersion = $version;
            let current = aya::util::KernelVersion::current().unwrap();
            let cond_literal = stringify!($cond);
            if current >= feat_version {
                // Host kernel is expected to have the feat but does not
                std::panic!(
                    r#"  assertion `{cond_literal}` failed: expected host kernel v{current} to have v{feat_version} feature"#,
                );
            } else {
                // Continue with tests since host is not expected to have feat
                std::eprintln!(
                    r#"ignoring assertion at {}:{}
  assertion `{cond_literal}` failed: continuing since host kernel v{current} is not expected to have v{feat_version} feature"#,
                    file!(), line!(),
                );
            }
        }
    };
}

pub(crate) use kernel_assert;

/// Performs `assert_eq!` macro. If the assertion fails and host kernel version
/// is above feature version, then fail test.
macro_rules! kernel_assert_eq {
    ($left:expr, $right:expr, $version:expr $(,)?) => {
        if $left != $right {
            let feat_version: aya::util::KernelVersion = $version;
            let current = aya::util::KernelVersion::current().unwrap();
            if current >= feat_version {
                // Host kernel is expected to have the feat but does not
                std::panic!(
                    r#"  assertion `left == right` failed: expected host kernel v{current} to have v{feat_version} feature
    left: {:?}
   right: {:?}"#,
                    $left, $right,
                );
            } else {
                // Continue with tests since host is not expected to have feat
                std::eprintln!(
                    r#"ignoring assertion at {}:{}
  assertion `left == right` failed: continuing since host kernel v{current} is not expected to have v{feat_version} feature
    left: {:?}
   right: {:?}"#,
                    file!(), line!(), $left, $right,
                );
            }
        }
    };
}

pub(crate) use kernel_assert_eq;

/// Returns whether the error is `EINVAL` for `ProgramError`.
/// `EINVAL` usually indicates that the operation does not exist.
pub(crate) fn is_prog_einval(err: &ProgramError) -> bool {
    let io_error = match &err {
        ProgramError::LoadError { io_error, .. } => io_error,
        ProgramError::SyscallError(err) => &err.io_error,
        _ => return false,
    };
    io_error
        .raw_os_error()
        .is_some_and(|errno| errno == libc::EINVAL)
}

/// Returns whether the error is `EINVAL` for `MapError`.
/// `EINVAL` usually indicates that the operation does not exist.
pub(crate) fn is_map_einval(err: &MapError) -> bool {
    if let MapError::SyscallError(err) = err {
        err.io_error
            .raw_os_error()
            .is_some_and(|errno| errno == libc::EINVAL)
    } else {
        false
    }
}

/// Returns whether the error is `EINVAL` for `LinkError`.
/// `EINVAL` usually indicates that the operation does not exist.
pub(crate) fn is_link_einval(err: &LinkError) -> bool {
    if let LinkError::SyscallError(err) = err {
        err.io_error
            .raw_os_error()
            .is_some_and(|errno| errno == libc::EINVAL)
    } else {
        false
    }
}
