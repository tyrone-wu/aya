//! Utility functions.
use std::{
    collections::BTreeMap,
    error::Error,
    ffi::{CStr, CString},
    fmt::Display,
    fs::{self, File},
    io::{self, BufRead, BufReader},
    mem,
    num::ParseIntError,
    os::fd::{AsFd as _, BorrowedFd},
    path::Path,
    ptr, slice,
    str::{FromStr, Utf8Error},
};

use aya_obj::generated::{TC_H_MAJ_MASK, TC_H_MIN_MASK};
use libc::{
    _SC_PAGESIZE, MAP_FAILED, MAP_PRIVATE, PROT_READ, c_int, c_void, if_nametoindex, off_t,
    sysconf, uname, utsname,
};
use log::warn;

use crate::{
    Pod,
    sys::{SyscallError, mmap, munmap},
};

/// Represents a kernel version, in major.minor.release version.
// Adapted from https://docs.rs/procfs/latest/procfs/sys/kernel/struct.Version.html.
#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd)]
pub struct KernelVersion {
    pub(crate) major: u8,
    pub(crate) minor: u8,
    pub(crate) patch: u16,
}

#[derive(thiserror::Error, Debug)]
enum CurrentKernelVersionError {
    #[error("failed to read kernel version")]
    IO(#[from] io::Error),
    #[error("failed to parse kernel version")]
    ParseError(String),
    #[error("kernel version string is not valid UTF-8")]
    Utf8(#[from] Utf8Error),
}

impl KernelVersion {
    /// Constructor.
    pub fn new(major: u8, minor: u8, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Returns the kernel version of the currently running kernel.
    pub fn current() -> Result<Self, impl Error> {
        thread_local! {
            // TODO(https://github.com/rust-lang/rust/issues/109737): Use
            // `std::cell::OnceCell` when `get_or_try_init` is stabilized.
            static CACHE: once_cell::unsync::OnceCell<KernelVersion> = const { once_cell::unsync::OnceCell::new() };
        }
        CACHE.with(|cell| {
            // TODO(https://github.com/rust-lang/rust/issues/109737): Replace `once_cell` with
            // `std::cell::OnceCell`.
            cell.get_or_try_init(|| {
                // error: unsupported operation: `open` not available when isolation is enabled
                if cfg!(miri) {
                    Ok(Self::new(0xff, 0xff, 0xff))
                } else {
                    Self::get_kernel_version()
                }
            })
            .copied()
        })
    }

    /// Returns true iff the current kernel version is greater than or equal to the given version.
    pub(crate) fn at_least(major: u8, minor: u8, patch: u16) -> bool {
        match Self::current() {
            Ok(current) => current >= Self::new(major, minor, patch),
            Err(error) => {
                warn!("failed to get current kernel version: {error}");
                false
            }
        }
    }

    /// The equivalent of LINUX_VERSION_CODE.
    pub fn code(self) -> u32 {
        let Self {
            major,
            minor,
            mut patch,
        } = self;

        // Certain LTS kernels went above the "max" 255 patch so
        // backports were done to cap the patch version
        let max_patch = match (major, minor) {
            // On 4.4 + 4.9, any patch 257 or above was hardcoded to 255.
            // See: https://github.com/torvalds/linux/commit/a15813a +
            // https://github.com/torvalds/linux/commit/42efb098
            (4, 4 | 9) => 257,
            // On 4.14, any patch 252 or above was hardcoded to 255.
            // See: https://github.com/torvalds/linux/commit/e131e0e
            (4, 14) => 252,
            // On 4.19, any patch 222 or above was hardcoded to 255.
            // See: https://github.com/torvalds/linux/commit/a256aac
            (4, 19) => 222,
            // For other kernels (i.e., newer LTS kernels as other
            // ones won't reach 255+ patches) clamp it to 255. See:
            // https://github.com/torvalds/linux/commit/9b82f13e
            _ => 255,
        };

        // anything greater or equal to `max_patch` is hardcoded to
        // 255.
        if patch >= max_patch {
            patch = 255;
        }

        (u32::from(major) << 16) + (u32::from(minor) << 8) + u32::from(patch)
    }

    // These (get_ubuntu_kernel_version, parse_ubuntu_kernel_version, read_ubuntu_kernel_version_file)
    // are ported from https://github.com/torvalds/linux/blob/3f01e9f/tools/lib/bpf/libbpf_probes.c#L21-L101.
    fn get_ubuntu_kernel_version() -> Result<Option<Self>, CurrentKernelVersionError> {
        Self::read_ubuntu_kernel_version_file().and_then(|content| {
            content
                .and_then(|content| Self::parse_ubuntu_kernel_version(&content).transpose())
                .transpose()
        })
    }

    fn read_ubuntu_kernel_version_file() -> Result<Option<String>, CurrentKernelVersionError> {
        const UBUNTU_KVER_FILE: &str = "/proc/version_signature";
        match fs::read_to_string(UBUNTU_KVER_FILE) {
            Ok(s) => Ok(Some(s)),
            Err(e) => {
                if e.kind() != io::ErrorKind::NotFound {
                    Err(e.into())
                } else {
                    Ok(None)
                }
            }
        }
    }

    fn parse_ubuntu_kernel_version(s: &str) -> Result<Option<Self>, CurrentKernelVersionError> {
        let mut parts = s.split_terminator(char::is_whitespace);
        let mut next = || {
            parts
                .next()
                .ok_or_else(|| CurrentKernelVersionError::ParseError(s.to_string()))
        };
        let _ubuntu: &str = next()?;
        let _ubuntu_version: &str = next()?;
        let kernel_version_string = next()?;
        Self::parse_kernel_version_string(kernel_version_string).map(Some)
    }

    fn get_debian_kernel_version(
        info: &utsname,
    ) -> Result<Option<Self>, CurrentKernelVersionError> {
        // Safety: man 2 uname:
        //
        // The length of the arrays in a struct utsname is unspecified (see NOTES); the fields are
        // terminated by a null byte ('\0').
        let s = unsafe { CStr::from_ptr(info.version.as_ptr()) };
        let s = s.to_str()?;
        let kernel_version_string = match s.split_once("Debian ") {
            Some((_prefix, suffix)) => suffix,
            None => return Ok(None),
        };
        Self::parse_kernel_version_string(kernel_version_string).map(Some)
    }

    fn get_kernel_version() -> Result<Self, CurrentKernelVersionError> {
        if let Ok(Some(v)) = Self::get_ubuntu_kernel_version() {
            return Ok(v);
        }

        let mut info = unsafe { mem::zeroed::<utsname>() };
        if unsafe { uname(&mut info) } != 0 {
            return Err(io::Error::last_os_error().into());
        }

        if let Some(v) = Self::get_debian_kernel_version(&info)? {
            return Ok(v);
        }

        // Safety: man 2 uname:
        //
        // The length of the arrays in a struct utsname is unspecified (see NOTES); the fields are
        // terminated by a null byte ('\0').
        let s = unsafe { CStr::from_ptr(info.release.as_ptr()) };
        let s = s.to_str()?;
        Self::parse_kernel_version_string(s)
    }

    fn parse_kernel_version_string(s: &str) -> Result<Self, CurrentKernelVersionError> {
        fn parse<T: FromStr<Err = ParseIntError>>(s: Option<&str>) -> Option<T> {
            s.map(str::parse).transpose().unwrap_or_default()
        }
        let error = || CurrentKernelVersionError::ParseError(s.to_string());
        let mut parts = s.split(|c: char| c == '.' || !c.is_ascii_digit());
        let major = parse(parts.next()).ok_or_else(error)?;
        let minor = parse(parts.next()).ok_or_else(error)?;
        let patch = parse(parts.next()).ok_or_else(error)?;
        Ok(Self::new(major, minor, patch))
    }
}

impl Display for KernelVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Returns the numeric IDs of the CPUs currently online.
pub fn online_cpus() -> Result<Vec<u32>, (&'static str, io::Error)> {
    const ONLINE_CPUS: &str = "/sys/devices/system/cpu/online";

    read_cpu_ranges(ONLINE_CPUS)
}

/// Get the number of possible cpus.
///
/// See `/sys/devices/system/cpu/possible`.
pub fn nr_cpus() -> Result<usize, (&'static str, io::Error)> {
    const POSSIBLE_CPUS: &str = "/sys/devices/system/cpu/possible";

    thread_local! {
        // TODO(https://github.com/rust-lang/rust/issues/109737): Use
        // `std::cell::OnceCell` when `get_or_try_init` is stabilized.
        static CACHE: once_cell::unsync::OnceCell<usize> = const { once_cell::unsync::OnceCell::new() };
    }
    CACHE.with(|cell| {
        // TODO(https://github.com/rust-lang/rust/issues/109737): Replace `once_cell` with
        // `std::cell::OnceCell`.
        cell.get_or_try_init(|| {
            // error: unsupported operation: `open` not available when isolation is enabled
            if cfg!(miri) {
                parse_cpu_ranges("0-3").map_err(|error| (POSSIBLE_CPUS, error))
            } else {
                read_cpu_ranges(POSSIBLE_CPUS)
            }
            .map(|cpus| cpus.len())
        })
        .copied()
    })
}

fn read_cpu_ranges(path: &'static str) -> Result<Vec<u32>, (&'static str, io::Error)> {
    (|| {
        let data = fs::read_to_string(path)?;
        parse_cpu_ranges(data.trim())
    })()
    .map_err(|error| (path, error))
}

fn parse_cpu_ranges(data: &str) -> Result<Vec<u32>, io::Error> {
    data.split(',')
        .map(|range| {
            let mut iter = range
                .split('-')
                .map(|s| s.parse::<u32>().map_err(|ParseIntError { .. }| range));
            let start = iter.next().unwrap()?; // str::split always returns at least one element.
            let end = match iter.next() {
                None => start,
                Some(end) => {
                    if iter.next().is_some() {
                        return Err(range);
                    }
                    end?
                }
            };
            Ok(start..=end)
        })
        .try_fold(Vec::new(), |mut cpus, range| {
            let range = range.map_err(|range| io::Error::new(io::ErrorKind::InvalidData, range))?;
            cpus.extend(range);
            Ok(cpus)
        })
}

/// Loads kernel symbols from `/proc/kallsyms`.
///
/// See [`crate::maps::StackTraceMap`] for an example on how to use this to resolve kernel addresses to symbols.
pub fn kernel_symbols() -> Result<BTreeMap<u64, String>, io::Error> {
    let mut reader = BufReader::new(File::open("/proc/kallsyms")?);
    parse_kernel_symbols(&mut reader)
}

fn parse_kernel_symbols(reader: impl BufRead) -> Result<BTreeMap<u64, String>, io::Error> {
    reader
        .lines()
        .map(|line| {
            let line = line?;
            (|| {
                let mut parts = line.splitn(4, ' ');
                let addr = parts.next()?;
                let _kind = parts.next()?;
                let name = parts.next()?;
                // TODO(https://github.com/rust-lang/rust-clippy/issues/14112): Remove this
                // allowance when the lint behaves more sensibly.
                #[expect(clippy::manual_ok_err)]
                let addr = match u64::from_str_radix(addr, 16) {
                    Ok(addr) => Some(addr),
                    Err(ParseIntError { .. }) => None,
                }?;
                Some((addr, name.to_owned()))
            })()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, line.clone()))
        })
        .collect()
}

/// Returns the prefix used by syscalls.
///
/// # Example
///
/// ```no_run
/// use aya::util::syscall_prefix;
/// let prefix = syscall_prefix().unwrap();
/// let syscall_fname = format!("{prefix}exec");
/// ```
///
/// # Errors
///
/// Returns [`std::io::ErrorKind::NotFound`] if the prefix can't be guessed. Returns other [`std::io::Error`] kinds if `/proc/kallsyms` can't be opened or is somehow invalid.
#[deprecated(
    since = "0.12.0",
    note = "On some systems - commonly on 64 bit kernels that support running \
    32 bit applications - the syscall prefix depends on what architecture an \
    application is compiled for, therefore attaching to only one prefix is \
    incorrect and can lead to security issues."
)]
pub fn syscall_prefix() -> Result<&'static str, io::Error> {
    const PREFIXES: [&str; 7] = [
        "sys_",
        "__x64_sys_",
        "__x32_compat_sys_",
        "__ia32_compat_sys_",
        "__arm64_sys_",
        "__s390x_sys_",
        "__s390_sys_",
    ];
    let ksym = kernel_symbols()?;
    for p in PREFIXES {
        let prefixed_syscall = format!("{p}bpf");
        if ksym.values().any(|el| *el == prefixed_syscall) {
            return Ok(p);
        }
    }
    Err(io::ErrorKind::NotFound.into())
}

pub(crate) fn ifindex_from_ifname(if_name: &str) -> Result<u32, io::Error> {
    let c_str_if_name = CString::new(if_name)?;
    let c_if_name = c_str_if_name.as_ptr();
    // Safety: libc wrapper
    let if_index = unsafe { if_nametoindex(c_if_name) };
    if if_index == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(if_index)
}

pub(crate) fn tc_handler_make(major: u32, minor: u32) -> u32 {
    (major & TC_H_MAJ_MASK) | (minor & TC_H_MIN_MASK)
}

/// Include bytes from a file for use in a subsequent [`crate::Ebpf::load`].
///
/// This macro differs from the standard `include_bytes!` macro since it also ensures that
/// the bytes are correctly aligned to be parsed as an ELF binary. This avoid some nasty
/// compilation errors when the resulting byte array is not the correct alignment.
///
/// # Examples
/// ```ignore
/// use aya::{Ebpf, include_bytes_aligned};
///
/// let mut bpf = Ebpf::load(include_bytes_aligned!(
///     "/path/to/bpf.o"
/// ))?;
///
/// # Ok::<(), aya::EbpfError>(())
/// ```
#[macro_export]
macro_rules! include_bytes_aligned {
    ($path:expr) => {{
        #[repr(align(32))]
        pub struct Aligned32;

        #[repr(C)]
        pub struct Aligned<Bytes: ?Sized> {
            pub _align: [Aligned32; 0],
            pub bytes: Bytes,
        }

        const ALIGNED: &Aligned<[u8]> = &Aligned {
            _align: [],
            bytes: *include_bytes!($path),
        };

        &ALIGNED.bytes
    }};
}

pub(crate) fn page_size() -> usize {
    // Safety: libc
    (unsafe { sysconf(_SC_PAGESIZE) }) as usize
}

// bytes_of converts a <T> to a byte slice
pub(crate) unsafe fn bytes_of<T: Pod>(val: &T) -> &[u8] {
    let ptr: *const _ = val;
    unsafe { slice::from_raw_parts(ptr.cast(), mem::size_of_val(val)) }
}

pub(crate) fn bytes_of_slice<T: Pod>(val: &[T]) -> &[u8] {
    let size = val.len().wrapping_mul(mem::size_of::<T>());
    // Safety:
    // Any alignment is allowed.
    // The size is determined in this function.
    // The Pod trait ensures the type is valid to cast to bytes.
    unsafe { slice::from_raw_parts(val.as_ptr().cast(), size) }
}

pub(crate) fn bytes_of_bpf_name(bpf_name: &[core::ffi::c_char; 16]) -> &[u8] {
    let length = bpf_name
        .iter()
        .rposition(|ch| *ch != 0)
        .map(|pos| pos + 1)
        .unwrap_or(0);
    unsafe { slice::from_raw_parts(bpf_name.as_ptr() as *const _, length) }
}

// MMap corresponds to a memory-mapped region.
//
// The data is unmapped in Drop.
#[cfg_attr(test, derive(Debug))]
pub(crate) struct MMap {
    ptr: ptr::NonNull<c_void>,
    len: usize,
}

// Needed because NonNull<T> is !Send and !Sync out of caution that the data
// might be aliased unsafely.
unsafe impl Send for MMap {}
unsafe impl Sync for MMap {}

impl MMap {
    pub(crate) fn new(
        fd: BorrowedFd<'_>,
        len: usize,
        prot: c_int,
        flags: c_int,
        offset: off_t,
    ) -> Result<Self, SyscallError> {
        match unsafe { mmap(ptr::null_mut(), len, prot, flags, fd, offset) } {
            MAP_FAILED => Err(SyscallError {
                call: "mmap",
                io_error: io::Error::last_os_error(),
            }),
            ptr => {
                let ptr = ptr::NonNull::new(ptr).ok_or(
                    // This should never happen, but to be paranoid, and so we never need to talk
                    // about a null pointer, we check it anyway.
                    SyscallError {
                        call: "mmap",
                        io_error: io::Error::other("mmap returned null pointer"),
                    },
                )?;
                Ok(Self { ptr, len })
            }
        }
    }

    /// Maps the file at `path` for reading, using `mmap` with `MAP_PRIVATE`.
    pub(crate) fn map_copy_read_only(path: &Path) -> Result<Self, io::Error> {
        let file = fs::File::open(path)?;
        Self::new(
            file.as_fd(),
            file.metadata()?.len().try_into().map_err(|e| {
                io::Error::new(
                    io::ErrorKind::FileTooLarge,
                    format!("file too large to mmap: {e}"),
                )
            })?,
            PROT_READ,
            MAP_PRIVATE,
            0,
        )
        .map_err(|SyscallError { io_error, call: _ }| io_error)
    }

    pub(crate) fn ptr(&self) -> ptr::NonNull<c_void> {
        self.ptr
    }
}

impl AsRef<[u8]> for MMap {
    fn as_ref(&self) -> &[u8] {
        let Self { ptr, len } = self;
        unsafe { std::slice::from_raw_parts(ptr.as_ptr().cast(), *len) }
    }
}

impl Drop for MMap {
    fn drop(&mut self) {
        let Self { ptr, len } = *self;
        unsafe { munmap(ptr.as_ptr(), len) };
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;

    #[test]
    fn test_parse_kernel_version_string() {
        // cat /proc/version_signature on Proxmox VE 8.1.4.
        assert_matches!(KernelVersion::parse_ubuntu_kernel_version(""), Err(CurrentKernelVersionError::ParseError(s)) if s.is_empty());
        // cat /proc/version_signature on Ubuntu 22.04.
        assert_matches!(KernelVersion::parse_ubuntu_kernel_version( "Ubuntu 5.15.0-82.91-generic 5.15.111"), Ok(Some(kernel_version)) => {
            assert_eq!(kernel_version, KernelVersion::new(5, 15, 111))
        });
        // WSL.
        assert_matches!(KernelVersion::parse_kernel_version_string("5.15.90.1-microsoft-standard-WSL2"), Ok(kernel_version) => {
            assert_eq!(kernel_version, KernelVersion::new(5, 15, 90))
        });
        // uname -r on Fedora.
        assert_matches!(KernelVersion::parse_kernel_version_string("6.3.11-200.fc38.x86_64"), Ok(kernel_version) => {
            assert_eq!(kernel_version, KernelVersion::new(6, 3, 11))
        });
    }

    #[test]
    fn test_parse_online_cpus() {
        assert_eq!(parse_cpu_ranges("0").unwrap(), vec![0]);
        assert_eq!(parse_cpu_ranges("0,1").unwrap(), vec![0, 1]);
        assert_eq!(parse_cpu_ranges("0,1,2").unwrap(), vec![0, 1, 2]);
        assert_eq!(
            parse_cpu_ranges("0-7").unwrap(),
            (0..=7).collect::<Vec<_>>()
        );
        assert_eq!(
            parse_cpu_ranges("0-3,4-7").unwrap(),
            (0..=7).collect::<Vec<_>>()
        );
        assert_eq!(
            parse_cpu_ranges("0-5,6,7").unwrap(),
            (0..=7).collect::<Vec<_>>()
        );
        assert_matches!(parse_cpu_ranges(""), Err(_));
        assert_matches!(parse_cpu_ranges("0-1,2-"), Err(_));
        assert_matches!(parse_cpu_ranges("foo"), Err(_));
    }

    #[test]
    fn test_parse_kernel_symbols() {
        let data = "0000000000002000 A irq_stack_backing_store\n\
                          0000000000006000 A cpu_tss_rw [foo bar]\n"
            .as_bytes();
        let syms = parse_kernel_symbols(&mut BufReader::new(data)).unwrap();
        assert_eq!(syms.keys().collect::<Vec<_>>(), vec![&0x2000, &0x6000]);
        assert_eq!(
            syms.get(&0x2000u64).unwrap().as_str(),
            "irq_stack_backing_store"
        );
        assert_eq!(syms.get(&0x6000u64).unwrap().as_str(), "cpu_tss_rw");
    }
}
