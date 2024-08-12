use std::{
    cmp,
    ffi::{c_char, CStr, CString},
    io, iter,
    mem::{self, MaybeUninit},
    os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, RawFd},
    slice,
};

use aya_obj::{
    btf::{FuncSecInfo, LineSecInfo},
    generated::{
        bpf_attach_type, bpf_attr, bpf_btf_info, bpf_cmd, bpf_insn, bpf_link_info, bpf_map_info,
        bpf_map_type, bpf_prog_info, bpf_prog_type, BPF_F_REPLACE,
    },
    VerifierLog,
};
use libc::{ENOENT, ENOSPC};

use crate::{
    maps::PerCpuValues,
    sys::{syscall, SysResult, Syscall, SyscallError},
    util::KernelVersion,
    Pod, VerifierLogLevel, BPF_OBJ_NAME_LEN,
};

pub(crate) fn bpf_create_map(
    name: &CStr,
    def: &aya_obj::maps::Map,
    btf_fd: Option<BorrowedFd<'_>>,
    kernel_version: KernelVersion,
) -> SysResult<crate::MockableFd> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    let u = unsafe { &mut attr.__bindgen_anon_1 };
    u.map_type = def.map_type();
    u.key_size = def.key_size();
    u.value_size = def.value_size();
    u.max_entries = def.max_entries();
    u.map_flags = def.map_flags();

    if let aya_obj::maps::Map::Btf(m) = def {
        use bpf_map_type::*;

        // Mimic https://github.com/libbpf/libbpf/issues/355
        // Currently a bunch of (usually pretty specialized) BPF maps do not support
        // specifying BTF types for the key and value.
        match u.map_type.try_into() {
            Ok(BPF_MAP_TYPE_PERF_EVENT_ARRAY)
            | Ok(BPF_MAP_TYPE_CGROUP_ARRAY)
            | Ok(BPF_MAP_TYPE_STACK_TRACE)
            | Ok(BPF_MAP_TYPE_ARRAY_OF_MAPS)
            | Ok(BPF_MAP_TYPE_HASH_OF_MAPS)
            | Ok(BPF_MAP_TYPE_DEVMAP)
            | Ok(BPF_MAP_TYPE_DEVMAP_HASH)
            | Ok(BPF_MAP_TYPE_CPUMAP)
            | Ok(BPF_MAP_TYPE_XSKMAP)
            | Ok(BPF_MAP_TYPE_SOCKMAP)
            | Ok(BPF_MAP_TYPE_SOCKHASH)
            | Ok(BPF_MAP_TYPE_QUEUE)
            | Ok(BPF_MAP_TYPE_STACK)
            | Ok(BPF_MAP_TYPE_RINGBUF) => {
                u.btf_key_type_id = 0;
                u.btf_value_type_id = 0;
                u.btf_fd = 0;
            }
            _ => {
                u.btf_key_type_id = m.def.btf_key_type_id;
                u.btf_value_type_id = m.def.btf_value_type_id;
                u.btf_fd = btf_fd.map(|fd| fd.as_raw_fd()).unwrap_or_default() as u32;
            }
        }
    }

    // https://github.com/torvalds/linux/commit/ad5b177bd73f5107d97c36f56395c4281fb6f089
    // The map name was added as a parameter in kernel 4.15+ so we skip adding it on
    // older kernels for compatibility
    if kernel_version >= KernelVersion::new(4, 15, 0) {
        // u.map_name is 16 bytes max and must be NULL terminated
        let name_len = cmp::min(name.to_bytes().len(), BPF_OBJ_NAME_LEN - 1);
        u.map_name[..name_len]
            .copy_from_slice(unsafe { slice::from_raw_parts(name.as_ptr(), name_len) });
    }

    // SAFETY: BPF_MAP_CREATE returns a new file descriptor.
    unsafe { fd_sys_bpf(bpf_cmd::BPF_MAP_CREATE, &mut attr) }
}

pub(crate) fn bpf_pin_object(fd: BorrowedFd<'_>, path: &CStr) -> SysResult<i64> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_4 };
    u.bpf_fd = fd.as_raw_fd() as u32;
    u.pathname = path.as_ptr() as u64;
    sys_bpf(bpf_cmd::BPF_OBJ_PIN, &mut attr)
}

pub(crate) fn bpf_get_object(path: &CStr) -> SysResult<crate::MockableFd> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_4 };
    u.pathname = path.as_ptr() as u64;
    // SAFETY: BPF_OBJ_GET returns a new file descriptor.
    unsafe { fd_sys_bpf(bpf_cmd::BPF_OBJ_GET, &mut attr) }
}

pub(crate) struct EbpfLoadProgramAttrs<'a> {
    pub(crate) name: Option<CString>,
    pub(crate) ty: bpf_prog_type,
    pub(crate) insns: &'a [bpf_insn],
    pub(crate) license: &'a CStr,
    pub(crate) kernel_version: u32,
    pub(crate) expected_attach_type: Option<bpf_attach_type>,
    pub(crate) prog_btf_fd: Option<BorrowedFd<'a>>,
    pub(crate) attach_btf_obj_fd: Option<BorrowedFd<'a>>,
    pub(crate) attach_btf_id: Option<u32>,
    pub(crate) attach_prog_fd: Option<BorrowedFd<'a>>,
    pub(crate) func_info_rec_size: usize,
    pub(crate) func_info: FuncSecInfo,
    pub(crate) line_info_rec_size: usize,
    pub(crate) line_info: LineSecInfo,
    pub(crate) flags: u32,
}

pub(crate) fn bpf_load_program(
    aya_attr: &EbpfLoadProgramAttrs<'_>,
    log_buf: &mut [u8],
    verifier_log_level: VerifierLogLevel,
) -> SysResult<crate::MockableFd> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    let u = unsafe { &mut attr.__bindgen_anon_3 };

    if let Some(prog_name) = &aya_attr.name {
        let mut name: [c_char; 16] = [0; 16];
        let name_bytes = prog_name.to_bytes();
        let len = cmp::min(name.len(), name_bytes.len());
        name[..len].copy_from_slice(unsafe {
            slice::from_raw_parts(name_bytes.as_ptr() as *const c_char, len)
        });
        u.prog_name = name;
    }

    u.prog_flags = aya_attr.flags;
    u.prog_type = aya_attr.ty as u32;
    if let Some(v) = aya_attr.expected_attach_type {
        u.expected_attach_type = v as u32;
    }
    u.insns = aya_attr.insns.as_ptr() as u64;
    u.insn_cnt = aya_attr.insns.len() as u32;
    u.license = aya_attr.license.as_ptr() as u64;
    u.kern_version = aya_attr.kernel_version;

    // these must be allocated here to ensure the slice outlives the pointer
    // so .as_ptr below won't point to garbage
    let line_info_buf = aya_attr.line_info.line_info_bytes();
    let func_info_buf = aya_attr.func_info.func_info_bytes();

    if let Some(btf_fd) = aya_attr.prog_btf_fd {
        u.prog_btf_fd = btf_fd.as_raw_fd() as u32;
        if aya_attr.line_info_rec_size > 0 {
            u.line_info = line_info_buf.as_ptr() as *const _ as u64;
            u.line_info_cnt = aya_attr.line_info.len() as u32;
            u.line_info_rec_size = aya_attr.line_info_rec_size as u32;
        }
        if aya_attr.func_info_rec_size > 0 {
            u.func_info = func_info_buf.as_ptr() as *const _ as u64;
            u.func_info_cnt = aya_attr.func_info.len() as u32;
            u.func_info_rec_size = aya_attr.func_info_rec_size as u32;
        }
    }
    if !log_buf.is_empty() {
        u.log_level = verifier_log_level.bits();
        u.log_buf = log_buf.as_mut_ptr() as u64;
        u.log_size = log_buf.len() as u32;
    }
    if let Some(v) = aya_attr.attach_btf_obj_fd {
        u.__bindgen_anon_1.attach_btf_obj_fd = v.as_raw_fd() as _;
    }
    if let Some(v) = aya_attr.attach_prog_fd {
        u.__bindgen_anon_1.attach_prog_fd = v.as_raw_fd() as u32;
    }

    if let Some(v) = aya_attr.attach_btf_id {
        u.attach_btf_id = v;
    }
    bpf_prog_load(&mut attr)
}

fn lookup<K: Pod, V: Pod>(
    fd: BorrowedFd<'_>,
    key: Option<&K>,
    flags: u64,
    cmd: bpf_cmd,
) -> SysResult<Option<V>> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let mut value = MaybeUninit::zeroed();

    let u = unsafe { &mut attr.__bindgen_anon_2 };
    u.map_fd = fd.as_raw_fd() as u32;
    if let Some(key) = key {
        u.key = key as *const _ as u64;
    }
    u.__bindgen_anon_1.value = &mut value as *mut _ as u64;
    u.flags = flags;

    match sys_bpf(cmd, &mut attr) {
        Ok(_) => Ok(Some(unsafe { value.assume_init() })),
        Err((_, io_error)) if io_error.raw_os_error() == Some(ENOENT) => Ok(None),
        Err(e) => Err(e),
    }
}

pub(crate) fn bpf_map_lookup_elem<K: Pod, V: Pod>(
    fd: BorrowedFd<'_>,
    key: &K,
    flags: u64,
) -> SysResult<Option<V>> {
    lookup(fd, Some(key), flags, bpf_cmd::BPF_MAP_LOOKUP_ELEM)
}

pub(crate) fn bpf_map_lookup_and_delete_elem<K: Pod, V: Pod>(
    fd: BorrowedFd<'_>,
    key: Option<&K>,
    flags: u64,
) -> SysResult<Option<V>> {
    lookup(fd, key, flags, bpf_cmd::BPF_MAP_LOOKUP_AND_DELETE_ELEM)
}

pub(crate) fn bpf_map_lookup_elem_per_cpu<K: Pod, V: Pod>(
    fd: BorrowedFd<'_>,
    key: &K,
    flags: u64,
) -> SysResult<Option<PerCpuValues<V>>> {
    let mut mem = PerCpuValues::<V>::alloc_kernel_mem().map_err(|io_error| (-1, io_error))?;
    match bpf_map_lookup_elem_ptr(fd, Some(key), mem.as_mut_ptr(), flags) {
        Ok(_) => Ok(Some(unsafe { PerCpuValues::from_kernel_mem(mem) })),
        Err((_, io_error)) if io_error.raw_os_error() == Some(ENOENT) => Ok(None),
        Err(e) => Err(e),
    }
}

pub(crate) fn bpf_map_lookup_elem_ptr<K: Pod, V>(
    fd: BorrowedFd<'_>,
    key: Option<&K>,
    value: *mut V,
    flags: u64,
) -> SysResult<Option<()>> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    let u = unsafe { &mut attr.__bindgen_anon_2 };
    u.map_fd = fd.as_raw_fd() as u32;
    if let Some(key) = key {
        u.key = key as *const _ as u64;
    }
    u.__bindgen_anon_1.value = value as u64;
    u.flags = flags;

    match sys_bpf(bpf_cmd::BPF_MAP_LOOKUP_ELEM, &mut attr) {
        Ok(_) => Ok(Some(())),
        Err((_, io_error)) if io_error.raw_os_error() == Some(ENOENT) => Ok(None),
        Err(e) => Err(e),
    }
}

pub(crate) fn bpf_map_update_elem<K: Pod, V: Pod>(
    fd: BorrowedFd<'_>,
    key: Option<&K>,
    value: &V,
    flags: u64,
) -> SysResult<i64> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    let u = unsafe { &mut attr.__bindgen_anon_2 };
    u.map_fd = fd.as_raw_fd() as u32;
    if let Some(key) = key {
        u.key = key as *const _ as u64;
    }
    u.__bindgen_anon_1.value = value as *const _ as u64;
    u.flags = flags;

    sys_bpf(bpf_cmd::BPF_MAP_UPDATE_ELEM, &mut attr)
}

pub(crate) fn bpf_map_push_elem<V: Pod>(
    fd: BorrowedFd<'_>,
    value: &V,
    flags: u64,
) -> SysResult<i64> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    let u = unsafe { &mut attr.__bindgen_anon_2 };
    u.map_fd = fd.as_raw_fd() as u32;
    u.__bindgen_anon_1.value = value as *const _ as u64;
    u.flags = flags;

    sys_bpf(bpf_cmd::BPF_MAP_UPDATE_ELEM, &mut attr)
}

pub(crate) fn bpf_map_update_elem_ptr<K, V>(
    fd: BorrowedFd<'_>,
    key: *const K,
    value: *mut V,
    flags: u64,
) -> SysResult<i64> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    let u = unsafe { &mut attr.__bindgen_anon_2 };
    u.map_fd = fd.as_raw_fd() as u32;
    u.key = key as u64;
    u.__bindgen_anon_1.value = value as u64;
    u.flags = flags;

    sys_bpf(bpf_cmd::BPF_MAP_UPDATE_ELEM, &mut attr)
}

pub(crate) fn bpf_map_update_elem_per_cpu<K: Pod, V: Pod>(
    fd: BorrowedFd<'_>,
    key: &K,
    values: &PerCpuValues<V>,
    flags: u64,
) -> SysResult<i64> {
    let mut mem = values.build_kernel_mem().map_err(|e| (-1, e))?;
    bpf_map_update_elem_ptr(fd, key, mem.as_mut_ptr(), flags)
}

pub(crate) fn bpf_map_delete_elem<K: Pod>(fd: BorrowedFd<'_>, key: &K) -> SysResult<i64> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    let u = unsafe { &mut attr.__bindgen_anon_2 };
    u.map_fd = fd.as_raw_fd() as u32;
    u.key = key as *const _ as u64;

    sys_bpf(bpf_cmd::BPF_MAP_DELETE_ELEM, &mut attr)
}

pub(crate) fn bpf_map_get_next_key<K: Pod>(
    fd: BorrowedFd<'_>,
    key: Option<&K>,
) -> SysResult<Option<K>> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let mut next_key = MaybeUninit::uninit();

    let u = unsafe { &mut attr.__bindgen_anon_2 };
    u.map_fd = fd.as_raw_fd() as u32;
    if let Some(key) = key {
        u.key = key as *const _ as u64;
    }
    u.__bindgen_anon_1.next_key = &mut next_key as *mut _ as u64;

    match sys_bpf(bpf_cmd::BPF_MAP_GET_NEXT_KEY, &mut attr) {
        Ok(_) => Ok(Some(unsafe { next_key.assume_init() })),
        Err((_, io_error)) if io_error.raw_os_error() == Some(ENOENT) => Ok(None),
        Err(e) => Err(e),
    }
}

// since kernel 5.2
pub(crate) fn bpf_map_freeze(fd: BorrowedFd<'_>) -> SysResult<i64> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_2 };
    u.map_fd = fd.as_raw_fd() as u32;
    sys_bpf(bpf_cmd::BPF_MAP_FREEZE, &mut attr)
}

pub(crate) enum LinkTarget<'f> {
    Fd(BorrowedFd<'f>),
    IfIndex(u32),
}

// since kernel 5.7
pub(crate) fn bpf_link_create(
    prog_fd: BorrowedFd<'_>,
    target: LinkTarget<'_>,
    attach_type: bpf_attach_type,
    btf_id: Option<u32>,
    flags: u32,
) -> SysResult<crate::MockableFd> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    attr.link_create.__bindgen_anon_1.prog_fd = prog_fd.as_raw_fd() as u32;

    match target {
        LinkTarget::Fd(fd) => {
            attr.link_create.__bindgen_anon_2.target_fd = fd.as_raw_fd() as u32;
        }
        LinkTarget::IfIndex(ifindex) => {
            attr.link_create.__bindgen_anon_2.target_ifindex = ifindex;
        }
    };
    attr.link_create.attach_type = attach_type as u32;
    attr.link_create.flags = flags;
    if let Some(btf_id) = btf_id {
        attr.link_create.__bindgen_anon_3.target_btf_id = btf_id;
    }

    // SAFETY: BPF_LINK_CREATE returns a new file descriptor.
    unsafe { fd_sys_bpf(bpf_cmd::BPF_LINK_CREATE, &mut attr) }
}

// since kernel 5.7
pub(crate) fn bpf_link_update(
    link_fd: BorrowedFd<'_>,
    new_prog_fd: BorrowedFd<'_>,
    old_prog_fd: Option<RawFd>,
    flags: u32,
) -> SysResult<i64> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    attr.link_update.link_fd = link_fd.as_raw_fd() as u32;
    attr.link_update.__bindgen_anon_1.new_prog_fd = new_prog_fd.as_raw_fd() as u32;
    if let Some(fd) = old_prog_fd {
        attr.link_update.__bindgen_anon_2.old_prog_fd = fd as u32;
        attr.link_update.flags = flags | BPF_F_REPLACE;
    } else {
        attr.link_update.flags = flags;
    }

    sys_bpf(bpf_cmd::BPF_LINK_UPDATE, &mut attr)
}

pub(crate) fn bpf_prog_attach(
    prog_fd: BorrowedFd<'_>,
    target_fd: BorrowedFd<'_>,
    attach_type: bpf_attach_type,
) -> Result<(), SyscallError> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    attr.__bindgen_anon_5.attach_bpf_fd = prog_fd.as_raw_fd() as u32;
    attr.__bindgen_anon_5.__bindgen_anon_1.target_fd = target_fd.as_raw_fd() as u32;
    attr.__bindgen_anon_5.attach_type = attach_type as u32;

    let ret = sys_bpf(bpf_cmd::BPF_PROG_ATTACH, &mut attr).map_err(|(code, io_error)| {
        assert_eq!(code, -1);
        SyscallError {
            call: "bpf_prog_attach",
            io_error,
        }
    })?;
    assert_eq!(ret, 0);
    Ok(())
}

pub(crate) fn bpf_prog_detach(
    prog_fd: BorrowedFd<'_>,
    target_fd: BorrowedFd<'_>,
    attach_type: bpf_attach_type,
) -> Result<(), SyscallError> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    attr.__bindgen_anon_5.attach_bpf_fd = prog_fd.as_raw_fd() as u32;
    attr.__bindgen_anon_5.__bindgen_anon_1.target_fd = target_fd.as_raw_fd() as u32;
    attr.__bindgen_anon_5.attach_type = attach_type as u32;

    let ret = sys_bpf(bpf_cmd::BPF_PROG_DETACH, &mut attr).map_err(|(code, io_error)| {
        assert_eq!(code, -1);
        SyscallError {
            call: "bpf_prog_detach",
            io_error,
        }
    })?;
    assert_eq!(ret, 0);
    Ok(())
}

pub(crate) fn bpf_prog_query(
    target_fd: RawFd,
    attach_type: bpf_attach_type,
    query_flags: u32,
    attach_flags: Option<&mut u32>,
    prog_ids: &mut [u32],
    prog_cnt: &mut u32,
) -> SysResult<i64> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    attr.query.__bindgen_anon_1.target_fd = target_fd as u32;
    attr.query.attach_type = attach_type as u32;
    attr.query.query_flags = query_flags;
    attr.query.__bindgen_anon_2.prog_cnt = prog_ids.len() as u32;
    attr.query.prog_ids = prog_ids.as_mut_ptr() as u64;

    let ret = sys_bpf(bpf_cmd::BPF_PROG_QUERY, &mut attr);

    *prog_cnt = unsafe { attr.query.__bindgen_anon_2.prog_cnt };

    if let Some(attach_flags) = attach_flags {
        *attach_flags = unsafe { attr.query.attach_flags };
    }

    ret
}

pub(crate) fn bpf_prog_get_fd_by_id(prog_id: u32) -> Result<crate::MockableFd, SyscallError> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    attr.__bindgen_anon_6.__bindgen_anon_1.prog_id = prog_id;
    // SAFETY: BPF_PROG_GET_FD_BY_ID returns a new file descriptor.
    unsafe { fd_sys_bpf(bpf_cmd::BPF_PROG_GET_FD_BY_ID, &mut attr) }.map_err(|(code, io_error)| {
        assert_eq!(code, -1);
        SyscallError {
            call: "bpf_prog_get_fd_by_id",
            io_error,
        }
    })
}

fn bpf_obj_get_info_by_fd<T, F: FnOnce(&mut T)>(
    fd: BorrowedFd<'_>,
    init: F,
) -> Result<T, SyscallError> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let mut info = unsafe { mem::zeroed() };

    init(&mut info);

    attr.info.bpf_fd = fd.as_raw_fd() as u32;
    attr.info.info = &info as *const _ as u64;
    attr.info.info_len = mem::size_of_val(&info) as u32;

    match sys_bpf(bpf_cmd::BPF_OBJ_GET_INFO_BY_FD, &mut attr) {
        Ok(code) => {
            assert_eq!(code, 0);
            Ok(info)
        }
        Err((code, io_error)) => {
            assert_eq!(code, -1);
            Err(SyscallError {
                call: "bpf_obj_get_info_by_fd",
                io_error,
            })
        }
    }
}

pub(crate) fn bpf_prog_get_info_by_fd(
    fd: BorrowedFd<'_>,
    map_ids: &mut [u32],
) -> Result<bpf_prog_info, SyscallError> {
    bpf_obj_get_info_by_fd(fd, |info: &mut bpf_prog_info| {
        info.nr_map_ids = map_ids.len() as _;
        info.map_ids = map_ids.as_mut_ptr() as _;
    })
}

pub(crate) fn bpf_map_get_fd_by_id(map_id: u32) -> Result<crate::MockableFd, SyscallError> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    attr.__bindgen_anon_6.__bindgen_anon_1.map_id = map_id;

    // SAFETY: BPF_MAP_GET_FD_BY_ID returns a new file descriptor.
    unsafe { fd_sys_bpf(bpf_cmd::BPF_MAP_GET_FD_BY_ID, &mut attr) }.map_err(|(code, io_error)| {
        assert_eq!(code, -1);
        SyscallError {
            call: "bpf_map_get_fd_by_id",
            io_error,
        }
    })
}

pub(crate) fn bpf_map_get_info_by_fd(fd: BorrowedFd<'_>) -> Result<bpf_map_info, SyscallError> {
    bpf_obj_get_info_by_fd(fd, |_| {})
}

pub(crate) fn bpf_link_get_fd_by_id(link_id: u32) -> Result<crate::MockableFd, SyscallError> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    attr.__bindgen_anon_6.__bindgen_anon_1.link_id = link_id;
    // SAFETY: BPF_LINK_GET_FD_BY_ID returns a new file descriptor.
    unsafe { fd_sys_bpf(bpf_cmd::BPF_LINK_GET_FD_BY_ID, &mut attr) }.map_err(|(code, io_error)| {
        assert_eq!(code, -1);
        SyscallError {
            call: "bpf_link_get_fd_by_id",
            io_error,
        }
    })
}

pub(crate) fn bpf_link_get_info_by_fd(fd: BorrowedFd<'_>) -> Result<bpf_link_info, SyscallError> {
    bpf_obj_get_info_by_fd(fd, |_| {})
}

pub(crate) fn btf_obj_get_info_by_fd(
    fd: BorrowedFd<'_>,
    buf: &mut [u8],
) -> Result<bpf_btf_info, SyscallError> {
    bpf_obj_get_info_by_fd(fd, |info: &mut bpf_btf_info| {
        info.btf = buf.as_mut_ptr() as _;
        info.btf_size = buf.len() as _;
    })
}

pub(crate) fn bpf_raw_tracepoint_open(
    name: Option<&CStr>,
    prog_fd: BorrowedFd<'_>,
) -> SysResult<crate::MockableFd> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    attr.raw_tracepoint.name = match name {
        Some(n) => n.as_ptr() as u64,
        None => 0,
    };
    attr.raw_tracepoint.prog_fd = prog_fd.as_raw_fd() as u32;

    // SAFETY: BPF_RAW_TRACEPOINT_OPEN returns a new file descriptor.
    unsafe { fd_sys_bpf(bpf_cmd::BPF_RAW_TRACEPOINT_OPEN, &mut attr) }
}

pub(crate) fn bpf_load_btf(
    raw_btf: &[u8],
    log_buf: &mut [u8],
    verifier_log_level: VerifierLogLevel,
) -> SysResult<crate::MockableFd> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_7 };
    u.btf = raw_btf.as_ptr() as *const _ as u64;
    u.btf_size = mem::size_of_val(raw_btf) as u32;
    if !log_buf.is_empty() {
        u.btf_log_level = verifier_log_level.bits();
        u.btf_log_buf = log_buf.as_mut_ptr() as u64;
        u.btf_log_size = log_buf.len() as u32;
    }
    // SAFETY: `BPF_BTF_LOAD` returns a newly created fd.
    unsafe { fd_sys_bpf(bpf_cmd::BPF_BTF_LOAD, &mut attr) }
}

// SAFETY: only use for bpf_cmd that return a new file descriptor on success.
pub(crate) unsafe fn fd_sys_bpf(cmd: bpf_cmd, attr: &mut bpf_attr) -> SysResult<crate::MockableFd> {
    let fd = sys_bpf(cmd, attr)?;
    let fd = fd.try_into().map_err(|_| {
        (
            fd,
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{cmd:?}: invalid fd returned: {fd}"),
            ),
        )
    })?;
    Ok(crate::MockableFd::from_raw_fd(fd))
}

pub(crate) fn bpf_btf_get_fd_by_id(id: u32) -> Result<crate::MockableFd, SyscallError> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    attr.__bindgen_anon_6.__bindgen_anon_1.btf_id = id;

    // SAFETY: BPF_BTF_GET_FD_BY_ID returns a new file descriptor.
    unsafe { fd_sys_bpf(bpf_cmd::BPF_BTF_GET_FD_BY_ID, &mut attr) }.map_err(|(code, io_error)| {
        assert_eq!(code, -1);
        SyscallError {
            call: "bpf_btf_get_fd_by_id",
            io_error,
        }
    })
}

pub(crate) fn bpf_prog_load(attr: &mut bpf_attr) -> SysResult<crate::MockableFd> {
    // SAFETY: BPF_PROG_LOAD returns a new file descriptor.
    unsafe { fd_sys_bpf(bpf_cmd::BPF_PROG_LOAD, attr) }
}

fn sys_bpf(cmd: bpf_cmd, attr: &mut bpf_attr) -> SysResult<i64> {
    syscall(Syscall::Ebpf { cmd, attr })
}

fn bpf_obj_get_next_id(
    id: u32,
    cmd: bpf_cmd,
    name: &'static str,
) -> Result<Option<u32>, SyscallError> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_6 };
    u.__bindgen_anon_1.start_id = id;
    match sys_bpf(cmd, &mut attr) {
        Ok(code) => {
            assert_eq!(code, 0);
            Ok(Some(unsafe { attr.__bindgen_anon_6.next_id }))
        }
        Err((code, io_error)) => {
            assert_eq!(code, -1);
            if io_error.raw_os_error() == Some(ENOENT) {
                Ok(None)
            } else {
                Err(SyscallError {
                    call: name,
                    io_error,
                })
            }
        }
    }
}

fn iter_obj_ids(
    cmd: bpf_cmd,
    name: &'static str,
) -> impl Iterator<Item = Result<u32, SyscallError>> {
    let mut current_id = Some(0);
    iter::from_fn(move || {
        let next_id = {
            let current_id = current_id?;
            bpf_obj_get_next_id(current_id, cmd, name).transpose()
        };
        current_id = next_id.as_ref().and_then(|next_id| match next_id {
            Ok(next_id) => Some(*next_id),
            Err(SyscallError { .. }) => None,
        });
        next_id
    })
}

pub(crate) fn iter_prog_ids() -> impl Iterator<Item = Result<u32, SyscallError>> {
    iter_obj_ids(bpf_cmd::BPF_PROG_GET_NEXT_ID, "bpf_prog_get_next_id")
}

pub(crate) fn iter_link_ids() -> impl Iterator<Item = Result<u32, SyscallError>> {
    iter_obj_ids(bpf_cmd::BPF_LINK_GET_NEXT_ID, "bpf_link_get_next_id")
}

pub(crate) fn iter_map_ids() -> impl Iterator<Item = Result<u32, SyscallError>> {
    iter_obj_ids(bpf_cmd::BPF_MAP_GET_NEXT_ID, "bpf_map_get_next_id")
}

pub(crate) fn retry_with_verifier_logs<T>(
    max_retries: usize,
    f: impl Fn(&mut [u8]) -> SysResult<T>,
) -> (SysResult<T>, VerifierLog) {
    const MIN_LOG_BUF_SIZE: usize = 1024 * 10;
    const MAX_LOG_BUF_SIZE: usize = (u32::MAX >> 8) as usize;

    let mut log_buf = Vec::new();
    let mut retries = 0;
    loop {
        let ret = f(log_buf.as_mut_slice());
        if retries != max_retries {
            if let Err((_, io_error)) = &ret {
                if retries == 0 || io_error.raw_os_error() == Some(ENOSPC) {
                    let len = (log_buf.capacity() * 10).clamp(MIN_LOG_BUF_SIZE, MAX_LOG_BUF_SIZE);
                    log_buf.resize(len, 0);
                    if let Some(first) = log_buf.first_mut() {
                        *first = 0;
                    }
                    retries += 1;
                    continue;
                }
            }
        }
        if let Some(pos) = log_buf.iter().position(|b| *b == 0) {
            log_buf.truncate(pos);
        }
        let log_buf = String::from_utf8(log_buf).unwrap();

        break (ret, VerifierLog::new(log_buf));
    }
}
