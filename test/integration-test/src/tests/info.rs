//! Tests the Info API.
// TODO: Figure out a way to assert that field is truely not present.
//       We can call `bpf_obj_get_info_by_fd()` and fill our target field with arbitrary data.
//       `E2BIG` error from `bpf_check_uarg_tail_zero()` will detect if we're accessing fields that
//       isn't supported on the kernel.
//       Issue is that `bpf_obj_get_info_by_fd()` will need to be public. :/

use std::{
    ffi::CString,
    fs::{self, File},
    os::unix::fs::MetadataExt as _,
    panic,
    path::Path,
    time::SystemTime,
};

use assert_matches::assert_matches;
use aya::{
    features,
    links::{loaded_links, AttachType, LinkInfo, LinkMetadata, LinkType},
    maps::{loaded_maps, Array, HashMap, IterableMap as _, MapType},
    programs::{
        loaded_programs,
        perf_event::{self, PerfEventConfig, SoftwareEvent},
        CgroupSkb, FEntry, KProbe, PerfEvent, ProgramType, RawTracePoint, SchedClassifier,
        SkLookup, SocketFilter, TracePoint, UProbe, Xdp,
    },
    sys::enable_stats,
    util::{self, KernelVersion},
    Btf, Ebpf,
};

use crate::utils::{
    is_link_einval, is_map_einval, is_prog_einval, kernel_assert, kernel_assert_eq, NetNsGuard,
};

const BPF_JIT_ENABLE: &str = "/proc/sys/net/core/bpf_jit_enable";
const BPF_STATS_ENABLED: &str = "/proc/sys/kernel/bpf_stats_enabled";

#[test]
fn test_loaded_programs() {
    // Load a program.
    // Since we are only testing the programs for their metadata, there is no need to "attach" them.
    let mut bpf = Ebpf::load(crate::SIMPLE_PROG).unwrap();
    let prog: &mut SocketFilter = bpf.program_mut("simple_prog").unwrap().try_into().unwrap();
    prog.load().unwrap();
    let test_prog = prog.info().unwrap();

    // Ensure loaded program doesn't panic
    let mut programs = loaded_programs().peekable();
    if let Err(err) = programs.peek().unwrap() {
        if is_prog_einval(err) {
            eprintln!(
                "ignoring test completely as `loaded_programs()` is not available on the host"
            );
            return;
        }
        panic!("{err}");
    }

    // Loaded programs should contain our test program
    let mut programs = programs.filter_map(|prog| prog.ok());
    kernel_assert!(
        programs.any(|prog| prog.id() == test_prog.id()),
        KernelVersion::new(4, 13, 0)
    );
}

#[test]
fn test_program_info() {
    // Kernels below v4.15 have been observed to have `bpf_jit_enable` disabled by default.
    let previously_enabled = is_sysctl_enabled(BPF_JIT_ENABLE);
    // Restore to previous state when panic occurs.
    let prev_panic = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        if !previously_enabled {
            disable_sysctl_param(BPF_JIT_ENABLE);
        }
        prev_panic(panic_info);
    }));
    let jit_enabled = previously_enabled || enable_sysctl_param(BPF_JIT_ENABLE);

    let mut bpf = Ebpf::load(crate::SIMPLE_PROG).unwrap();
    let prog: &mut SocketFilter = bpf.program_mut("simple_prog").unwrap().try_into().unwrap();
    prog.load().unwrap();
    let test_prog = prog.info().unwrap();

    // Test `bpf_prog_info` fields.
    kernel_assert_eq!(
        ProgramType::SocketFilter,
        test_prog.program_type().unwrap_or(ProgramType::Unspecified),
        KernelVersion::new(4, 13, 0),
    );
    kernel_assert!(test_prog.id() > 0, KernelVersion::new(4, 13, 0));
    kernel_assert!(test_prog.tag() > 0, KernelVersion::new(4, 13, 0));
    if jit_enabled {
        kernel_assert!(test_prog.size_jitted() > 0, KernelVersion::new(4, 13, 0));
    }
    kernel_assert!(
        test_prog.size_translated().is_some(),
        KernelVersion::new(4, 13, 0),
    );
    kernel_assert!(
        test_prog.loaded_at().is_some(),
        KernelVersion::new(4, 15, 0),
    );
    kernel_assert_eq!(
        Some(0),
        test_prog.created_by_uid(),
        KernelVersion::new(4, 15, 0),
    );
    let maps = test_prog.map_ids().unwrap();
    kernel_assert!(
        maps.is_some_and(|ids| ids.is_empty()),
        KernelVersion::new(4, 15, 0),
    );
    kernel_assert_eq!(
        Some("simple_prog"),
        test_prog.name_as_str(),
        KernelVersion::new(4, 15, 0),
    );
    kernel_assert_eq!(
        Some(true),
        test_prog.gpl_compatible(),
        KernelVersion::new(4, 18, 0),
    );
    kernel_assert!(
        test_prog.verified_instruction_count().is_some(),
        KernelVersion::new(5, 16, 0),
    );

    // We can't reliably test these fields since `0` can be interpreted as the actual value or
    // unavailable.
    test_prog.btf_id();

    // Ensure rest of the fields do not panic.
    test_prog.memory_locked().unwrap();
    test_prog.fd().unwrap();

    // Restore to previous state
    if !previously_enabled {
        disable_sysctl_param(BPF_JIT_ENABLE);
    }
}

#[test]
fn test_loaded_at() {
    let mut bpf: Ebpf = Ebpf::load(crate::SIMPLE_PROG).unwrap();
    let prog: &mut SocketFilter = bpf.program_mut("simple_prog").unwrap().try_into().unwrap();

    // SystemTime is not monotonic, which can cause this test to flake. We don't expect the clock
    // timestamp to continuously jump around, so we add some retries. If the test is ever correct,
    // we know that the value returned by loaded_at() was reasonable relative to SystemTime::now().
    let mut failures = Vec::new();
    for _ in 0..5 {
        let t1 = SystemTime::now();
        prog.load().unwrap();

        let t2 = SystemTime::now();
        let loaded_at = match prog.info().unwrap().loaded_at() {
            Some(time) => time,
            None => {
                eprintln!("ignoring test completely as `load_time` field of `bpf_prog_info` is not available on the host");
                return;
            }
        };
        prog.unload().unwrap();

        let range = t1..t2;
        if range.contains(&loaded_at) {
            failures.clear();
            break;
        }
        failures.push(LoadedAtRange(loaded_at, range));
    }
    assert!(
        failures.is_empty(),
        "loaded_at was not in range: {failures:?}",
    );

    struct LoadedAtRange(SystemTime, std::ops::Range<SystemTime>);
    impl std::fmt::Debug for LoadedAtRange {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let Self(loaded_at, range) = self;
            write!(f, "{range:?}.contains({loaded_at:?})")
        }
    }
}

#[test]
fn test_prog_stats() {
    // Test depends on whether trace point exists.
    if !Path::new("/sys/kernel/debug/tracing/events/syscalls/sys_enter_bpf").exists() {
        eprintln!(
            "ignoring test completely as `syscalls/sys_enter_bpf` is not available on the host"
        );
        return;
    }

    let stats_fd = enable_stats(aya::sys::Stats::RunTime).ok();
    // Restore to previous state when panic occurs.
    let previously_enabled = is_sysctl_enabled(BPF_STATS_ENABLED);
    let prev_panic = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        if !previously_enabled {
            disable_sysctl_param(BPF_STATS_ENABLED);
        }
        prev_panic(panic_info);
    }));

    let stats_enabled =
        stats_fd.is_some() || previously_enabled || enable_sysctl_param(BPF_STATS_ENABLED);
    if !stats_enabled {
        eprintln!("ignoring test completely as bpf stats could not be enabled on the host");
        return;
    }

    let mut bpf = Ebpf::load(crate::TEST).unwrap();
    let prog: &mut TracePoint = bpf
        .program_mut("test_tracepoint")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
    prog.attach("syscalls", "sys_enter_bpf").unwrap();
    let test_prog = prog.info().unwrap();

    kernel_assert!(test_prog.run_count() > 0, KernelVersion::new(5, 1, 0));

    // Restore to previous state
    if !previously_enabled {
        disable_sysctl_param(BPF_STATS_ENABLED);
    }
}

#[test]
fn list_loaded_maps() {
    // Load a program with maps.
    let mut bpf: Ebpf = Ebpf::load(crate::MAP_TEST).unwrap();
    let prog: &mut SocketFilter = bpf.program_mut("simple_prog").unwrap().try_into().unwrap();
    prog.load().unwrap();

    // Ensure the loaded_maps() api doesn't panic
    let mut maps = loaded_maps().peekable();
    if let Err(err) = maps.peek().unwrap() {
        if is_map_einval(err) {
            eprintln!("ignoring test completely as `loaded_maps()` is not available on the host");
            return;
        }
        panic!("{err}");
    }

    // Loaded maps should contain our test maps
    let maps: Vec<_> = maps.filter_map(|m| m.ok()).collect();
    if let Ok(info) = &prog.info() {
        if let Some(map_ids) = info.map_ids().unwrap() {
            assert_eq!(2, map_ids.len());
            for id in map_ids {
                assert!(
                    maps.iter().any(|m| m.id() == id),
                    "expected `loaded_maps()` to have `map_ids` from program",
                );
            }
        }
    }

    let hash: HashMap<_, u32, u8> = HashMap::try_from(bpf.map("BAR").unwrap()).unwrap();
    let hash_id = hash.map().info().unwrap().id();
    kernel_assert!(
        maps.iter().any(|map| map.id() == hash_id),
        KernelVersion::new(4, 13, 0),
    );

    let array: Array<_, u32> = Array::try_from(bpf.map("FOO").unwrap()).unwrap();
    let array_id = array.map().info().unwrap().id();
    kernel_assert!(
        maps.iter().any(|map| map.id() == array_id),
        KernelVersion::new(4, 13, 0),
    );
}

#[test]
fn test_map_info() {
    let mut bpf: Ebpf = Ebpf::load(crate::MAP_TEST).unwrap();
    let prog: &mut SocketFilter = bpf.program_mut("simple_prog").unwrap().try_into().unwrap();
    prog.load().unwrap();

    // Test `bpf_map_info` fields.
    let hash: HashMap<_, u32, u8> = HashMap::try_from(bpf.map("BAR").unwrap()).unwrap();
    let hash = hash.map().info().unwrap();
    kernel_assert_eq!(
        MapType::Hash,
        hash.map_type().unwrap_or(MapType::Unspecified),
        KernelVersion::new(4, 13, 0),
    );
    kernel_assert!(hash.id() > 0, KernelVersion::new(4, 13, 0));
    kernel_assert_eq!(4, hash.key_size(), KernelVersion::new(4, 13, 0));
    kernel_assert_eq!(1, hash.value_size(), KernelVersion::new(4, 13, 0));
    kernel_assert_eq!(8, hash.max_entries(), KernelVersion::new(4, 13, 0));
    kernel_assert_eq!(
        Some("BAR"),
        hash.name_as_str(),
        KernelVersion::new(4, 15, 0),
    );

    hash.map_flags();
    hash.fd().unwrap();

    let array: Array<_, u32> = Array::try_from(bpf.map("FOO").unwrap()).unwrap();
    let array = array.map().info().unwrap();
    kernel_assert_eq!(
        MapType::Array,
        array.map_type().unwrap_or(MapType::Unspecified),
        KernelVersion::new(4, 13, 0),
    );
    kernel_assert!(array.id() > 0, KernelVersion::new(4, 13, 0));
    kernel_assert_eq!(4, array.key_size(), KernelVersion::new(4, 13, 0));
    kernel_assert_eq!(4, array.value_size(), KernelVersion::new(4, 13, 0));
    kernel_assert_eq!(10, array.max_entries(), KernelVersion::new(4, 13, 0));
    kernel_assert_eq!(
        Some("FOO"),
        array.name_as_str(),
        KernelVersion::new(4, 15, 0),
    );

    array.map_flags();
    array.fd().unwrap();
}

#[test]
fn test_link_info_raw_tp() {
    let mut bpf: Ebpf = Ebpf::load(crate::TEST).unwrap();
    let prog: &mut RawTracePoint = bpf
        .program_mut("raw_tracepoint")
        .unwrap()
        .try_into()
        .unwrap();
    if let Err(err) = prog.load() {
        if is_prog_einval(&err) {
            eprintln!(
                "ignoring test completely as `BPF_PROG_TYPE_RAW_TRACEPOINT` is not available on the host"
            );
            return;
        }
        panic!("{err}");
    }
    prog.attach("sys_exit").unwrap();

    let link_info = match get_link_info() {
        Some(info) => info,
        None => return,
    };

    assert_matches!(link_info.link_type(), Ok(link_type) => kernel_assert_eq!(
        LinkType::RawTracePoint,
        link_type,
        KernelVersion::new(5, 8, 0),
    ));
    kernel_assert!(link_info.id() > 0, KernelVersion::new(5, 8, 0));
    assert_matches!(prog.info(), Ok(prog_info) => kernel_assert_eq!(
        prog_info.id(),
        link_info.program_id(),
        KernelVersion::new(5, 8, 0),
    ));
    assert_matches!(link_info.metadata(), Ok(metadata) => assert_matches!(
        metadata,
        LinkMetadata::RawTracePoint { name } => {
            kernel_assert_eq!(Some("sys_exit"), name.as_deref(), KernelVersion::new(5, 8, 0));
        }
    ));
}

#[test]
fn test_link_info_tracing() {
    if features().btf().is_none() {
        eprintln!("ignoring test completely as BTF is not available on the host");
        return;
    }

    let mut bpf: Ebpf = Ebpf::load(crate::TEST).unwrap();
    let prog: &mut FEntry = bpf.program_mut("fentry").unwrap().try_into().unwrap();
    let btf = Btf::from_sys_fs().unwrap();
    if let Err(err) = prog.load("do_unlinkat", &btf) {
        if is_prog_einval(&err) {
            eprintln!(
                "ignoring test completely as `BPF_PROG_TYPE_TRACING` is not available on the host"
            );
            return;
        }
        panic!("{err}");
    }
    prog.attach().unwrap();

    let link_info = match get_link_info() {
        Some(info) => info,
        None => return,
    };

    assert_matches!(link_info.link_type(), Ok(link_type) => kernel_assert_eq!(
        LinkType::Tracing,
        link_type,
        KernelVersion::new(5, 8, 0),
    ));
    kernel_assert!(link_info.id() > 0, KernelVersion::new(5, 8, 0));
    assert_matches!(prog.info(), Ok(prog_info) => kernel_assert_eq!(
        prog_info.id(),
        link_info.program_id(),
        KernelVersion::new(5, 8, 0),
    ));
    assert_matches!(link_info.metadata(), Ok(metadata) => assert_matches!(
        metadata,
        LinkMetadata::Tracing { attach_type, target_obj_id, target_btf_id } => {
            assert_matches!(attach_type, Ok(attach_type) => kernel_assert_eq!(
                Some(AttachType::TraceFEntry),
                attach_type,
                KernelVersion::new(5, 8, 0),
            ));
            kernel_assert!(target_obj_id.is_some(), KernelVersion::new(5, 13, 0));
            kernel_assert!(target_btf_id.is_some(), KernelVersion::new(5, 13, 0));
        }
    ));
}

#[test]
fn test_link_info_cgroup() {
    let mut bpf: Ebpf = Ebpf::load(crate::TEST).unwrap();
    let prog: &mut CgroupSkb = bpf.program_mut("cgroup_skb").unwrap().try_into().unwrap();
    if let Err(err) = prog.load() {
        if is_prog_einval(&err) {
            eprintln!(
                "ignoring test completely as `BPF_PROG_TYPE_CGROUP_SKB` is not available on the host"
            );
            return;
        }
        panic!("{err}");
    }
    prog.attach(
        File::open("/sys/fs/cgroup").unwrap(),
        aya::programs::cgroup_skb::CgroupSkbAttachType::Ingress,
        aya::programs::links::CgroupAttachMode::Single,
    )
    .unwrap();

    let link_info = match get_link_info() {
        Some(info) => info,
        None => return,
    };

    assert_matches!(link_info.link_type(), Ok(link_type) => kernel_assert_eq!(
        LinkType::Cgroup,
        link_type,
        KernelVersion::new(5, 8, 0),
    ));
    kernel_assert!(link_info.id() > 0, KernelVersion::new(5, 8, 0));
    assert_matches!(prog.info(), Ok(prog_info) => kernel_assert_eq!(
        prog_info.id(),
        link_info.program_id(),
        KernelVersion::new(5, 8, 0),
    ));
    assert_matches!(link_info.metadata(), Ok(metadata) => assert_matches!(
        metadata,
        LinkMetadata::Cgroup { id, attach_type } => {
            kernel_assert_eq!(1, id, KernelVersion::new(5, 8, 0));
            assert_matches!(attach_type, Ok(attach_type) => kernel_assert_eq!(
                AttachType::CgroupInetIngress,
                attach_type,
                KernelVersion::new(5, 8, 0),
            ));
        }
    ));
}

#[test]
fn test_link_info_netns() {
    let netns = NetNsGuard::new();

    let mut bpf: Ebpf = Ebpf::load(crate::TEST).unwrap();
    let prog: &mut SkLookup = bpf
        .program_mut("test_sk_lookup")
        .unwrap()
        .try_into()
        .unwrap();
    if let Err(err) = prog.load() {
        if is_prog_einval(&err) {
            eprintln!(
                "ignoring test completely as `BPF_PROG_TYPE_SK_LOOKUP` is not available on the host"
            );
            return;
        }
        panic!("{err}");
    }
    let netns_path = File::open(netns.path()).unwrap();
    prog.attach(netns_path).unwrap();

    let link_info = match get_link_info() {
        Some(info) => info,
        None => return,
    };

    assert_matches!(link_info.link_type(), Ok(link_type) => kernel_assert_eq!(
        LinkType::NetNs,
        link_type,
        KernelVersion::new(5, 8, 0),
    ));
    kernel_assert!(link_info.id() > 0, KernelVersion::new(5, 8, 0));
    assert_matches!(prog.info(), Ok(prog_info) => kernel_assert_eq!(
        prog_info.id(),
        link_info.program_id(),
        KernelVersion::new(5, 8, 0),
    ));
    assert_matches!(link_info.metadata(), Ok(metadata) => assert_matches!(
        metadata,
        LinkMetadata::NetNs { net_namespace_inode, attach_type } => {
            let expected_ino = netns.file_metadata().unwrap().ino();
            kernel_assert_eq!(
                expected_ino,
                net_namespace_inode as u64,
                KernelVersion::new(5, 8, 0),
            );
            assert_matches!(attach_type, Ok(attach_type) => kernel_assert_eq!(
                AttachType::SkLookup,
                attach_type,
                KernelVersion::new(5, 8, 0),
            ));
        }
    ));
}

#[test]
fn test_link_info_xdp() {
    if KernelVersion::current().unwrap() < KernelVersion::new(5, 9, 0) {
        eprintln!("ignoring test completely as `BPF_LINK_TYPE_XDP` is not available on the host");
        return;
    }

    let _netns = NetNsGuard::new();

    let mut bpf: Ebpf = Ebpf::load(crate::TEST).unwrap();
    let prog: &mut Xdp = bpf.program_mut("pass").unwrap().try_into().unwrap();
    if let Err(err) = prog.load() {
        if is_prog_einval(&err) {
            eprintln!(
                "ignoring test completely as `BPF_PROG_TYPE_XDP` is not available on the host"
            );
            return;
        }
        panic!("{err}");
    }
    prog.attach("lo", aya::programs::xdp::XdpFlags::default())
        .unwrap();

    let link_info = match get_link_info() {
        Some(info) => info,
        None => return,
    };

    assert_matches!(link_info.link_type(), Ok(link_type) => kernel_assert_eq!(
        LinkType::Xdp,
        link_type,
        KernelVersion::new(5, 8, 0),
    ));
    kernel_assert!(link_info.id() > 0, KernelVersion::new(5, 8, 0));
    assert_matches!(prog.info(), Ok(prog_info) => kernel_assert_eq!(
        prog_info.id(),
        link_info.program_id(),
        KernelVersion::new(5, 8, 0),
    ));
    assert_matches!(link_info.metadata(), Ok(metadata) => {
        kernel_assert!(matches!(metadata, LinkMetadata::Xdp { .. }), KernelVersion::new(5, 9, 0));
        if let LinkMetadata::Xdp { interface_index, interface_name } = metadata {
            let ifname = CString::new("lo").unwrap();
            let expected_ifindex = unsafe { libc::if_nametoindex(ifname.as_ptr()) };

            kernel_assert_eq!(expected_ifindex, interface_index, KernelVersion::new(5, 9, 0));
            kernel_assert_eq!(Some("lo"), interface_name.as_deref(), KernelVersion::new(5, 9, 0));
        }
    });
}

#[test]
fn test_link_info_perf_uprobe() {
    if !features().bpf_perf_link() {
        eprintln!(
            "ignoring test completely as `BPF_LINK_TYPE_PERF_EVENT` is not available on the host"
        );
        return;
    }

    let mut bpf: Ebpf = Ebpf::load(crate::TEST).unwrap();
    let prog: &mut UProbe = bpf.program_mut("test_uprobe").unwrap().try_into().unwrap();
    if let Err(err) = prog.load() {
        if is_prog_einval(&err) {
            eprintln!(
                "ignoring test completely as `BPF_PROG_TYPE_KPROBE` is not available on the host"
            );
            return;
        }
        panic!("{err}");
    }
    prog.attach(Some("uprobe_function"), 0, "/proc/self/exe", None)
        .unwrap();

    let link_info = match get_link_info() {
        Some(info) => info,
        None => return,
    };

    assert_matches!(link_info.link_type(), Ok(link_type) => kernel_assert_eq!(
        LinkType::PerfEvent,
        link_type,
        KernelVersion::new(5, 8, 0),
    ));
    kernel_assert!(link_info.id() > 0, KernelVersion::new(5, 8, 0));
    assert_matches!(prog.info(), Ok(prog_info) => kernel_assert_eq!(
        prog_info.id(),
        link_info.program_id(),
        KernelVersion::new(5, 8, 0),
    ));
    assert_matches!(link_info.metadata(), Ok(metadata) => {
        kernel_assert!(
            matches!(metadata, LinkMetadata::UProbe { .. }),
            KernelVersion::new(6, 6, 0),
        );
        if let LinkMetadata::UProbe { return_probe, file_path, symbol_offset, .. } = metadata {
            kernel_assert!(!return_probe, KernelVersion::new(6, 6, 0));
            kernel_assert_eq!(
                Some("/proc/self/exe"),
                file_path.as_deref(),
                KernelVersion::new(6, 6, 0),
            );
            kernel_assert!(symbol_offset > 0, KernelVersion::new(6, 6, 0));
        }
    });
}

#[test]
fn test_link_info_perf_kprobe() {
    if !features().bpf_perf_link() {
        eprintln!(
            "ignoring test completely as `BPF_LINK_TYPE_PERF_EVENT` is not available on the host"
        );
        return;
    }

    let mut bpf: Ebpf = Ebpf::load(crate::TEST).unwrap();
    let prog: &mut KProbe = bpf
        .program_mut("test_kretprobe")
        .unwrap()
        .try_into()
        .unwrap();
    if let Err(err) = prog.load() {
        if is_prog_einval(&err) {
            eprintln!(
                "ignoring test completely as `BPF_PROG_TYPE_KPROBE` is not available on the host"
            );
            return;
        }
        panic!("{err}");
    }
    prog.attach("try_to_wake_up", 0).unwrap();

    let link_info = match get_link_info() {
        Some(info) => info,
        None => return,
    };

    assert_matches!(link_info.link_type(), Ok(link_type) => kernel_assert_eq!(
        LinkType::PerfEvent,
        link_type,
        KernelVersion::new(5, 8, 0),
    ));
    kernel_assert!(link_info.id() > 0, KernelVersion::new(5, 8, 0));
    assert_matches!(prog.info(), Ok(prog_info) => kernel_assert_eq!(
        prog_info.id(),
        link_info.program_id(),
        KernelVersion::new(5, 8, 0),
    ));
    assert_matches!(link_info.metadata(), Ok(metadata) => {
        kernel_assert!(
            matches!(metadata, LinkMetadata::KProbe { .. }),
            KernelVersion::new(6, 6, 0),
        );
        if let LinkMetadata::KProbe { return_probe, function_name, address, .. } = metadata {
            kernel_assert!(return_probe, KernelVersion::new(6, 6, 0));

            let name = function_name.unwrap();
            kernel_assert_eq!("try_to_wake_up", name, KernelVersion::new(6, 6, 0));

            let expected_addr = util::kernel_symbols().unwrap()
                .into_iter()
                .find_map(|(k, v)| (v == name).then_some(k));
            kernel_assert_eq!(expected_addr, Some(address), KernelVersion::new(6, 6, 0));
        }
    });
}

#[test]
fn test_link_info_perf_tracepoint() {
    if !features().bpf_perf_link() {
        eprintln!(
            "ignoring test completely as `BPF_LINK_TYPE_PERF_EVENT` is not available on the host"
        );
        return;
    }

    let mut bpf: Ebpf = Ebpf::load(crate::TEST).unwrap();
    let prog: &mut TracePoint = bpf
        .program_mut("test_tracepoint")
        .unwrap()
        .try_into()
        .unwrap();
    if let Err(err) = prog.load() {
        if is_prog_einval(&err) {
            eprintln!(
                "ignoring test completely as `BPF_PROG_TYPE_TRACEPOINT` is not available on the host"
            );
            return;
        }
        panic!("{err}");
    }
    prog.attach("syscalls", "sys_enter_kill").unwrap();

    let link_info = match get_link_info() {
        Some(info) => info,
        None => return,
    };

    assert_matches!(link_info.link_type(), Ok(link_type) => kernel_assert_eq!(
        LinkType::PerfEvent,
        link_type,
        KernelVersion::new(5, 8, 0),
    ));
    kernel_assert!(link_info.id() > 0, KernelVersion::new(5, 8, 0));
    assert_matches!(prog.info(), Ok(prog_info) => kernel_assert_eq!(
        prog_info.id(),
        link_info.program_id(),
        KernelVersion::new(5, 8, 0),
    ));
    assert_matches!(link_info.metadata(), Ok(metadata) => {
        kernel_assert!(
            matches!(metadata, LinkMetadata::TracePoint { .. }),
            KernelVersion::new(6, 6, 0),
        );
        if let LinkMetadata::TracePoint { tracepoint_name, .. } = metadata {
            kernel_assert_eq!(
                Some("sys_enter_kill"),
                tracepoint_name.as_deref(),
                KernelVersion::new(6, 6, 0),
            );
        }
    });
}

#[test]
fn test_link_info_perf_event() {
    if !features().bpf_perf_link() {
        eprintln!(
            "ignoring test completely as `BPF_LINK_TYPE_PERF_EVENT` is not available on the host"
        );
        return;
    }

    let mut bpf: Ebpf = Ebpf::load(crate::TEST).unwrap();
    let prog: &mut PerfEvent = bpf
        .program_mut("test_perf_event")
        .unwrap()
        .try_into()
        .unwrap();
    if let Err(err) = prog.load() {
        if is_prog_einval(&err) {
            eprintln!(
                "ignoring test completely as `BPF_PROG_TYPE_PERF_EVENT` is not available on the host"
            );
            return;
        }
        panic!("{err}");
    }
    prog.attach(
        PerfEventConfig::Software(SoftwareEvent::ContextSwitches),
        perf_event::PerfEventScope::CallingProcessAnyCpu,
        perf_event::SamplePolicy::Frequency(1),
        true,
    )
    .unwrap();

    let link_info = match get_link_info() {
        Some(info) => info,
        None => return,
    };

    assert_matches!(link_info.link_type(), Ok(link_type) => kernel_assert_eq!(
        LinkType::PerfEvent,
        link_type,
        KernelVersion::new(5, 8, 0),
    ));
    kernel_assert!(link_info.id() > 0, KernelVersion::new(5, 8, 0));
    assert_matches!(prog.info(), Ok(prog_info) => kernel_assert_eq!(
        prog_info.id(),
        link_info.program_id(),
        KernelVersion::new(5, 8, 0),
    ));
    assert_matches!(link_info.metadata(), Ok(metadata) => {
        kernel_assert!(
            matches!(metadata, LinkMetadata::PerfEvent { .. }),
            KernelVersion::new(6, 6, 0),
        );
        if let LinkMetadata::PerfEvent { event, .. } = metadata {
            kernel_assert_eq!(
                PerfEventConfig::Software(SoftwareEvent::ContextSwitches),
                event,
                KernelVersion::new(6, 6, 0),
            );
        }
    });
}

#[test]
fn test_link_info_tcx() {
    if KernelVersion::current().unwrap() < KernelVersion::new(6, 6, 0) {
        eprintln!("ignoring test completely as `BPF_LINK_TYPE_TCX` is not available on the host");
        return;
    }

    let _netns = NetNsGuard::new();
    let _ = aya::programs::tc::qdisc_add_clsact("lo");

    let mut bpf: Ebpf = Ebpf::load(crate::TEST).unwrap();
    let prog: &mut SchedClassifier = bpf
        .program_mut("test_sched_cls")
        .unwrap()
        .try_into()
        .unwrap();
    if let Err(err) = prog.load() {
        if is_prog_einval(&err) {
            eprintln!(
                "ignoring test completely as `BPF_PROG_TYPE_SCHED_CLS` is not available on the host"
            );
            return;
        }
        panic!("{err}");
    }
    prog.attach("lo", aya::programs::tc::TcAttachType::Egress)
        .unwrap();

    let link_info = match get_link_info() {
        Some(info) => info,
        None => return,
    };

    assert_matches!(link_info.link_type(), Ok(link_type) => kernel_assert_eq!(
        LinkType::Tcx,
        link_type,
        KernelVersion::new(5, 8, 0),
    ));
    kernel_assert!(link_info.id() > 0, KernelVersion::new(5, 8, 0));
    assert_matches!(prog.info(), Ok(prog_info) => kernel_assert_eq!(
        prog_info.id(),
        link_info.program_id(),
        KernelVersion::new(5, 8, 0),
    ));
    assert_matches!(link_info.metadata(), Ok(metadata) => {
        kernel_assert!(
            matches!(metadata, LinkMetadata::Tcx { .. }),
            KernelVersion::new(6, 6, 0),
        );
        if let LinkMetadata::Tcx { interface_index, interface_name, attach_type } = metadata {
            let ifname = CString::new("lo").unwrap();
            let expected_ifindex = unsafe { libc::if_nametoindex(ifname.as_ptr()) };

            kernel_assert_eq!(expected_ifindex, interface_index, KernelVersion::new(6, 6, 0));
            kernel_assert_eq!(Some("lo"), interface_name.as_deref(), KernelVersion::new(6, 6, 0));
            assert_matches!(attach_type, Ok(attach_type) => kernel_assert_eq!(
                AttachType::TcxEgress,
                attach_type,
                KernelVersion::new(6, 6, 0),
            ));
        }
    });
}

/// Whether sysctl parameter is enabled in the `/proc` file.
fn is_sysctl_enabled(path: &str) -> bool {
    match fs::read_to_string(path) {
        Ok(contents) => contents.chars().next().is_some_and(|c| c == '1'),
        Err(_) => false,
    }
}

/// Enable sysctl parameter through procfs.
fn enable_sysctl_param(path: &str) -> bool {
    fs::write(path, b"1").is_ok()
}

/// Disable sysctl parameter through procfs.
fn disable_sysctl_param(path: &str) -> bool {
    fs::write(path, b"0").is_ok()
}

/// Return link info if `loaded_links()` is available, `None` if not available, or panic if link
/// error occurs.
fn get_link_info() -> Option<LinkInfo> {
    // There may be a link from `hid_tail_call` program, which is why we get last link.
    let link = loaded_links().last().unwrap();
    match link {
        Ok(info) => Some(info),
        Err(err) => {
            if is_link_einval(&err) {
                eprintln!(
                    "ignoring test completely as `loaded_links()` is not available on the host"
                );
                return None;
            }
            panic!("{err}");
        }
    }
}
