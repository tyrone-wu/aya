//! Metadata information about an eBPF link.

use std::{
    os::fd::{AsFd as _, BorrowedFd},
    str,
};

use aya_obj::generated::{
    bpf_attach_type, bpf_cgroup_iter_order, bpf_link_info, bpf_link_type, bpf_perf_event_type,
    nf_inet_hooks, perf_hw_cache_id, perf_hw_cache_op_id, perf_hw_cache_op_result_id, perf_hw_id,
    perf_sw_ids, perf_type_id, BPF_F_KPROBE_MULTI_RETURN, BPF_F_UPROBE_MULTI_RETURN, NFPROTO_IPV4,
    NFPROTO_IPV6,
};

#[allow(unused_imports)] // Used in rustdoc linking
use crate::programs::ProgramType;
use crate::{
    programs::{
        links::{FdLink, LinkError},
        perf_event::PerfEventConfig,
    },
    sys::{bpf_link_get_fd_by_id, bpf_link_get_info_by_fd, iter_link_ids},
    util::bytes_of_bpf_name,
};

/// Provides metadata information about an attached eBPF link.
///
/// Introduced in kernel v5.8.
#[doc(alias = "bpf_link_info")]
pub struct LinkInfo(bpf_link_info);

impl LinkInfo {
    pub(crate) fn from_fd(fd: BorrowedFd<'_>) -> Result<Self, LinkError> {
        let info = bpf_link_get_info_by_fd(fd.as_fd(), |_| {})?;
        Ok(Self(info))
    }

    /// Loads link info from a link ID.
    ///
    /// Uses kernel v5.8 features.
    pub fn from_id(id: u32) -> Result<Self, LinkError> {
        bpf_link_get_fd_by_id(id)
            .map_err(LinkError::from)
            .and_then(|fd| Self::from_fd(fd.as_fd()))
    }

    /// The link type.
    ///
    /// Introduced in kernel v5.8.
    pub fn link_type(&self) -> Result<LinkType, LinkError> {
        bpf_link_type::try_from(self.0.type_)
            .unwrap_or(bpf_link_type::__MAX_BPF_LINK_TYPE)
            .try_into()
    }

    /// The unique ID of the link.
    ///
    /// Introduced in kernel v5.8.
    pub fn id(&self) -> u32 {
        self.0.id
    }

    /// The ID of the program that is using this link.
    ///
    /// This field is unused in [`LinkType::StructOps`].
    ///
    /// Introduced in kernel v5.8.
    pub fn program_id(&self) -> u32 {
        self.0.prog_id
    }

    /// Metadata on the specific link.
    ///
    /// Availability of the metadata may vary depending on kernel version.
    pub fn metadata(&self) -> Result<LinkMetadata, LinkError> {
        match self.link_type()? {
            LinkType::Unspecified => Err(LinkError::InvalidLink),
            LinkType::RawTracePoint => {
                // SAFETY: union access
                let raw_tp = unsafe { &self.0.__bindgen_anon_1.raw_tracepoint };
                let mut bytes = vec![0u8; raw_tp.tp_name_len as usize];
                bpf_link_get_info_by_fd(self.fd()?.as_fd(), |info: &mut bpf_link_info| {
                    info.__bindgen_anon_1.raw_tracepoint.tp_name = bytes.as_mut_ptr() as _;
                    info.__bindgen_anon_1.raw_tracepoint.tp_name_len = raw_tp.tp_name_len;
                })?;
                bytes.pop(); // Remove null terminator
                let name = String::from_utf8(bytes).ok();

                Ok(LinkMetadata::RawTracePoint { name })
            }
            LinkType::Tracing => {
                // SAFETY: union access
                let tracing = unsafe { &self.0.__bindgen_anon_1.tracing };
                let attach_type = if tracing.attach_type != 0 {
                    AttachType::try_from(tracing.attach_type).map(Some)
                } else {
                    Ok(None)
                };
                let target_obj_id = (tracing.target_obj_id > 0).then_some(tracing.target_obj_id);
                let target_btf_id = (tracing.target_btf_id > 0).then_some(tracing.target_btf_id);

                Ok(LinkMetadata::Tracing {
                    attach_type,
                    target_obj_id,
                    target_btf_id,
                })
            }
            LinkType::Cgroup => {
                // SAFETY: union access
                let cgroup = unsafe { &self.0.__bindgen_anon_1.cgroup };
                let attach_type = AttachType::try_from(cgroup.attach_type);

                Ok(LinkMetadata::Cgroup {
                    id: cgroup.cgroup_id,
                    attach_type,
                })
            }
            LinkType::Iter => {
                // SAFETY: union access
                let iter = unsafe { &self.0.__bindgen_anon_1.iter };
                if iter.target_name_len == 0 {
                    return Ok(LinkMetadata::NotAvailable);
                }

                let mut bytes = vec![0u8; iter.target_name_len as usize];
                bpf_link_get_info_by_fd(self.fd()?.as_fd(), |info: &mut bpf_link_info| {
                    info.__bindgen_anon_1.iter.target_name = bytes.as_mut_ptr() as _;
                    info.__bindgen_anon_1.iter.target_name_len = iter.target_name_len;
                })?;
                bytes.pop(); // Remove null terminator
                let target = String::from_utf8(bytes).unwrap_or_default();

                Ok(match target.as_str() {
                    "bpf_map_elem" | "bpf_sk_storage_map" => {
                        // SAFETY: union access
                        let map = unsafe { &iter.__bindgen_anon_1.map };
                        LinkMetadata::IterMapElement {
                            bpf_iter: target,
                            map_id: map.map_id,
                        }
                    }
                    "cgroup" => {
                        // SAFETY: union access
                        let cgroup = unsafe { &iter.__bindgen_anon_2.cgroup };
                        let order = bpf_cgroup_iter_order::try_from(cgroup.order)
                            .unwrap_or(bpf_cgroup_iter_order::BPF_CGROUP_ITER_ORDER_UNSPEC)
                            .try_into();
                        LinkMetadata::IterCgroup {
                            cgroup_id: cgroup.cgroup_id,
                            order,
                        }
                    }
                    "task" | "task_file" | "task_vma" => {
                        // SAFETY: union access
                        let task = unsafe { &iter.__bindgen_anon_2.task };
                        LinkMetadata::IterTask {
                            bpf_iter: target,
                            tid: task.tid,
                            pid: task.pid,
                        }
                    }
                    _ => LinkMetadata::Iter {
                        bpf_iter: (!target.is_empty()).then_some(target),
                    },
                })
            }
            LinkType::NetNs => {
                // SAFETY: union access
                let netns = unsafe { &self.0.__bindgen_anon_1.netns };
                let attach_type = AttachType::try_from(netns.attach_type);

                Ok(LinkMetadata::NetNs {
                    net_namespace_inode: netns.netns_ino,
                    attach_type,
                })
            }
            LinkType::Xdp => {
                // SAFETY: union access
                let xdp = unsafe { &self.0.__bindgen_anon_1.xdp };
                if xdp.ifindex == 0 {
                    return Ok(LinkMetadata::NotAvailable);
                }

                let mut bytes = [0_i8; libc::IFNAMSIZ];
                // SAFETY: libc wrapper
                unsafe { libc::if_indextoname(xdp.ifindex, bytes.as_mut_ptr()) };
                let interface_name = str::from_utf8(bytes_of_bpf_name(&bytes))
                    .map(ToOwned::to_owned)
                    .ok();

                Ok(LinkMetadata::Xdp {
                    interface_index: xdp.ifindex,
                    interface_name,
                })
            }
            LinkType::StructOps => {
                // SAFETY: union access
                let struct_ops = unsafe { &self.0.__bindgen_anon_1.struct_ops };
                if struct_ops.map_id == 0 {
                    return Ok(LinkMetadata::NotAvailable);
                }

                Ok(LinkMetadata::StructOps {
                    map_id: struct_ops.map_id,
                })
            }
            LinkType::Netfilter => {
                // SAFETY: union access
                let netfilter = unsafe { &self.0.__bindgen_anon_1.netfilter };
                if netfilter.pf == 0 {
                    return Ok(LinkMetadata::NotAvailable);
                }

                let protocol_family = ProtocolFamily::try_from(netfilter.pf);
                let hook = nf_inet_hooks::try_from(netfilter.hooknum)
                    .unwrap_or(nf_inet_hooks::NF_INET_NUMHOOKS)
                    .try_into();
                // Kernel bug: The `netfilter.flags` field is never populated (remains 0).
                // let defrag = (netfilter.flags & BPF_F_NETFILTER_IP_DEFRAG) != 0;

                Ok(LinkMetadata::Netfilter {
                    protocol_family,
                    hook,
                    priority: netfilter.priority,
                    // defrag,
                })
            }
            LinkType::KProbeMulti => {
                // SAFETY: union access
                let kprobe_multi = unsafe { &self.0.__bindgen_anon_1.kprobe_multi };
                if kprobe_multi.count == 0 {
                    return Ok(LinkMetadata::NotAvailable);
                }

                let count = kprobe_multi.count as usize;
                let mut addrs = vec![0u64; count];
                let mut cookies = vec![0u64; count];
                bpf_link_get_info_by_fd(self.fd()?.as_fd(), |info: &mut bpf_link_info| {
                    info.__bindgen_anon_1.kprobe_multi.addrs = addrs.as_mut_ptr() as _;
                    info.__bindgen_anon_1.kprobe_multi.cookies = cookies.as_mut_ptr() as _;
                    info.__bindgen_anon_1.kprobe_multi.count = kprobe_multi.count;
                })?;
                let attach_data = addrs.into_iter().zip(cookies).collect();
                let return_probe = (kprobe_multi.flags & BPF_F_KPROBE_MULTI_RETURN) != 0;

                Ok(LinkMetadata::KProbeMulti {
                    attach_data,
                    return_probe,
                    misses: kprobe_multi.missed,
                })
            }
            LinkType::UProbeMulti => {
                // SAFETY: union access
                let uprobe_multi = unsafe { &self.0.__bindgen_anon_1.uprobe_multi };
                if uprobe_multi.count == 0 {
                    return Ok(LinkMetadata::NotAvailable);
                }

                // Kernel bug: The `path_size` field is only populated on the second/returned
                // after filling `path` & `path_size`.
                let mut path = [0_u8; libc::PATH_MAX as usize];
                let count = uprobe_multi.count as usize;
                let mut offsets = vec![0u64; count];
                let mut ref_ctr_offsets = vec![0u64; count];
                let mut cookies = vec![0u64; count];
                let ret_info =
                    bpf_link_get_info_by_fd(self.fd()?.as_fd(), |info: &mut bpf_link_info| {
                        // SAFETY: union access
                        let uprobe_multi_attr = unsafe { &mut info.__bindgen_anon_1.uprobe_multi };

                        uprobe_multi_attr.path = path.as_mut_ptr() as _;
                        uprobe_multi_attr.path_size = libc::PATH_MAX as u32;

                        uprobe_multi_attr.offsets = offsets.as_mut_ptr() as _;
                        uprobe_multi_attr.ref_ctr_offsets = ref_ctr_offsets.as_mut_ptr() as _;
                        uprobe_multi_attr.cookies = cookies.as_mut_ptr() as _;
                        uprobe_multi_attr.count = uprobe_multi.count;
                    })?;
                // Actual path size on return info, without null terminator.
                let path_size = unsafe { &ret_info.__bindgen_anon_1.uprobe_multi }
                    .path_size
                    .saturating_sub(1) as usize;
                let file_path = str::from_utf8(&path[..path_size])
                    .map(ToOwned::to_owned)
                    .ok();
                let attach_data = offsets
                    .into_iter()
                    .zip(ref_ctr_offsets)
                    .zip(cookies)
                    .map(|((o, r), c)| (o, r, c))
                    .collect();
                let return_probe = (uprobe_multi.flags & BPF_F_UPROBE_MULTI_RETURN) != 0;

                Ok(LinkMetadata::UProbeMulti {
                    file_path,
                    attach_data,
                    return_probe,
                    pid: uprobe_multi.pid,
                })
            }
            LinkType::PerfEvent => {
                use bpf_perf_event_type::*;

                // SAFETY: union access
                let perf_event = unsafe { &self.0.__bindgen_anon_1.perf_event };
                let prog_type = bpf_perf_event_type::try_from(perf_event.type_)
                    .map_err(|_| LinkError::InvalidLink)?;

                match prog_type {
                    BPF_PERF_EVENT_UNSPEC => return Ok(LinkMetadata::NotAvailable),
                    BPF_PERF_EVENT_EVENT => {
                        // SAFETY: union access
                        let perf_event = unsafe { &perf_event.__bindgen_anon_1.event };
                        let event = match perf_type_id::try_from(perf_event.type_)
                            .unwrap_or(perf_type_id::PERF_TYPE_MAX)
                        {
                            perf_type_id::PERF_TYPE_HARDWARE => {
                                let config = perf_hw_id::try_from(perf_event.config)
                                    .unwrap_or(perf_hw_id::PERF_COUNT_HW_MAX)
                                    .try_into()?;
                                PerfEventConfig::Hardware(config)
                            }
                            perf_type_id::PERF_TYPE_SOFTWARE => {
                                let config = perf_sw_ids::try_from(perf_event.config)
                                    .unwrap_or(perf_sw_ids::PERF_COUNT_SW_MAX)
                                    .try_into()?;
                                PerfEventConfig::Software(config)
                            }
                            perf_type_id::PERF_TYPE_TRACEPOINT => PerfEventConfig::TracePoint {
                                event_id: perf_event.config,
                            },
                            perf_type_id::PERF_TYPE_HW_CACHE => {
                                let event = perf_hw_cache_id::try_from(perf_event.config & 0xFF)
                                    .unwrap_or(perf_hw_cache_id::PERF_COUNT_HW_CACHE_MAX)
                                    .try_into()?;
                                let operation = perf_hw_cache_op_id::try_from(
                                    (perf_event.config & 0xFF00) >> 8,
                                )
                                .unwrap_or(perf_hw_cache_op_id::PERF_COUNT_HW_CACHE_OP_MAX)
                                .try_into()?;
                                let result = perf_hw_cache_op_result_id::try_from(
                                    (perf_event.config & 0xFF0000) >> 16,
                                )
                                .unwrap_or(
                                    perf_hw_cache_op_result_id::PERF_COUNT_HW_CACHE_RESULT_MAX,
                                )
                                .try_into()?;
                                PerfEventConfig::HwCache {
                                    event,
                                    operation,
                                    result,
                                }
                            }
                            perf_type_id::PERF_TYPE_RAW => PerfEventConfig::Raw {
                                event_id: perf_event.config,
                            },
                            perf_type_id::PERF_TYPE_BREAKPOINT => PerfEventConfig::Breakpoint,
                            perf_type_id::PERF_TYPE_MAX => {
                                // If `.type_` value goes beyond the provided `perf_type_id`
                                // values, this meaning it is a dynamic PMU.
                                PerfEventConfig::Pmu {
                                    pmu_type: perf_event.type_,
                                    config: perf_event.config,
                                }
                            }
                        };

                        return Ok(LinkMetadata::PerfEvent {
                            event,
                            cookie: perf_event.cookie,
                        });
                    }
                    _ => {}
                }

                let fd = self.fd()?;
                // Kernel bug: https://lore.kernel.org/bpf/ZvqLanKfaO9dLlf4@krava/
                // The `name_len` field is not populated on the kernel-side.
                let mut bytes = [0_u8; libc::PATH_MAX as usize];
                match prog_type {
                    BPF_PERF_EVENT_UPROBE | BPF_PERF_EVENT_URETPROBE => {
                        bpf_link_get_info_by_fd(fd.as_fd(), |info: &mut bpf_link_info| {
                            // SAFETY: union access
                            let uprobe = unsafe {
                                &mut info.__bindgen_anon_1.perf_event.__bindgen_anon_1.uprobe
                            };
                            uprobe.file_name = bytes.as_mut_ptr() as _;
                            uprobe.name_len = libc::PATH_MAX as u32;
                        })?;

                        // SAFETY: union access
                        let uprobe = unsafe { &perf_event.__bindgen_anon_1.uprobe };
                        let return_probe = prog_type == BPF_PERF_EVENT_URETPROBE;
                        let file_path = bytes
                            .iter()
                            .position(|b| b == &0)
                            .and_then(|i| str::from_utf8(&bytes[..i]).map(ToOwned::to_owned).ok());

                        Ok(LinkMetadata::UProbe {
                            return_probe,
                            file_path,
                            symbol_offset: uprobe.offset,
                            cookie: uprobe.cookie,
                        })
                    }
                    BPF_PERF_EVENT_KPROBE | BPF_PERF_EVENT_KRETPROBE => {
                        bpf_link_get_info_by_fd(fd.as_fd(), |info: &mut bpf_link_info| {
                            // SAFETY: union access
                            let kprobe = unsafe {
                                &mut info.__bindgen_anon_1.perf_event.__bindgen_anon_1.kprobe
                            };
                            kprobe.func_name = bytes.as_mut_ptr() as _;
                            kprobe.name_len = libc::PATH_MAX as u32;
                        })?;

                        // SAFETY: union access
                        let kprobe = unsafe { &perf_event.__bindgen_anon_1.kprobe };
                        let return_probe = prog_type == BPF_PERF_EVENT_KRETPROBE;
                        let function_name = bytes
                            .iter()
                            .position(|b| b == &0)
                            .and_then(|i| str::from_utf8(&bytes[..i]).map(ToOwned::to_owned).ok());

                        Ok(LinkMetadata::KProbe {
                            return_probe,
                            function_name,
                            symbol_offset: kprobe.offset,
                            address: kprobe.addr,
                            misses: kprobe.missed,
                            cookie: kprobe.cookie,
                        })
                    }
                    BPF_PERF_EVENT_TRACEPOINT => {
                        bpf_link_get_info_by_fd(fd.as_fd(), |info: &mut bpf_link_info| {
                            // SAFETY: union access
                            let tracepoint = unsafe {
                                &mut info.__bindgen_anon_1.perf_event.__bindgen_anon_1.tracepoint
                            };
                            tracepoint.tp_name = bytes.as_mut_ptr() as _;
                            tracepoint.name_len = libc::PATH_MAX as u32;
                        })?;

                        // SAFETY: union access
                        let tp = unsafe { &perf_event.__bindgen_anon_1.tracepoint };
                        let tracepoint_name = bytes
                            .iter()
                            .position(|b| b == &0)
                            .and_then(|i| str::from_utf8(&bytes[..i]).map(ToOwned::to_owned).ok());

                        Ok(LinkMetadata::TracePoint {
                            tracepoint_name,
                            cookie: tp.cookie,
                        })
                    }
                    _ => Err(LinkError::InvalidLink),
                }
            }
            LinkType::Tcx => {
                // SAFETY: union access
                let tcx = unsafe { &self.0.__bindgen_anon_1.tcx };
                if tcx.ifindex == 0 {
                    return Ok(LinkMetadata::NotAvailable);
                }

                let mut bytes = [0_i8; libc::IFNAMSIZ];
                // SAFETY: libc wrapper
                unsafe { libc::if_indextoname(tcx.ifindex, bytes.as_mut_ptr()) };
                let interface_name = str::from_utf8(bytes_of_bpf_name(&bytes))
                    .map(ToOwned::to_owned)
                    .ok();
                let attach_type = AttachType::try_from(tcx.attach_type);

                Ok(LinkMetadata::Tcx {
                    interface_index: tcx.ifindex,
                    interface_name,
                    attach_type,
                })
            }
            LinkType::Netkit => {
                // SAFETY: union access
                let netkit = unsafe { &self.0.__bindgen_anon_1.netkit };

                let mut bytes = [0_i8; libc::IFNAMSIZ];
                // SAFETY: libc wrapper
                unsafe { libc::if_indextoname(netkit.ifindex, bytes.as_mut_ptr()) };
                let interface_name = str::from_utf8(bytes_of_bpf_name(&bytes))
                    .map(ToOwned::to_owned)
                    .ok();
                let attach_type = AttachType::try_from(netkit.attach_type);

                Ok(LinkMetadata::Netkit {
                    interface_index: netkit.ifindex,
                    interface_name,
                    attach_type,
                })
            }
        }
    }

    fn fd(&self) -> Result<FdLink, LinkError> {
        let Self(info) = self;
        let fd = bpf_link_get_fd_by_id(info.id)?;
        Ok(FdLink { fd })
    }
}

/// Metadata on the specific link.
#[derive(Debug)]
pub enum LinkMetadata {
    /// Metadata not available on the host.
    NotAvailable,

    /// [`LinkType::RawTracePoint`] metadata.
    ///
    /// Introduced in kernel v5.8.
    RawTracePoint {
        /// Name of the event that the link is hooked to.
        ///
        /// `None` is returned if the name is not valid unicode.
        name: Option<String>,
    },

    /// [`LinkType::Tracing`] metadata.
    ///
    /// Introduced in kernel v5.8.
    /// Availability of fields may vary depending on kernel version.
    Tracing {
        /// The [`AttachType`] of the link.
        ///
        /// `None` is returned if this field is unused (e.g. [`ProgramType::Extension`]).
        ///
        /// Introduced in kernel v5.8.
        attach_type: Result<Option<AttachType>, LinkError>,
        /// The meaning of this field depends on program type using this link:
        /// - [`ProgramType::Extension`]: The ID of the program that the extension program is extending.
        /// - Otherwise: The BTF **object** ID.
        ///
        /// `None` is returned if the field is not available.
        ///
        /// Introduced in kernel v5.13.
        target_obj_id: Option<u32>,
        /// The BTF **type** ID inside the BTF object.
        ///
        /// `None` is returned if the field is not available, or unused.
        ///
        /// Introduced in kernel v5.13.
        target_btf_id: Option<u32>,
    },

    /// [`LinkType::Cgroup`] metadata.
    ///
    /// Introduced in kernel v5.8.
    Cgroup {
        /// The ID of the cGroup that the link is attached to.
        id: u64,
        /// The [`AttachType`] of the link.
        attach_type: Result<AttachType, LinkError>,
    },

    /// [`LinkType::Iter`] metadata.
    ///
    /// Introduced in kernel v5.10.
    Iter {
        /// Name of the target `bpf_iter__`.
        ///
        /// `None` is returned if the name was not valid unicode.
        bpf_iter: Option<String>,
    },
    /// [`LinkType::Iter`] metadata for iterating elements of a map.
    ///
    /// Introduced in kernel v5.10.
    IterMapElement {
        /// Name of the target `bpf_iter__` (`bpf_map_elem`, `bpf_sk_storage_map`).
        bpf_iter: String,
        /// The ID of the map's elements to iterate.
        map_id: u32,
    },
    /// [`LinkType::Iter`] metadata for iterating cgroups.
    ///
    /// Introduced in kernel v6.1.
    IterCgroup {
        /// The ID of the cgroup of where the iterator starts.
        ///
        /// An ID of `0` indicates that the iterator starts from the default cgroup v2 root.
        /// If iterating through cgroup v1 hierarchy instead, then the ID should not be `0`.
        cgroup_id: u64,
        /// How the iterator traverses the cgroups.
        order: Result<CgroupIterOrder, LinkError>,
    },
    /// [`LinkType::Iter`] metadata for iterating tasks.
    ///
    /// Introduced in kernel v6.1.
    IterTask {
        /// Name of the target `bpf_iter__` (`task`, `task_file`, `task_vma`).
        bpf_iter: String,
        /// The ID of the task/thread to visit.
        ///
        /// An ID of `0` indicates that the iterator iterates through every task/thread of a
        /// process.
        tid: u32,
        /// The ID of the process/task group to visit.
        ///
        /// An ID of `0` indicates that the iterator iterates through every process.
        pid: u32,
    },

    /// [`LinkType::NetNs`] metadata.
    ///
    /// Introduced in kernel v5.8.
    NetNs {
        /// The inode number of the network namespace that the link is attached to.
        net_namespace_inode: u32,
        /// The [`AttachType`] of the link.
        attach_type: Result<AttachType, LinkError>,
    },

    /// [`LinkType::Xdp`] metadata.
    ///
    /// Introduced in kernel v5.9.
    Xdp {
        /// The interface index that the link is attached to.
        interface_index: u32,
        /// The name of the network interface.
        ///
        /// `None` is returned if the name was not valid unicode.
        interface_name: Option<String>,
    },

    /// [`LinkType::StructOps`] metadata.
    ///
    /// Introduced in kernel v6.4.
    StructOps {
        /// The ID of the [`MapType::StructOps`](crate::maps::MapType::StructOps) map.
        map_id: u32,
    },

    /// [`LinkType::Netfilter`] metadata.
    ///
    /// Introduced in kernel v6.4.
    Netfilter {
        /// The protocol family of the packets to intercept.
        protocol_family: Result<ProtocolFamily, LinkError>,
        /// The netfilter hook location that the link is attached to.
        hook: Result<InetHook, LinkError>,
        /// The priority of the netfilter function.
        priority: i32,
        // /// Whether IP packet defragmentation is enabled.
        // ///
        // /// Note this field is bugged in that it is never populated, so this is always `false`.
        // defrag: bool,
    },

    /// [`LinkType::KProbeMulti`] metadata.
    ///
    /// Introduced in kernel v6.6.
    /// Availability of fields may vary depending on kernel version.
    KProbeMulti {
        /// The list of (`address`, `cookie`) pairs attached to this link.
        ///
        /// The first element is the memory address of the kernel symbol.
        /// Introduced in kernel v6.6.
        ///
        /// The second element is the cookie passed when attaching the program.
        /// Introduced in kernel v6.9.
        attach_data: Vec<(u64, u64)>,
        /// Whether the `KProbe` program is a return probe.
        ///
        /// Introduced in kernel v6.6.
        return_probe: bool,
        /// The number of times the program missed execute when the probe point was triggered.
        ///
        /// Introduced in kernel v6.7.
        misses: u64,
    },

    /// [`LinkType::UProbeMulti`] metadata.
    ///
    /// Introduced in kernel v6.8.
    UProbeMulti {
        /// The absolute file path that the link is attached to.
        ///
        /// `None` is returned if the name was not valid unicode.
        file_path: Option<String>,
        /// The list of (`offset`, `ref_ctr_offset`, `cookie`) tuples attached to this link.
        ///
        /// The first element is the offset into the function/symbol in the target file.
        ///
        /// The second element is the reference counter offsets.
        ///
        /// The third element is the cookie passed when attaching the program.
        attach_data: Vec<(u64, u64, u64)>,
        /// Whether the `UProbe` program is a return probe.
        return_probe: bool,
        /// The process ID that the `UProbe` is attached to.
        pid: u32,
    },

    /// [`LinkType::PerfEvent`] metadata for `UProbe` programs.
    ///
    /// Introduced in kernel v6.6.
    /// Availability of fields may vary depending on kernel version.
    UProbe {
        /// Whether the `UProbe` program is a return probe.
        ///
        /// Introduced in kernel v6.6.
        return_probe: bool,
        /// The absolute file path that the link is attached to.
        ///
        /// `None` is returned if the name was not valid unicode.
        ///
        /// Introduced in kernel v6.6.
        file_path: Option<String>,
        /// The offset into the function/symbol in the target file.
        ///
        /// Introduced in kernel v6.6.
        symbol_offset: u32,
        /// The cookie passed when attaching the program.
        ///
        /// Introduced in kernel v6.9.
        cookie: u64,
    },
    /// [`LinkType::PerfEvent`] metadata for `KProbe` programs.
    ///
    /// Introduced in kernel v6.6.
    /// Availability of fields may vary depending on kernel version.
    KProbe {
        /// Whether the `KProbe` program is a return probe.
        ///
        /// Introduced in kernel v6.6.
        return_probe: bool,
        /// The name of the function that the link is attached to.
        ///
        /// `None` is returned if the name was not valid unicode.
        ///
        /// Introduced in kernel v6.6.
        function_name: Option<String>,
        /// The offset into the function/symbol in the target function.
        ///
        /// Introduced in kernel v6.6.
        symbol_offset: u32,
        /// The memory address of the kernel symbol, which maps to the funciton name.
        ///
        /// Introduced in kernel v6.6.
        address: u64,
        /// The number of times the program missed execute when the probe point was triggered.
        ///
        /// Introduced in kernel v6.7.
        misses: u64,
        /// The cookie passed when attaching the program.
        ///
        /// Introduced in kernel v6.9.
        cookie: u64,
    },
    /// [`LinkType::PerfEvent`] metadata for `Tracepoint` programs.
    ///
    /// Introduced in kernel v6.6.
    /// Availability of fields may vary depending on kernel version.
    TracePoint {
        /// The name of the tracepoint that the link link is attached to.
        ///
        /// `None` is returned if the name was not valid unicode.
        ///
        /// Introduced in kernel v6.6.
        tracepoint_name: Option<String>,
        /// The cookie passed when attaching the program.
        ///
        /// Introduced in kernel v6.9.
        cookie: u64,
    },
    /// [`LinkType::PerfEvent`] metadata for `PerfEvent` programs.
    ///
    /// Introduced in kernel v6.6.
    /// Availability of fields may vary depending on kernel version.
    PerfEvent {
        /// The perf event type and configuration the program.
        ///
        /// Introduced in kernel v6.6.
        event: PerfEventConfig,
        /// The cookie passed when attaching the program.
        ///
        /// Introduced in kernel v6.9.
        cookie: u64,
    },

    /// [`LinkType::Tcx`] metadata.
    ///
    /// Introduced in kernel v6.6.
    Tcx {
        /// The interface index that the link is attached to.
        interface_index: u32,
        /// The name of the network interface.
        ///
        /// `None` is returned if the name was not valid unicode.
        interface_name: Option<String>,
        /// The [`AttachType`] of the link.
        attach_type: Result<AttachType, LinkError>,
    },

    /// [`LinkType::Netkit`] metadata.
    ///
    /// Introduced in kernel v6.7.
    Netkit {
        /// The interface index that the link is attached to.
        interface_index: u32,
        /// The name of the network interface.
        ///
        /// `None` is returned if the name was not valid unicode.
        interface_name: Option<String>,
        /// The [`AttachType`] of the link.
        attach_type: Result<AttachType, LinkError>,
    },
}

/// Returns an iterator of [`LinkInfo`] over all eBPF links on the host.
///
/// Uses kernel v5.8 features.
///
/// # Example
/// ```
/// # use aya::links::loaded_links;
/// #
/// for link in loaded_links() {
///     match link {
///         Ok(info) => println!("{:?}", info.link_type()),
///         Err(err) => println!("Error iterating links: {:?}", err),
///     }
/// }
/// ```
///
/// # Errors
///
/// Returns [`LinkError::SyscallError`] if any of the syscalls required to either get
/// next link ID, get the link fd, or the [`LinkInfo`] fail.
///
/// In cases where iteration can't be performed, for example the caller does not have the necessary
/// privileges, a single item will be yielded containing the error that occurred.
pub fn loaded_links() -> impl Iterator<Item = Result<LinkInfo, LinkError>> {
    iter_link_ids()
        .map(|id| {
            let id = id?;
            bpf_link_get_fd_by_id(id)
        })
        .map(|fd| {
            let fd = fd?;
            bpf_link_get_info_by_fd(fd.as_fd(), |_| {})
        })
        .map(|result| result.map(LinkInfo).map_err(Into::into))
}

/// The type of eBPF link.
#[non_exhaustive]
#[doc(alias = "bpf_link_type")]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum LinkType {
    /// An unspecified link type.
    Unspecified = bpf_link_type::BPF_LINK_TYPE_UNSPEC as isize,
    /// Link type used in:
    /// - [`ProgramType::RawTracePoint`]
    /// - [`ProgramType::RawTracePointWritable`]
    /// - [`ProgramType::Tracing`] with attach type:
    ///   - [`AttachType::TraceRawTp`]
    ///
    /// Introduced in kernel v5.8.
    #[doc(alias = "BPF_LINK_TYPE_RAW_TRACEPOINT")]
    RawTracePoint = bpf_link_type::BPF_LINK_TYPE_RAW_TRACEPOINT as isize,
    /// Link type used in:
    /// - [`ProgramType::Tracing`] with attach type:
    ///   - [`AttachType::TraceFEntry`]
    ///   - [`AttachType::TraceFExit`]
    ///   - [`AttachType::ModifyReturn`]
    /// - [`ProgramType::Extension`]
    /// - [`ProgramType::Lsm`] with attach type:
    ///   - [`AttachType::LsmMac`]
    ///
    /// Introduced in kernel v5.8.
    #[doc(alias = "BPF_LINK_TYPE_TRACING")]
    Tracing = bpf_link_type::BPF_LINK_TYPE_TRACING as isize,
    /// Link type used in:
    /// - [`ProgramType::CgroupSkb`]
    /// - [`ProgramType::CgroupSock`]
    /// - [`ProgramType::SockOps`]
    /// - [`ProgramType::CgroupDevice`]
    /// - [`ProgramType::CgroupSockAddr`]
    /// - [`ProgramType::CgroupSysctl`]
    /// - [`ProgramType::CgroupSockopt`]
    /// - [`ProgramType::Tracing`] with attach type:
    ///   - [`AttachType::LsmCgroup`]
    ///
    /// Introduced in kernel v5.8.
    #[doc(alias = "BPF_LINK_TYPE_CGROUP")]
    Cgroup = bpf_link_type::BPF_LINK_TYPE_CGROUP as isize,
    /// Link type used in:
    /// - [`ProgramType::Tracing`] with attach type:
    ///   - [`AttachType::TraceIter`]
    ///
    /// Introduced in kernel v5.8.
    #[doc(alias = "BPF_LINK_TYPE_ITER")]
    Iter = bpf_link_type::BPF_LINK_TYPE_ITER as isize,
    /// Link type used in:
    /// - [`ProgramType::FlowDissector`]
    /// - [`ProgramType::SkLookup`]
    ///
    /// Introduced in kernel v5.8.
    #[doc(alias = "BPF_LINK_TYPE_NETNS")]
    NetNs = bpf_link_type::BPF_LINK_TYPE_NETNS as isize,
    /// Link type used in:
    /// - [`ProgramType::Xdp`]
    ///
    /// Introduced in kernel v5.9.
    #[doc(alias = "BPF_LINK_TYPE_XDP")]
    Xdp = bpf_link_type::BPF_LINK_TYPE_XDP as isize,
    /// Link type used in:
    /// - [`ProgramType::TracePoint`]
    /// - [`ProgramType::PerfEvent`]
    /// - [`ProgramType::KProbe`] with attach type:
    ///   - [`AttachType::PerfEvent`]
    ///
    /// Introduced in kernel v5.15.
    #[doc(alias = "BPF_LINK_TYPE_PERF_EVENT")]
    PerfEvent = bpf_link_type::BPF_LINK_TYPE_PERF_EVENT as isize,
    /// Link type used in:
    /// - [`ProgramType::KProbe`] with attach type:
    ///   - [`AttachType::TraceKProbeMulti`]
    ///
    /// Introduced in kernel v5.18.
    #[doc(alias = "BPF_LINK_TYPE_KPROBE_MULTI")]
    KProbeMulti = bpf_link_type::BPF_LINK_TYPE_KPROBE_MULTI as isize,
    /// Link type used in:
    /// - [`MapType::StructOps`](crate::maps::MapType::StructOps) with
    ///   [`AttachType::StructOps`].
    ///
    /// Introduced in kernel v5.19.
    #[doc(alias = "BPF_LINK_TYPE_STRUCT_OPS")]
    StructOps = bpf_link_type::BPF_LINK_TYPE_STRUCT_OPS as isize,
    /// Link type used in:
    /// - [`ProgramType::Netfilter`]
    ///
    /// Introduced in kernel v6.4.
    #[doc(alias = "BPF_LINK_TYPE_NETFILTER")]
    Netfilter = bpf_link_type::BPF_LINK_TYPE_NETFILTER as isize,
    /// Link type used in:
    /// - [`ProgramType::SchedClassifier`] with attach type:
    ///   - [`AttachType::TcxIngress`]
    ///   - [`AttachType::TcxEgress`]
    ///
    /// Introduced in kernel v6.6.
    #[doc(alias = "BPF_LINK_TYPE_TCX")]
    Tcx = bpf_link_type::BPF_LINK_TYPE_TCX as isize,
    /// Link type used in:
    /// - [`ProgramType::KProbe`] with attach type:
    ///   - [`AttachType::TraceUProbeMulti`]
    ///
    /// Introduced in kernel v6.6.
    #[doc(alias = "BPF_LINK_TYPE_UPROBE_MULTI")]
    UProbeMulti = bpf_link_type::BPF_LINK_TYPE_UPROBE_MULTI as isize,
    /// Link type used in:
    /// - [`ProgramType::SchedClassifier`] with attach type:
    ///   - [`AttachType::NetkitPrimary`]
    ///   - [`AttachType::NetkitPeer`]
    ///
    /// Introduced in kernel v6.7.
    #[doc(alias = "BPF_LINK_TYPE_NETKIT")]
    Netkit = bpf_link_type::BPF_LINK_TYPE_NETKIT as isize,
}

impl TryFrom<bpf_link_type> for LinkType {
    type Error = LinkError;

    fn try_from(link_type: bpf_link_type) -> Result<Self, Self::Error> {
        use bpf_link_type::*;
        Ok(match link_type {
            BPF_LINK_TYPE_UNSPEC => Self::Unspecified,
            BPF_LINK_TYPE_RAW_TRACEPOINT => Self::RawTracePoint,
            BPF_LINK_TYPE_TRACING => Self::Tracing,
            BPF_LINK_TYPE_CGROUP => Self::Cgroup,
            BPF_LINK_TYPE_ITER => Self::Iter,
            BPF_LINK_TYPE_NETNS => Self::NetNs,
            BPF_LINK_TYPE_XDP => Self::Xdp,
            BPF_LINK_TYPE_PERF_EVENT => Self::PerfEvent,
            BPF_LINK_TYPE_KPROBE_MULTI => Self::KProbeMulti,
            BPF_LINK_TYPE_STRUCT_OPS => Self::StructOps,
            BPF_LINK_TYPE_NETFILTER => Self::Netfilter,
            BPF_LINK_TYPE_TCX => Self::Tcx,
            BPF_LINK_TYPE_UPROBE_MULTI => Self::UProbeMulti,
            BPF_LINK_TYPE_NETKIT => Self::Netkit,
            __MAX_BPF_LINK_TYPE => return Err(LinkError::InvalidLink),
        })
    }
}

/// The type of attachment.
#[non_exhaustive]
#[doc(alias = "bpf_attach_type")]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum AttachType {
    /// Attach type used in [`ProgramType::CgroupSkb`] programs.
    ///
    /// Note that programs without an expected attach type (e.g. Extension, etc.) may display this
    /// attach type, as `0` maps to `BPF_CGROUP_INET_INGRESS`. This is not to be mistaken for the
    /// program actually having this attach type.
    ///
    /// Introduced in kernel v4.10.
    #[doc(alias = "BPF_CGROUP_INET_INGRESS")]
    CgroupInetIngress = bpf_attach_type::BPF_CGROUP_INET_INGRESS as isize,
    /// Attach type used in [`ProgramType::CgroupSkb`] programs.
    ///
    /// Introduced in kernel v4.10.
    #[doc(alias = "BPF_CGROUP_INET_EGRESS")]
    CgroupInetEgress = bpf_attach_type::BPF_CGROUP_INET_EGRESS as isize,
    /// Attach type used in [`ProgramType::CgroupSock`] programs.
    ///
    /// Introduced in kernel v4.10.
    #[doc(alias = "BPF_CGROUP_INET_SOCK_CREATE")]
    CgroupInetSockCreate = bpf_attach_type::BPF_CGROUP_INET_SOCK_CREATE as isize,
    /// Attach type used in [`ProgramType::SockOps`] programs.
    ///
    /// Introduced in kernel v4.13.
    #[doc(alias = "BPF_CGROUP_SOCK_OPS")]
    CgroupSockOps = bpf_attach_type::BPF_CGROUP_SOCK_OPS as isize,
    /// Attach type used in [`ProgramType::SkSkb`] programs.
    ///
    /// Introduced in kernel v4.14.
    #[doc(alias = "BPF_SK_SKB_STREAM_PARSER")]
    SkSkbStreamParser = bpf_attach_type::BPF_SK_SKB_STREAM_PARSER as isize,
    /// Attach type used in [`ProgramType::SkSkb`] programs.
    ///
    /// Introduced in kernel v4.14.
    #[doc(alias = "BPF_SK_SKB_STREAM_VERDICT")]
    SkSkbStreamVerdict = bpf_attach_type::BPF_SK_SKB_STREAM_VERDICT as isize,
    /// Attach type used in [`ProgramType::CgroupDevice`] programs.
    ///
    /// Introduced in kernel v4.15.
    #[doc(alias = "BPF_CGROUP_DEVICE")]
    CgroupDevice = bpf_attach_type::BPF_CGROUP_DEVICE as isize,
    /// Attach type used in [`ProgramType::SkMsg`] programs.
    ///
    /// Introduced in kernel v4.17.
    #[doc(alias = "BPF_SK_MSG_VERDICT")]
    SkMsgVerdict = bpf_attach_type::BPF_SK_MSG_VERDICT as isize,
    /// Attach type used in [`ProgramType::CgroupSockAddr`] programs.
    ///
    /// Introduced in kernel v4.17.
    #[doc(alias = "BPF_CGROUP_INET4_BIND")]
    CgroupInet4Bind = bpf_attach_type::BPF_CGROUP_INET4_BIND as isize,
    /// Attach type used in [`ProgramType::CgroupSockAddr`] programs.
    ///
    /// Introduced in kernel v4.17.
    #[doc(alias = "BPF_CGROUP_INET6_BIND")]
    CgroupInet6Bind = bpf_attach_type::BPF_CGROUP_INET6_BIND as isize,
    /// Attach type used in [`ProgramType::CgroupSockAddr`] programs.
    ///
    /// Introduced in kernel v4.17.
    #[doc(alias = "BPF_CGROUP_INET4_CONNECT")]
    CgroupInet4Connect = bpf_attach_type::BPF_CGROUP_INET4_CONNECT as isize,
    /// Attach type used in [`ProgramType::CgroupSockAddr`] programs.
    ///
    /// Introduced in kernel v4.17.
    #[doc(alias = "BPF_CGROUP_INET6_CONNECT")]
    CgroupInet6Connect = bpf_attach_type::BPF_CGROUP_INET6_CONNECT as isize,
    /// Attach type used in [`ProgramType::CgroupSock`] programs.
    ///
    /// Introduced in kernel v4.17.
    #[doc(alias = "BPF_CGROUP_INET4_POST_BIND")]
    CgroupInet4PostBind = bpf_attach_type::BPF_CGROUP_INET4_POST_BIND as isize,
    /// Attach type used in [`ProgramType::CgroupSock`] programs.
    ///
    /// Introduced in kernel v4.17.
    #[doc(alias = "BPF_CGROUP_INET6_POST_BIND")]
    CgroupInet6PostBind = bpf_attach_type::BPF_CGROUP_INET6_POST_BIND as isize,
    /// Attach type used in [`ProgramType::CgroupSockAddr`] programs.
    ///
    /// Introduced in kernel v4.18.
    #[doc(alias = "BPF_CGROUP_UDP4_SENDMSG")]
    CgroupUdp4Sendmsg = bpf_attach_type::BPF_CGROUP_UDP4_SENDMSG as isize,
    /// Attach type used in [`ProgramType::CgroupSockAddr`] programs.
    ///
    /// Introduced in kernel v4.18.
    #[doc(alias = "BPF_CGROUP_UDP6_SENDMSG")]
    CgroupUdp6Sendmsg = bpf_attach_type::BPF_CGROUP_UDP6_SENDMSG as isize,
    /// Attach type used in [`ProgramType::LircMode2`] programs.
    ///
    /// Introduced in kernel v4.18.
    #[doc(alias = "BPF_LIRC_MODE2")]
    LircMode2 = bpf_attach_type::BPF_LIRC_MODE2 as isize,
    /// Attach type used in [`ProgramType::FlowDissector`] programs.
    ///
    /// Introduced in kernel v4.20.
    #[doc(alias = "BPF_FLOW_DISSECTOR")]
    FlowDissector = bpf_attach_type::BPF_FLOW_DISSECTOR as isize,
    /// Attach type used in [`ProgramType::CgroupSysctl`] programs.
    ///
    /// Introduced in kernel v5.2.
    #[doc(alias = "BPF_CGROUP_SYSCTL")]
    CgroupSysctl = bpf_attach_type::BPF_CGROUP_SYSCTL as isize,
    /// Attach type used in [`ProgramType::CgroupSockAddr`] programs.
    ///
    /// Introduced in kernel v5.2.
    #[doc(alias = "BPF_CGROUP_UDP4_RECVMSG")]
    CgroupUdp4Recvmsg = bpf_attach_type::BPF_CGROUP_UDP4_RECVMSG as isize,
    /// Attach type used in [`ProgramType::CgroupSockAddr`] programs.
    ///
    /// Introduced in kernel v5.2.
    #[doc(alias = "BPF_CGROUP_UDP6_RECVMSG")]
    CgroupUdp6Recvmsg = bpf_attach_type::BPF_CGROUP_UDP6_RECVMSG as isize,
    /// Attach type used in [`ProgramType::CgroupSockopt`] programs.
    ///
    /// Introduced in kernel v5.3.
    #[doc(alias = "BPF_CGROUP_GETSOCKOPT")]
    CgroupGetsockopt = bpf_attach_type::BPF_CGROUP_GETSOCKOPT as isize,
    /// Attach type used in [`ProgramType::CgroupSockopt`] programs.
    ///
    /// Introduced in kernel v5.3.
    #[doc(alias = "BPF_CGROUP_SETSOCKOPT")]
    CgroupSetsockopt = bpf_attach_type::BPF_CGROUP_SETSOCKOPT as isize,
    /// Attach type used in [`ProgramType::Tracing`] programs.
    ///
    /// Introduced in kernel v5.5.
    #[doc(alias = "BPF_TRACE_RAW_TP")]
    TraceRawTp = bpf_attach_type::BPF_TRACE_RAW_TP as isize,
    /// Attach type used in [`ProgramType::Tracing`] programs.
    ///
    /// Introduced in kernel v5.5.
    #[doc(alias = "BPF_TRACE_FENTRY")]
    TraceFEntry = bpf_attach_type::BPF_TRACE_FENTRY as isize,
    /// Attach type used in [`ProgramType::Tracing`] programs.
    ///
    /// Introduced in kernel v5.5.
    #[doc(alias = "BPF_TRACE_FEXIT")]
    TraceFExit = bpf_attach_type::BPF_TRACE_FEXIT as isize,
    /// Attach type used in [`ProgramType::Tracing`] programs.
    ///
    /// Introduced in kernel v5.7.
    #[doc(alias = "BPF_MODIFY_RETURN")]
    ModifyReturn = bpf_attach_type::BPF_MODIFY_RETURN as isize,
    /// Attach type used in [`ProgramType::Lsm`] programs.
    ///
    /// Introduced in kernel v5.7.
    #[doc(alias = "BPF_LSM_MAC")]
    LsmMac = bpf_attach_type::BPF_LSM_MAC as isize,
    /// Attach type used in [`ProgramType::Tracing`] programs.
    ///
    /// Introduced in kernel v5.8.
    #[doc(alias = "BPF_TRACE_ITER")]
    TraceIter = bpf_attach_type::BPF_TRACE_ITER as isize,
    /// Attach type used in [`ProgramType::CgroupSockAddr`] programs.
    ///
    /// Introduced in kernel v5.8.
    #[doc(alias = "BPF_CGROUP_INET4_GETPEERNAME")]
    CgroupInet4Getpeername = bpf_attach_type::BPF_CGROUP_INET4_GETPEERNAME as isize,
    /// Attach type used in [`ProgramType::CgroupSockAddr`] programs.
    ///
    /// Introduced in kernel v5.8.
    #[doc(alias = "BPF_CGROUP_INET6_GETPEERNAME")]
    CgroupInet6Getpeername = bpf_attach_type::BPF_CGROUP_INET6_GETPEERNAME as isize,
    /// Attach type used in [`ProgramType::CgroupSockAddr`] programs.
    ///
    /// Introduced in kernel v5.8.
    #[doc(alias = "BPF_CGROUP_INET4_GETSOCKNAME")]
    CgroupInet4Getsockname = bpf_attach_type::BPF_CGROUP_INET4_GETSOCKNAME as isize,
    /// Attach type used in [`ProgramType::CgroupSockAddr`] programs.
    ///
    /// Introduced in kernel v5.8.
    #[doc(alias = "BPF_CGROUP_INET6_GETSOCKNAME")]
    CgroupInet6Getsockname = bpf_attach_type::BPF_CGROUP_INET6_GETSOCKNAME as isize,
    /// Attach type used in [`ProgramType::Xdp`] programs.
    ///
    /// Introduced in kernel v5.8.
    #[doc(alias = "BPF_XDP_DEVMAP")]
    XdpDevMap = bpf_attach_type::BPF_XDP_DEVMAP as isize,
    /// Attach type used in [`ProgramType::CgroupSock`] programs.
    ///
    /// Introduced in kernel v5.9.
    #[doc(alias = "BPF_CGROUP_INET_SOCK_RELEASE")]
    CgroupInetSockRelease = bpf_attach_type::BPF_CGROUP_INET_SOCK_RELEASE as isize,
    /// Attach type used in [`ProgramType::Xdp`] programs.
    ///
    /// Introduced in kernel v5.9.
    #[doc(alias = "BPF_XDP_CPUMAP")]
    XdpCpuMap = bpf_attach_type::BPF_XDP_CPUMAP as isize,
    /// Attach type used in [`ProgramType::SkLookup`] programs.
    ///
    /// Introduced in kernel v5.9.
    #[doc(alias = "BPF_SK_LOOKUP")]
    SkLookup = bpf_attach_type::BPF_SK_LOOKUP as isize,
    /// Attach type used in [`ProgramType::SkLookup`] programs.
    ///
    /// Introduced in kernel v5.9.
    #[doc(alias = "BPF_XDP")]
    Xdp = bpf_attach_type::BPF_XDP as isize,
    /// Attach type used in [`ProgramType::SkSkb`] programs.
    ///
    /// Introduced in kernel v5.13.
    #[doc(alias = "BPF_SK_SKB_VERDICT")]
    SkSkbVerdict = bpf_attach_type::BPF_SK_SKB_VERDICT as isize,
    /// Attach type used in [`ProgramType::SkReuseport`] programs.
    ///
    /// Introduced in kernel v5.14.
    #[doc(alias = "BPF_SK_REUSEPORT_SELECT")]
    SkReuseportSelect = bpf_attach_type::BPF_SK_REUSEPORT_SELECT as isize,
    /// Attach type used in [`ProgramType::SkReuseport`] programs.
    ///
    /// Introduced in kernel v5.14.
    #[doc(alias = "BPF_SK_REUSEPORT_SELECT_OR_MIGRATE")]
    SkReuseportSelectOrMigrate = bpf_attach_type::BPF_SK_REUSEPORT_SELECT_OR_MIGRATE as isize,
    /// Attach type used in:
    /// - [`ProgramType::KProbe`]
    /// - [`ProgramType::TracePoint`]
    /// - [`ProgramType::PerfEvent`]
    ///
    /// Introduced in kernel v5.15.
    #[doc(alias = "BPF_PERF_EVENT")]
    PerfEvent = bpf_attach_type::BPF_PERF_EVENT as isize,
    /// Attach type used in [`ProgramType::KProbe`] programs.
    ///
    /// Introduced in kernel v5.18.
    #[doc(alias = "BPF_TRACE_KPROBE_MULTI")]
    TraceKProbeMulti = bpf_attach_type::BPF_TRACE_KPROBE_MULTI as isize,
    /// Attach type used in:
    /// - [`ProgramType::Tracing`]
    /// - [`ProgramType::Lsm`]
    ///
    /// Introduced in kernel v6.0.
    #[doc(alias = "BPF_LSM_CGROUP")]
    LsmCgroup = bpf_attach_type::BPF_LSM_CGROUP as isize,
    /// A Struct Ops attach type.
    ///
    /// Introduced in kernel v6.4.
    #[doc(alias = "BPF_STRUCT_OPS")]
    StructOps = bpf_attach_type::BPF_STRUCT_OPS as isize,
    /// Attach type used in [`ProgramType::Netfilter`] programs.
    ///
    /// Introduced in kernel v6.4.
    #[doc(alias = "BPF_NETFILTER")]
    Netfilter = bpf_attach_type::BPF_NETFILTER as isize,
    /// Attach type used in [`ProgramType::SchedClassifier`] programs.
    ///
    /// Introduced in kernel v6.6.
    #[doc(alias = "BPF_TCX_INGRESS")]
    TcxIngress = bpf_attach_type::BPF_TCX_INGRESS as isize,
    /// Attach type used in [`ProgramType::SchedClassifier`] programs.
    ///
    /// Introduced in kernel v6.6.
    #[doc(alias = "BPF_TCX_EGRESS")]
    TcxEgress = bpf_attach_type::BPF_TCX_EGRESS as isize,
    /// Attach type used in [`ProgramType::KProbe`] programs.
    ///
    /// Introduced in kernel v6.6.
    #[doc(alias = "BPF_TRACE_UPROBE_MULTI")]
    TraceUProbeMulti = bpf_attach_type::BPF_TRACE_UPROBE_MULTI as isize,
    /// Attach type used in [`ProgramType::CgroupSockAddr`] programs.
    ///
    /// Introduced in kernel v6.7.
    #[doc(alias = "BPF_CGROUP_UNIX_CONNECT")]
    CgroupUnixConnect = bpf_attach_type::BPF_CGROUP_UNIX_CONNECT as isize,
    /// Attach type used in [`ProgramType::CgroupSockAddr`] programs.
    ///
    /// Introduced in kernel v6.7.
    #[doc(alias = "BPF_CGROUP_UNIX_SENDMSG")]
    CgroupUnixSendmsg = bpf_attach_type::BPF_CGROUP_UNIX_SENDMSG as isize,
    /// Attach type used in [`ProgramType::CgroupSockAddr`] programs.
    ///
    /// Introduced in kernel v6.7.
    #[doc(alias = "BPF_CGROUP_UNIX_RECVMSG")]
    CgroupUnixRecvmsg = bpf_attach_type::BPF_CGROUP_UNIX_RECVMSG as isize,
    /// Attach type used in [`ProgramType::CgroupSockAddr`] programs.
    ///
    /// Introduced in kernel v6.7.
    #[doc(alias = "BPF_CGROUP_UNIX_GETPEERNAME")]
    CgroupUnixGetpeername = bpf_attach_type::BPF_CGROUP_UNIX_GETPEERNAME as isize,
    /// Attach type used in [`ProgramType::CgroupSockAddr`] programs.
    ///
    /// Introduced in kernel v6.7.
    #[doc(alias = "BPF_CGROUP_UNIX_GETSOCKNAME")]
    CgroupUnixGetsockname = bpf_attach_type::BPF_CGROUP_UNIX_GETSOCKNAME as isize,
    /// Attach type used in [`ProgramType::SchedClassifier`] programs.
    ///
    /// Introduced in kernel v6.7.
    #[doc(alias = "BPF_NETKIT_PRIMARY")]
    NetkitPrimary = bpf_attach_type::BPF_NETKIT_PRIMARY as isize,
    /// Attach type used in [`ProgramType::SchedClassifier`] programs.
    ///
    /// Introduced in kernel v6.7.
    #[doc(alias = "BPF_NETKIT_PEER")]
    NetkitPeer = bpf_attach_type::BPF_NETKIT_PEER as isize,
}

impl TryFrom<bpf_attach_type> for AttachType {
    type Error = LinkError;

    fn try_from(attach_type: bpf_attach_type) -> Result<Self, Self::Error> {
        use bpf_attach_type::*;
        Ok(match attach_type {
            BPF_CGROUP_INET_INGRESS => Self::CgroupInetIngress,
            BPF_CGROUP_INET_EGRESS => Self::CgroupInetEgress,
            BPF_CGROUP_INET_SOCK_CREATE => Self::CgroupInetSockCreate,
            BPF_CGROUP_SOCK_OPS => Self::CgroupSockOps,
            BPF_SK_SKB_STREAM_PARSER => Self::SkSkbStreamParser,
            BPF_SK_SKB_STREAM_VERDICT => Self::SkSkbStreamVerdict,
            BPF_CGROUP_DEVICE => Self::CgroupDevice,
            BPF_SK_MSG_VERDICT => Self::SkMsgVerdict,
            BPF_CGROUP_INET4_BIND => Self::CgroupInet4Bind,
            BPF_CGROUP_INET6_BIND => Self::CgroupInet6Bind,
            BPF_CGROUP_INET4_CONNECT => Self::CgroupInet4Connect,
            BPF_CGROUP_INET6_CONNECT => Self::CgroupInet6Connect,
            BPF_CGROUP_INET4_POST_BIND => Self::CgroupInet4PostBind,
            BPF_CGROUP_INET6_POST_BIND => Self::CgroupInet6PostBind,
            BPF_CGROUP_UDP4_SENDMSG => Self::CgroupUdp4Sendmsg,
            BPF_CGROUP_UDP6_SENDMSG => Self::CgroupUdp6Sendmsg,
            BPF_LIRC_MODE2 => Self::LircMode2,
            BPF_FLOW_DISSECTOR => Self::FlowDissector,
            BPF_CGROUP_SYSCTL => Self::CgroupSysctl,
            BPF_CGROUP_UDP4_RECVMSG => Self::CgroupUdp4Recvmsg,
            BPF_CGROUP_UDP6_RECVMSG => Self::CgroupUdp6Recvmsg,
            BPF_CGROUP_GETSOCKOPT => Self::CgroupGetsockopt,
            BPF_CGROUP_SETSOCKOPT => Self::CgroupSetsockopt,
            BPF_TRACE_RAW_TP => Self::TraceRawTp,
            BPF_TRACE_FENTRY => Self::TraceFEntry,
            BPF_TRACE_FEXIT => Self::TraceFExit,
            BPF_MODIFY_RETURN => Self::ModifyReturn,
            BPF_LSM_MAC => Self::LsmMac,
            BPF_TRACE_ITER => Self::TraceIter,
            BPF_CGROUP_INET4_GETPEERNAME => Self::CgroupInet4Getpeername,
            BPF_CGROUP_INET6_GETPEERNAME => Self::CgroupInet6Getpeername,
            BPF_CGROUP_INET4_GETSOCKNAME => Self::CgroupInet4Getsockname,
            BPF_CGROUP_INET6_GETSOCKNAME => Self::CgroupInet6Getsockname,
            BPF_XDP_DEVMAP => Self::XdpDevMap,
            BPF_CGROUP_INET_SOCK_RELEASE => Self::CgroupInetSockRelease,
            BPF_XDP_CPUMAP => Self::XdpCpuMap,
            BPF_SK_LOOKUP => Self::SkLookup,
            BPF_XDP => Self::Xdp,
            BPF_SK_SKB_VERDICT => Self::SkSkbVerdict,
            BPF_SK_REUSEPORT_SELECT => Self::SkReuseportSelect,
            BPF_SK_REUSEPORT_SELECT_OR_MIGRATE => Self::SkReuseportSelectOrMigrate,
            BPF_PERF_EVENT => Self::PerfEvent,
            BPF_TRACE_KPROBE_MULTI => Self::TraceKProbeMulti,
            BPF_LSM_CGROUP => Self::LsmCgroup,
            BPF_STRUCT_OPS => Self::StructOps,
            BPF_NETFILTER => Self::Netfilter,
            BPF_TCX_INGRESS => Self::TcxIngress,
            BPF_TCX_EGRESS => Self::TcxEgress,
            BPF_TRACE_UPROBE_MULTI => Self::TraceUProbeMulti,
            BPF_CGROUP_UNIX_CONNECT => Self::CgroupUnixConnect,
            BPF_CGROUP_UNIX_SENDMSG => Self::CgroupUnixSendmsg,
            BPF_CGROUP_UNIX_RECVMSG => Self::CgroupUnixRecvmsg,
            BPF_CGROUP_UNIX_GETPEERNAME => Self::CgroupUnixGetpeername,
            BPF_CGROUP_UNIX_GETSOCKNAME => Self::CgroupUnixGetsockname,
            BPF_NETKIT_PRIMARY => Self::NetkitPrimary,
            BPF_NETKIT_PEER => Self::NetkitPeer,
            __MAX_BPF_ATTACH_TYPE => return Err(LinkError::InvalidAttachment),
        })
    }
}

impl TryFrom<u32> for AttachType {
    type Error = LinkError;

    fn try_from(attach_type: u32) -> Result<Self, Self::Error> {
        bpf_attach_type::try_from(attach_type)
            .unwrap_or(bpf_attach_type::__MAX_BPF_ATTACH_TYPE)
            .try_into()
    }
}

/// How the iterator should traverse the cgroups.
// TODO: move this into appropriate location once this program type is implemented
#[doc(alias = "bpf_cgroup_iter_order")]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum CgroupIterOrder {
    /// Only yield the cgroup that was specified (single).
    #[doc(alias = "BPF_CGROUP_ITER_SELF_ONLY")]
    SelfOnly = bpf_cgroup_iter_order::BPF_CGROUP_ITER_SELF_ONLY as isize,
    /// Traverse the descendants of the specified cgroup, starting from the specified cgroup down to its children (top-down).
    #[doc(alias = "BPF_CGROUP_ITER_DESCENDANTS_PRE")]
    DescendantsPre = bpf_cgroup_iter_order::BPF_CGROUP_ITER_DESCENDANTS_PRE as isize,
    /// Traverse the descendants of the specified cgroup, starting from its children up to the cgroup (bottom-up).
    #[doc(alias = "BPF_CGROUP_ITER_DESCENDANTS_POST")]
    DescendantsPost = bpf_cgroup_iter_order::BPF_CGROUP_ITER_DESCENDANTS_POST as isize,
    /// Traverse the ancestors of the specified cgroup, from the specified cgroup up to the root.
    #[doc(alias = "BPF_CGROUP_ITER_ANCESTORS_UP")]
    AncestorsUp = bpf_cgroup_iter_order::BPF_CGROUP_ITER_ANCESTORS_UP as isize,
}

// TODO: move this into appropriate location once this program type is implemented
impl TryFrom<bpf_cgroup_iter_order> for CgroupIterOrder {
    type Error = LinkError;

    fn try_from(order: bpf_cgroup_iter_order) -> Result<Self, Self::Error> {
        use bpf_cgroup_iter_order::*;
        Ok(match order {
            BPF_CGROUP_ITER_SELF_ONLY => Self::SelfOnly,
            BPF_CGROUP_ITER_DESCENDANTS_PRE => Self::DescendantsPre,
            BPF_CGROUP_ITER_DESCENDANTS_POST => Self::DescendantsPost,
            BPF_CGROUP_ITER_ANCESTORS_UP => Self::AncestorsUp,
            _ => return Err(LinkError::InvalidAttachment),
        })
    }
}

/// The protocol/address family of the packets to process or intercept.
///
/// Note that BPF netfilter only supports `NFPROTO_IPV4` and `NFPROTO_IPV6`.
// TODO: move this into appropriate location once this program type is implemented
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ProtocolFamily {
    /// Target IPv4 packets.
    #[doc(alias = "NFPROTO_IPV4")]
    Ipv4 = NFPROTO_IPV4 as isize,
    /// Target IPv6 packets.
    #[doc(alias = "NFPROTO_IPV6")]
    Ipv6 = NFPROTO_IPV6 as isize,
}

impl TryFrom<u32> for ProtocolFamily {
    type Error = LinkError;

    fn try_from(pf: u32) -> Result<Self, Self::Error> {
        Ok(match pf {
            NFPROTO_IPV4 => Self::Ipv4,
            NFPROTO_IPV6 => Self::Ipv6,
            _ => return Err(LinkError::InvalidAttachment),
        })
    }
}

/// The hook location in the network stack.
// TODO: move this into appropriate location once this program type is implemented
#[doc(alias = "nf_inet_hooks")]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum InetHook {
    /// When an incoming packet has entered the network stack, and before the routing decision is made.
    #[doc(alias = "NF_INET_PRE_ROUTING")]
    PreRouting = nf_inet_hooks::NF_INET_PRE_ROUTING as isize,
    /// After the routing decision of an incoming packet is determined and is destined for the
    /// current host.
    #[doc(alias = "NF_INET_LOCAL_IN")]
    LocalIn = nf_inet_hooks::NF_INET_LOCAL_IN as isize,
    /// After the routing decision of a packet is determined, and its forwarded destination is not
    /// the current host.
    #[doc(alias = "NF_INET_FORWARD")]
    Forward = nf_inet_hooks::NF_INET_FORWARD as isize,
    /// Packets created by the current host that are destined outbound. This is after the outgoing
    /// packet has hit the network stack, and before the routing decision is made.
    #[doc(alias = "NF_INET_LOCAL_OUT")]
    LocalOut = nf_inet_hooks::NF_INET_LOCAL_OUT as isize,
    /// After the routing decision of an outgoing packet is determined, before leaving the host.
    #[doc(alias = "NF_INET_POST_ROUTING")]
    PostRouting = nf_inet_hooks::NF_INET_POST_ROUTING as isize,
}

impl TryFrom<nf_inet_hooks> for InetHook {
    type Error = LinkError;

    fn try_from(hook: nf_inet_hooks) -> Result<Self, Self::Error> {
        Ok(match hook {
            nf_inet_hooks::NF_INET_PRE_ROUTING => Self::PreRouting,
            nf_inet_hooks::NF_INET_LOCAL_IN => Self::LocalIn,
            nf_inet_hooks::NF_INET_FORWARD => Self::Forward,
            nf_inet_hooks::NF_INET_LOCAL_OUT => Self::LocalOut,
            nf_inet_hooks::NF_INET_POST_ROUTING => Self::PostRouting,
            _ => return Err(LinkError::InvalidAttachment),
        })
    }
}
