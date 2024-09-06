//! Program type bindings.

use crate::{generated::bpf_prog_type, InvalidTypeBinding};

impl TryFrom<u32> for bpf_prog_type {
    type Error = InvalidTypeBinding<u32>;

    fn try_from(prog_type: u32) -> Result<Self, Self::Error> {
        use aya_ebpf::bindings::bpf_prog_type as prog_binding;
        use bpf_prog_type::*;
        Ok(match prog_type {
            prog_binding::BPF_PROG_TYPE_UNSPEC => BPF_PROG_TYPE_UNSPEC,
            prog_binding::BPF_PROG_TYPE_SOCKET_FILTER => BPF_PROG_TYPE_SOCKET_FILTER,
            prog_binding::BPF_PROG_TYPE_KPROBE => BPF_PROG_TYPE_KPROBE,
            prog_binding::BPF_PROG_TYPE_SCHED_CLS => BPF_PROG_TYPE_SCHED_CLS,
            prog_binding::BPF_PROG_TYPE_SCHED_ACT => BPF_PROG_TYPE_SCHED_ACT,
            prog_binding::BPF_PROG_TYPE_TRACEPOINT => BPF_PROG_TYPE_TRACEPOINT,
            prog_binding::BPF_PROG_TYPE_XDP => BPF_PROG_TYPE_XDP,
            prog_binding::BPF_PROG_TYPE_PERF_EVENT => BPF_PROG_TYPE_PERF_EVENT,
            prog_binding::BPF_PROG_TYPE_CGROUP_SKB => BPF_PROG_TYPE_CGROUP_SKB,
            prog_binding::BPF_PROG_TYPE_CGROUP_SOCK => BPF_PROG_TYPE_CGROUP_SOCK,
            prog_binding::BPF_PROG_TYPE_LWT_IN => BPF_PROG_TYPE_LWT_IN,
            prog_binding::BPF_PROG_TYPE_LWT_OUT => BPF_PROG_TYPE_LWT_OUT,
            prog_binding::BPF_PROG_TYPE_LWT_XMIT => BPF_PROG_TYPE_LWT_XMIT,
            prog_binding::BPF_PROG_TYPE_SOCK_OPS => BPF_PROG_TYPE_SOCK_OPS,
            prog_binding::BPF_PROG_TYPE_SK_SKB => BPF_PROG_TYPE_SK_SKB,
            prog_binding::BPF_PROG_TYPE_CGROUP_DEVICE => BPF_PROG_TYPE_CGROUP_DEVICE,
            prog_binding::BPF_PROG_TYPE_SK_MSG => BPF_PROG_TYPE_SK_MSG,
            prog_binding::BPF_PROG_TYPE_RAW_TRACEPOINT => BPF_PROG_TYPE_RAW_TRACEPOINT,
            prog_binding::BPF_PROG_TYPE_CGROUP_SOCK_ADDR => BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
            prog_binding::BPF_PROG_TYPE_LWT_SEG6LOCAL => BPF_PROG_TYPE_LWT_SEG6LOCAL,
            prog_binding::BPF_PROG_TYPE_LIRC_MODE2 => BPF_PROG_TYPE_LIRC_MODE2,
            prog_binding::BPF_PROG_TYPE_SK_REUSEPORT => BPF_PROG_TYPE_SK_REUSEPORT,
            prog_binding::BPF_PROG_TYPE_FLOW_DISSECTOR => BPF_PROG_TYPE_FLOW_DISSECTOR,
            prog_binding::BPF_PROG_TYPE_CGROUP_SYSCTL => BPF_PROG_TYPE_CGROUP_SYSCTL,
            prog_binding::BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE => {
                BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE
            }
            prog_binding::BPF_PROG_TYPE_CGROUP_SOCKOPT => BPF_PROG_TYPE_CGROUP_SOCKOPT,
            prog_binding::BPF_PROG_TYPE_TRACING => BPF_PROG_TYPE_TRACING,
            prog_binding::BPF_PROG_TYPE_STRUCT_OPS => BPF_PROG_TYPE_STRUCT_OPS,
            prog_binding::BPF_PROG_TYPE_EXT => BPF_PROG_TYPE_EXT,
            prog_binding::BPF_PROG_TYPE_LSM => BPF_PROG_TYPE_LSM,
            prog_binding::BPF_PROG_TYPE_SK_LOOKUP => BPF_PROG_TYPE_SK_LOOKUP,
            prog_binding::BPF_PROG_TYPE_SYSCALL => BPF_PROG_TYPE_SYSCALL,
            prog_binding::BPF_PROG_TYPE_NETFILTER => BPF_PROG_TYPE_NETFILTER,
            _ => return Err(InvalidTypeBinding { value: prog_type }),
        })
    }
}
