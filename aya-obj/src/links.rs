//! Link type bindings.

use crate::{
    generated::{bpf_attach_type, bpf_link_type},
    InvalidTypeBinding,
};

impl TryFrom<u32> for bpf_link_type {
    type Error = InvalidTypeBinding<u32>;

    fn try_from(link_type: u32) -> Result<Self, Self::Error> {
        use aya_ebpf::bindings::bpf_link_type as link_binding;
        use bpf_link_type::*;
        Ok(match link_type {
            link_binding::BPF_LINK_TYPE_UNSPEC => BPF_LINK_TYPE_UNSPEC,
            link_binding::BPF_LINK_TYPE_RAW_TRACEPOINT => BPF_LINK_TYPE_RAW_TRACEPOINT,
            link_binding::BPF_LINK_TYPE_TRACING => BPF_LINK_TYPE_TRACING,
            link_binding::BPF_LINK_TYPE_CGROUP => BPF_LINK_TYPE_CGROUP,
            link_binding::BPF_LINK_TYPE_ITER => BPF_LINK_TYPE_ITER,
            link_binding::BPF_LINK_TYPE_NETNS => BPF_LINK_TYPE_NETNS,
            link_binding::BPF_LINK_TYPE_XDP => BPF_LINK_TYPE_XDP,
            link_binding::BPF_LINK_TYPE_PERF_EVENT => BPF_LINK_TYPE_PERF_EVENT,
            link_binding::BPF_LINK_TYPE_KPROBE_MULTI => BPF_LINK_TYPE_KPROBE_MULTI,
            link_binding::BPF_LINK_TYPE_STRUCT_OPS => BPF_LINK_TYPE_STRUCT_OPS,
            link_binding::BPF_LINK_TYPE_NETFILTER => BPF_LINK_TYPE_NETFILTER,
            link_binding::BPF_LINK_TYPE_TCX => BPF_LINK_TYPE_TCX,
            link_binding::BPF_LINK_TYPE_UPROBE_MULTI => BPF_LINK_TYPE_UPROBE_MULTI,
            link_binding::BPF_LINK_TYPE_NETKIT => BPF_LINK_TYPE_NETKIT,
            _ => return Err(InvalidTypeBinding { value: link_type }),
        })
    }
}

impl TryFrom<u32> for bpf_attach_type {
    type Error = InvalidTypeBinding<u32>;

    fn try_from(attach_type: u32) -> Result<Self, Self::Error> {
        use aya_ebpf::bindings::bpf_attach_type as attach_binding;
        use bpf_attach_type::*;
        Ok(match attach_type {
            attach_binding::BPF_CGROUP_INET_INGRESS => BPF_CGROUP_INET_INGRESS,
            attach_binding::BPF_CGROUP_INET_EGRESS => BPF_CGROUP_INET_EGRESS,
            attach_binding::BPF_CGROUP_INET_SOCK_CREATE => BPF_CGROUP_INET_SOCK_CREATE,
            attach_binding::BPF_CGROUP_SOCK_OPS => BPF_CGROUP_SOCK_OPS,
            attach_binding::BPF_SK_SKB_STREAM_PARSER => BPF_SK_SKB_STREAM_PARSER,
            attach_binding::BPF_SK_SKB_STREAM_VERDICT => BPF_SK_SKB_STREAM_VERDICT,
            attach_binding::BPF_CGROUP_DEVICE => BPF_CGROUP_DEVICE,
            attach_binding::BPF_SK_MSG_VERDICT => BPF_SK_MSG_VERDICT,
            attach_binding::BPF_CGROUP_INET4_BIND => BPF_CGROUP_INET4_BIND,
            attach_binding::BPF_CGROUP_INET6_BIND => BPF_CGROUP_INET6_BIND,
            attach_binding::BPF_CGROUP_INET4_CONNECT => BPF_CGROUP_INET4_CONNECT,
            attach_binding::BPF_CGROUP_INET6_CONNECT => BPF_CGROUP_INET6_CONNECT,
            attach_binding::BPF_CGROUP_INET4_POST_BIND => BPF_CGROUP_INET4_POST_BIND,
            attach_binding::BPF_CGROUP_INET6_POST_BIND => BPF_CGROUP_INET6_POST_BIND,
            attach_binding::BPF_CGROUP_UDP4_SENDMSG => BPF_CGROUP_UDP4_SENDMSG,
            attach_binding::BPF_CGROUP_UDP6_SENDMSG => BPF_CGROUP_UDP6_SENDMSG,
            attach_binding::BPF_LIRC_MODE2 => BPF_LIRC_MODE2,
            attach_binding::BPF_FLOW_DISSECTOR => BPF_FLOW_DISSECTOR,
            attach_binding::BPF_CGROUP_SYSCTL => BPF_CGROUP_SYSCTL,
            attach_binding::BPF_CGROUP_UDP4_RECVMSG => BPF_CGROUP_UDP4_RECVMSG,
            attach_binding::BPF_CGROUP_UDP6_RECVMSG => BPF_CGROUP_UDP6_RECVMSG,
            attach_binding::BPF_CGROUP_GETSOCKOPT => BPF_CGROUP_GETSOCKOPT,
            attach_binding::BPF_CGROUP_SETSOCKOPT => BPF_CGROUP_SETSOCKOPT,
            attach_binding::BPF_TRACE_RAW_TP => BPF_TRACE_RAW_TP,
            attach_binding::BPF_TRACE_FENTRY => BPF_TRACE_FENTRY,
            attach_binding::BPF_TRACE_FEXIT => BPF_TRACE_FEXIT,
            attach_binding::BPF_MODIFY_RETURN => BPF_MODIFY_RETURN,
            attach_binding::BPF_LSM_MAC => BPF_LSM_MAC,
            attach_binding::BPF_TRACE_ITER => BPF_TRACE_ITER,
            attach_binding::BPF_CGROUP_INET4_GETPEERNAME => BPF_CGROUP_INET4_GETPEERNAME,
            attach_binding::BPF_CGROUP_INET6_GETPEERNAME => BPF_CGROUP_INET6_GETPEERNAME,
            attach_binding::BPF_CGROUP_INET4_GETSOCKNAME => BPF_CGROUP_INET4_GETSOCKNAME,
            attach_binding::BPF_CGROUP_INET6_GETSOCKNAME => BPF_CGROUP_INET6_GETSOCKNAME,
            attach_binding::BPF_XDP_DEVMAP => BPF_XDP_DEVMAP,
            attach_binding::BPF_CGROUP_INET_SOCK_RELEASE => BPF_CGROUP_INET_SOCK_RELEASE,
            attach_binding::BPF_XDP_CPUMAP => BPF_XDP_CPUMAP,
            attach_binding::BPF_SK_LOOKUP => BPF_SK_LOOKUP,
            attach_binding::BPF_XDP => BPF_XDP,
            attach_binding::BPF_SK_SKB_VERDICT => BPF_SK_SKB_VERDICT,
            attach_binding::BPF_SK_REUSEPORT_SELECT => BPF_SK_REUSEPORT_SELECT,
            attach_binding::BPF_SK_REUSEPORT_SELECT_OR_MIGRATE => {
                BPF_SK_REUSEPORT_SELECT_OR_MIGRATE
            }
            attach_binding::BPF_PERF_EVENT => BPF_PERF_EVENT,
            attach_binding::BPF_TRACE_KPROBE_MULTI => BPF_TRACE_KPROBE_MULTI,
            attach_binding::BPF_LSM_CGROUP => BPF_LSM_CGROUP,
            attach_binding::BPF_STRUCT_OPS => BPF_STRUCT_OPS,
            attach_binding::BPF_NETFILTER => BPF_NETFILTER,
            attach_binding::BPF_TCX_INGRESS => BPF_TCX_INGRESS,
            attach_binding::BPF_TCX_EGRESS => BPF_TCX_EGRESS,
            attach_binding::BPF_TRACE_UPROBE_MULTI => BPF_TRACE_UPROBE_MULTI,
            attach_binding::BPF_CGROUP_UNIX_CONNECT => BPF_CGROUP_UNIX_CONNECT,
            attach_binding::BPF_CGROUP_UNIX_SENDMSG => BPF_CGROUP_UNIX_SENDMSG,
            attach_binding::BPF_CGROUP_UNIX_RECVMSG => BPF_CGROUP_UNIX_RECVMSG,
            attach_binding::BPF_CGROUP_UNIX_GETPEERNAME => BPF_CGROUP_UNIX_GETPEERNAME,
            attach_binding::BPF_CGROUP_UNIX_GETSOCKNAME => BPF_CGROUP_UNIX_GETSOCKNAME,
            attach_binding::BPF_NETKIT_PRIMARY => BPF_NETKIT_PRIMARY,
            attach_binding::BPF_NETKIT_PEER => BPF_NETKIT_PEER,
            _ => return Err(InvalidTypeBinding { value: attach_type }),
        })
    }
}
