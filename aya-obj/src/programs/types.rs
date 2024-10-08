//! Program type bindings.

use crate::{
    generated::{bpf_perf_event_type, bpf_prog_type},
    InvalidTypeBinding,
};

impl TryFrom<u32> for bpf_prog_type {
    type Error = InvalidTypeBinding<u32>;

    fn try_from(prog_type: u32) -> Result<Self, Self::Error> {
        use bpf_prog_type::*;
        Ok(match prog_type {
            x if x == BPF_PROG_TYPE_UNSPEC as u32 => BPF_PROG_TYPE_UNSPEC,
            x if x == BPF_PROG_TYPE_SOCKET_FILTER as u32 => BPF_PROG_TYPE_SOCKET_FILTER,
            x if x == BPF_PROG_TYPE_KPROBE as u32 => BPF_PROG_TYPE_KPROBE,
            x if x == BPF_PROG_TYPE_SCHED_CLS as u32 => BPF_PROG_TYPE_SCHED_CLS,
            x if x == BPF_PROG_TYPE_SCHED_ACT as u32 => BPF_PROG_TYPE_SCHED_ACT,
            x if x == BPF_PROG_TYPE_TRACEPOINT as u32 => BPF_PROG_TYPE_TRACEPOINT,
            x if x == BPF_PROG_TYPE_XDP as u32 => BPF_PROG_TYPE_XDP,
            x if x == BPF_PROG_TYPE_PERF_EVENT as u32 => BPF_PROG_TYPE_PERF_EVENT,
            x if x == BPF_PROG_TYPE_CGROUP_SKB as u32 => BPF_PROG_TYPE_CGROUP_SKB,
            x if x == BPF_PROG_TYPE_CGROUP_SOCK as u32 => BPF_PROG_TYPE_CGROUP_SOCK,
            x if x == BPF_PROG_TYPE_LWT_IN as u32 => BPF_PROG_TYPE_LWT_IN,
            x if x == BPF_PROG_TYPE_LWT_OUT as u32 => BPF_PROG_TYPE_LWT_OUT,
            x if x == BPF_PROG_TYPE_LWT_XMIT as u32 => BPF_PROG_TYPE_LWT_XMIT,
            x if x == BPF_PROG_TYPE_SOCK_OPS as u32 => BPF_PROG_TYPE_SOCK_OPS,
            x if x == BPF_PROG_TYPE_SK_SKB as u32 => BPF_PROG_TYPE_SK_SKB,
            x if x == BPF_PROG_TYPE_CGROUP_DEVICE as u32 => BPF_PROG_TYPE_CGROUP_DEVICE,
            x if x == BPF_PROG_TYPE_SK_MSG as u32 => BPF_PROG_TYPE_SK_MSG,
            x if x == BPF_PROG_TYPE_RAW_TRACEPOINT as u32 => BPF_PROG_TYPE_RAW_TRACEPOINT,
            x if x == BPF_PROG_TYPE_CGROUP_SOCK_ADDR as u32 => BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
            x if x == BPF_PROG_TYPE_LWT_SEG6LOCAL as u32 => BPF_PROG_TYPE_LWT_SEG6LOCAL,
            x if x == BPF_PROG_TYPE_LIRC_MODE2 as u32 => BPF_PROG_TYPE_LIRC_MODE2,
            x if x == BPF_PROG_TYPE_SK_REUSEPORT as u32 => BPF_PROG_TYPE_SK_REUSEPORT,
            x if x == BPF_PROG_TYPE_FLOW_DISSECTOR as u32 => BPF_PROG_TYPE_FLOW_DISSECTOR,
            x if x == BPF_PROG_TYPE_CGROUP_SYSCTL as u32 => BPF_PROG_TYPE_CGROUP_SYSCTL,
            x if x == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE as u32 => {
                BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE
            }
            x if x == BPF_PROG_TYPE_CGROUP_SOCKOPT as u32 => BPF_PROG_TYPE_CGROUP_SOCKOPT,
            x if x == BPF_PROG_TYPE_TRACING as u32 => BPF_PROG_TYPE_TRACING,
            x if x == BPF_PROG_TYPE_STRUCT_OPS as u32 => BPF_PROG_TYPE_STRUCT_OPS,
            x if x == BPF_PROG_TYPE_EXT as u32 => BPF_PROG_TYPE_EXT,
            x if x == BPF_PROG_TYPE_LSM as u32 => BPF_PROG_TYPE_LSM,
            x if x == BPF_PROG_TYPE_SK_LOOKUP as u32 => BPF_PROG_TYPE_SK_LOOKUP,
            x if x == BPF_PROG_TYPE_SYSCALL as u32 => BPF_PROG_TYPE_SYSCALL,
            x if x == BPF_PROG_TYPE_NETFILTER as u32 => BPF_PROG_TYPE_NETFILTER,
            _ => return Err(InvalidTypeBinding { value: prog_type }),
        })
    }
}

impl TryFrom<u32> for bpf_perf_event_type {
    type Error = InvalidTypeBinding<u32>;

    fn try_from(prog_type: u32) -> Result<Self, Self::Error> {
        use bpf_perf_event_type::*;
        Ok(match prog_type {
            x if x == BPF_PERF_EVENT_UNSPEC as u32 => BPF_PERF_EVENT_UNSPEC,
            x if x == BPF_PERF_EVENT_UPROBE as u32 => BPF_PERF_EVENT_UPROBE,
            x if x == BPF_PERF_EVENT_URETPROBE as u32 => BPF_PERF_EVENT_URETPROBE,
            x if x == BPF_PERF_EVENT_KPROBE as u32 => BPF_PERF_EVENT_KPROBE,
            x if x == BPF_PERF_EVENT_KRETPROBE as u32 => BPF_PERF_EVENT_KRETPROBE,
            x if x == BPF_PERF_EVENT_TRACEPOINT as u32 => BPF_PERF_EVENT_TRACEPOINT,
            x if x == BPF_PERF_EVENT_EVENT as u32 => BPF_PERF_EVENT_EVENT,
            _ => return Err(InvalidTypeBinding { value: prog_type }),
        })
    }
}

impl TryFrom<u32> for crate::generated::perf_type_id {
    type Error = InvalidTypeBinding<u32>;

    fn try_from(perf_type: u32) -> Result<Self, Self::Error> {
        use crate::generated::perf_type_id::*;
        Ok(match perf_type {
            x if x == PERF_TYPE_HARDWARE as u32 => PERF_TYPE_HARDWARE,
            x if x == PERF_TYPE_SOFTWARE as u32 => PERF_TYPE_SOFTWARE,
            x if x == PERF_TYPE_TRACEPOINT as u32 => PERF_TYPE_TRACEPOINT,
            x if x == PERF_TYPE_HW_CACHE as u32 => PERF_TYPE_HW_CACHE,
            x if x == PERF_TYPE_RAW as u32 => PERF_TYPE_RAW,
            x if x == PERF_TYPE_BREAKPOINT as u32 => PERF_TYPE_BREAKPOINT,
            _ => return Err(InvalidTypeBinding { value: perf_type }),
        })
    }
}

impl TryFrom<u64> for crate::generated::perf_hw_id {
    type Error = InvalidTypeBinding<u64>;

    fn try_from(hw_id: u64) -> Result<Self, Self::Error> {
        use crate::generated::perf_hw_id::*;
        Ok(match hw_id {
            x if x == PERF_COUNT_HW_CPU_CYCLES as u64 => PERF_COUNT_HW_CPU_CYCLES,
            x if x == PERF_COUNT_HW_INSTRUCTIONS as u64 => PERF_COUNT_HW_INSTRUCTIONS,
            x if x == PERF_COUNT_HW_CACHE_REFERENCES as u64 => PERF_COUNT_HW_CACHE_REFERENCES,
            x if x == PERF_COUNT_HW_CACHE_MISSES as u64 => PERF_COUNT_HW_CACHE_MISSES,
            x if x == PERF_COUNT_HW_BRANCH_INSTRUCTIONS as u64 => PERF_COUNT_HW_BRANCH_INSTRUCTIONS,
            x if x == PERF_COUNT_HW_BRANCH_MISSES as u64 => PERF_COUNT_HW_BRANCH_MISSES,
            x if x == PERF_COUNT_HW_BUS_CYCLES as u64 => PERF_COUNT_HW_BUS_CYCLES,
            x if x == PERF_COUNT_HW_STALLED_CYCLES_FRONTEND as u64 => {
                PERF_COUNT_HW_STALLED_CYCLES_FRONTEND
            }
            x if x == PERF_COUNT_HW_STALLED_CYCLES_BACKEND as u64 => {
                PERF_COUNT_HW_STALLED_CYCLES_BACKEND
            }
            x if x == PERF_COUNT_HW_REF_CPU_CYCLES as u64 => PERF_COUNT_HW_REF_CPU_CYCLES,
            _ => return Err(InvalidTypeBinding { value: hw_id }),
        })
    }
}

impl TryFrom<u64> for crate::generated::perf_sw_ids {
    type Error = InvalidTypeBinding<u64>;

    fn try_from(sw_id: u64) -> Result<Self, Self::Error> {
        use crate::generated::perf_sw_ids::*;
        Ok(match sw_id {
            x if x == PERF_COUNT_SW_CPU_CLOCK as u64 => PERF_COUNT_SW_CPU_CLOCK,
            x if x == PERF_COUNT_SW_TASK_CLOCK as u64 => PERF_COUNT_SW_TASK_CLOCK,
            x if x == PERF_COUNT_SW_PAGE_FAULTS as u64 => PERF_COUNT_SW_PAGE_FAULTS,
            x if x == PERF_COUNT_SW_CONTEXT_SWITCHES as u64 => PERF_COUNT_SW_CONTEXT_SWITCHES,
            x if x == PERF_COUNT_SW_CPU_MIGRATIONS as u64 => PERF_COUNT_SW_CPU_MIGRATIONS,
            x if x == PERF_COUNT_SW_PAGE_FAULTS_MIN as u64 => PERF_COUNT_SW_PAGE_FAULTS_MIN,
            x if x == PERF_COUNT_SW_PAGE_FAULTS_MAJ as u64 => PERF_COUNT_SW_PAGE_FAULTS_MAJ,
            x if x == PERF_COUNT_SW_ALIGNMENT_FAULTS as u64 => PERF_COUNT_SW_ALIGNMENT_FAULTS,
            x if x == PERF_COUNT_SW_EMULATION_FAULTS as u64 => PERF_COUNT_SW_EMULATION_FAULTS,
            x if x == PERF_COUNT_SW_DUMMY as u64 => PERF_COUNT_SW_DUMMY,
            x if x == PERF_COUNT_SW_BPF_OUTPUT as u64 => PERF_COUNT_SW_BPF_OUTPUT,
            x if x == PERF_COUNT_SW_CGROUP_SWITCHES as u64 => PERF_COUNT_SW_CGROUP_SWITCHES,
            _ => return Err(InvalidTypeBinding { value: sw_id }),
        })
    }
}

impl TryFrom<u64> for crate::generated::perf_hw_cache_id {
    type Error = InvalidTypeBinding<u64>;

    fn try_from(cache_id: u64) -> Result<Self, Self::Error> {
        use crate::generated::perf_hw_cache_id::*;
        Ok(match cache_id {
            x if x == PERF_COUNT_HW_CACHE_L1D as u64 => PERF_COUNT_HW_CACHE_L1D,
            x if x == PERF_COUNT_HW_CACHE_L1I as u64 => PERF_COUNT_HW_CACHE_L1I,
            x if x == PERF_COUNT_HW_CACHE_LL as u64 => PERF_COUNT_HW_CACHE_LL,
            x if x == PERF_COUNT_HW_CACHE_DTLB as u64 => PERF_COUNT_HW_CACHE_DTLB,
            x if x == PERF_COUNT_HW_CACHE_ITLB as u64 => PERF_COUNT_HW_CACHE_ITLB,
            x if x == PERF_COUNT_HW_CACHE_BPU as u64 => PERF_COUNT_HW_CACHE_BPU,
            x if x == PERF_COUNT_HW_CACHE_NODE as u64 => PERF_COUNT_HW_CACHE_NODE,
            _ => return Err(InvalidTypeBinding { value: cache_id }),
        })
    }
}

impl TryFrom<u64> for crate::generated::perf_hw_cache_op_id {
    type Error = InvalidTypeBinding<u64>;

    fn try_from(cache_op_id: u64) -> Result<Self, Self::Error> {
        use crate::generated::perf_hw_cache_op_id::*;
        Ok(match cache_op_id {
            x if x == PERF_COUNT_HW_CACHE_OP_READ as u64 => PERF_COUNT_HW_CACHE_OP_READ,
            x if x == PERF_COUNT_HW_CACHE_OP_WRITE as u64 => PERF_COUNT_HW_CACHE_OP_WRITE,
            x if x == PERF_COUNT_HW_CACHE_OP_PREFETCH as u64 => PERF_COUNT_HW_CACHE_OP_PREFETCH,
            _ => return Err(InvalidTypeBinding { value: cache_op_id }),
        })
    }
}

impl TryFrom<u64> for crate::generated::perf_hw_cache_op_result_id {
    type Error = InvalidTypeBinding<u64>;

    fn try_from(hw_cache_res: u64) -> Result<Self, Self::Error> {
        use crate::generated::perf_hw_cache_op_result_id::*;
        Ok(match hw_cache_res {
            x if x == PERF_COUNT_HW_CACHE_RESULT_ACCESS as u64 => PERF_COUNT_HW_CACHE_RESULT_ACCESS,
            x if x == PERF_COUNT_HW_CACHE_RESULT_MISS as u64 => PERF_COUNT_HW_CACHE_RESULT_MISS,
            _ => {
                return Err(InvalidTypeBinding {
                    value: hw_cache_res,
                })
            }
        })
    }
}

impl TryFrom<u32> for crate::generated::bpf_cgroup_iter_order {
    type Error = InvalidTypeBinding<u32>;

    fn try_from(order: u32) -> Result<Self, Self::Error> {
        use crate::generated::bpf_cgroup_iter_order::*;
        Ok(match order {
            x if x == BPF_CGROUP_ITER_ORDER_UNSPEC as u32 => BPF_CGROUP_ITER_ORDER_UNSPEC,
            x if x == BPF_CGROUP_ITER_SELF_ONLY as u32 => BPF_CGROUP_ITER_SELF_ONLY,
            x if x == BPF_CGROUP_ITER_DESCENDANTS_PRE as u32 => BPF_CGROUP_ITER_DESCENDANTS_PRE,
            x if x == BPF_CGROUP_ITER_DESCENDANTS_POST as u32 => BPF_CGROUP_ITER_DESCENDANTS_POST,
            x if x == BPF_CGROUP_ITER_ANCESTORS_UP as u32 => BPF_CGROUP_ITER_ANCESTORS_UP,
            _ => return Err(InvalidTypeBinding { value: order }),
        })
    }
}

impl TryFrom<u32> for crate::generated::nf_inet_hooks {
    type Error = InvalidTypeBinding<u32>;

    fn try_from(hook: u32) -> Result<Self, Self::Error> {
        use crate::generated::nf_inet_hooks::*;
        Ok(match hook {
            x if x == NF_INET_PRE_ROUTING as u32 => NF_INET_PRE_ROUTING,
            x if x == NF_INET_LOCAL_IN as u32 => NF_INET_LOCAL_IN,
            x if x == NF_INET_FORWARD as u32 => NF_INET_FORWARD,
            x if x == NF_INET_LOCAL_OUT as u32 => NF_INET_LOCAL_OUT,
            x if x == NF_INET_POST_ROUTING as u32 => NF_INET_POST_ROUTING,
            _ => return Err(InvalidTypeBinding { value: hook }),
        })
    }
}
