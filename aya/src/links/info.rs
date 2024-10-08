//! Metadata information about an eBPF link.

use std::os::fd::{AsFd as _, BorrowedFd};

use aya_obj::generated::{bpf_attach_type, bpf_link_info, bpf_link_type};

#[allow(unused_imports)] // Used in rustdoc linking
use crate::programs::ProgramType;
use crate::{
    programs::links::{FdLink, LinkError},
    sys::{bpf_link_get_fd_by_id, bpf_link_get_info_by_fd, iter_link_ids},
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
            _ => Ok(LinkMetadata::NotImplemented),
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

    /// For metadata that have not been implemented yet.
    #[doc(hidden)]
    NotImplemented,
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
    /// - [`AttachType::StructOps`]
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
