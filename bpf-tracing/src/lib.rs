//! Rich and event-based diagnostic information for eBPF.
//!
//! It exports a set of macros that can be used to emit
//! diagnostic events from eBPF programs. The events are
//! efficiently copied to user space via a ring buffer
//! and integrated into the [`tracing`] infrastructure.
//!
//! # Example
//!
//! ```no_run
//! # use std::mem::MaybeUninit;
//! # mod tracing_subscriber {
//! #     pub struct Fmt;
//! #     pub struct EnvFilter;
//! #
//! #     pub fn fmt() -> Fmt {
//! #         Fmt
//! #     }
//! #
//! #     impl EnvFilter {
//! #         pub fn from_default_env() -> Self {
//! #             EnvFilter
//! #         }
//! #     }
//! #
//! #     impl Fmt {
//! #         pub fn with_env_filter(self, _filter: EnvFilter) -> Self {
//! #             self
//! #         }
//! #
//! #         pub fn with_file(self, _with_file: bool) -> Self {
//! #             self
//! #         }
//! #
//! #         pub fn with_line_number(self, _with_line_number: bool) -> Self {
//! #             self
//! #         }
//! #
//! #         pub fn init(self) {}
//! #     }
//! # }
//! # struct SkelBuilder;
//! # struct OpenSkel;
//! # struct Skel;
//! #
//! # impl Default for SkelBuilder {
//! #     fn default() -> Self {
//! #         Self
//! #     }
//! # }
//! #
//! # impl SkelBuilder {
//! #     fn open(&self, _open_obj: &mut MaybeUninit<()>) -> xbpf::libbpf::Result<OpenSkel> {
//! #         unimplemented!()
//! #     }
//! # }
//! #
//! # impl OpenSkel {
//! #     fn load(self) -> xbpf::libbpf::Result<Skel> {
//! #         unimplemented!()
//! #     }
//! # }
//! #
//! # impl Skel {
//! #     fn object(&self) -> &xbpf::libbpf::Object {
//! #         unimplemented!()
//! #     }
//! # }
//! #
//! # fn main() -> xbpf::libbpf::Result<()> {
//!
//! tracing_subscriber::fmt()
//!     .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
//!     .with_file(true)
//!     .with_line_number(true)
//!     .init();
//!
//! let mut open_obj = MaybeUninit::uninit();
//! let skel_builder = SkelBuilder::default();
//! let open_skel = skel_builder.open(&mut open_obj)?;
//! let skel = open_skel.load()?;
//!
//! bpf_tracing::try_init(skel.object());
//! # Ok(())
//! # }
//! ```
//!
//! And in your eBPF program:
//!
//! ```custom,{.language-c}
//! bpf_info("Established socket [%pI4:%u->%pI4:%u]", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port);
//! ```
//!
//! [`tracing`]: https://github.com/tokio-rs/tracing

/// Initializes a ring buffer reader that continuously observes and
/// emits tracing events.
///
/// # Errors
/// Returns an Error if the `trace_pipe` file cannot be opened
/// or found.
#[inline]
pub fn try_init(obj: &xbpf::libbpf::Object) -> xbpf::libbpf::Result<()> {
    xbpf::tracing::try_init(obj)
}
