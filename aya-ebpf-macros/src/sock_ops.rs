use proc_macro2::TokenStream;
use proc_macro2_diagnostics::{Diagnostic, SpanDiagnosticExt as _};
use quote::quote;
use syn::{ItemFn, spanned::Spanned as _};

pub(crate) struct SockOps {
    item: ItemFn,
}

impl SockOps {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<Self, Diagnostic> {
        if !attrs.is_empty() {
            return Err(attrs.span().error("unexpected attribute"));
        }
        let item = syn::parse2(item)?;
        Ok(Self { item })
    }

    pub(crate) fn expand(&self) -> TokenStream {
        let Self { item } = self;
        let ItemFn {
            attrs: _,
            vis,
            sig,
            block: _,
        } = item;
        let fn_name = &sig.ident;
        quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = "sockops")]
            #vis fn #fn_name(ctx: *mut ::aya_ebpf::bindings::bpf_sock_ops) -> u32 {
                return #fn_name(::aya_ebpf::programs::SockOpsContext::new(ctx));

                #item
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use syn::parse_quote;

    use super::*;

    #[test]
    fn test_sock_ops() {
        let prog = SockOps::parse(
            parse_quote! {},
            parse_quote! {
                fn prog(ctx: &mut ::aya_ebpf::programs::SockOpsContext) -> u32 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = "sockops")]
            fn prog(ctx: *mut ::aya_ebpf::bindings::bpf_sock_ops) -> u32 {
                return prog(::aya_ebpf::programs::SockOpsContext::new(ctx));

                fn prog(ctx: &mut ::aya_ebpf::programs::SockOpsContext) -> u32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }
}
