//! Type definition code generation.
//!
//! Generates `#[contracttype]` structs and enums, `#[contracterror]` error
//! enums, `#[soroban_sdk::contractevent]` event structs, and maps
//! [`ScSpecTypeDef`] to Rust type tokens.

use proc_macro2::{Literal, TokenStream};
use quote::{format_ident, quote};
use stellar_xdr::curr as stellar_xdr;
use stellar_xdr::{
    ScSpecEventParamLocationV0, ScSpecEventV0, ScSpecTypeDef, ScSpecUdtEnumV0,
    ScSpecUdtErrorEnumV0, ScSpecUdtStructV0, ScSpecUdtUnionCaseV0, ScSpecUdtUnionV0,
};

pub(super) fn gen_struct(spec: &ScSpecUdtStructV0) -> TokenStream {
    let ident = format_ident!("{}", spec.name.to_utf8_string_lossy());

    if spec.lib.len() > 0 {
        let lib_ident = format_ident!("{}", spec.lib.to_utf8_string_lossy());
        return quote! { type #ident = ::#lib_ident::#ident; };
    }

    let is_tuple = spec
        .fields
        .iter()
        .all(|f| f.name.to_utf8_string_lossy().parse::<usize>().is_ok());

    if is_tuple {
        let fields = spec.fields.iter().map(|f| {
            let f_type = gen_type_ident(&f.type_);
            quote! { pub #f_type }
        });
        quote! {
            #[contracttype]
            #[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
            pub struct #ident(#(#fields),*);
        }
    } else {
        let fields = spec.fields.iter().map(|f| {
            let f_ident = format_ident!("{}", f.name.to_utf8_string_lossy());
            let f_type = gen_type_ident(&f.type_);
            quote! { pub #f_ident: #f_type }
        });
        quote! {
            #[contracttype]
            #[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
            pub struct #ident { #(#fields,)* }
        }
    }
}

pub(super) fn gen_union(spec: &ScSpecUdtUnionV0) -> TokenStream {
    let ident = format_ident!("{}", spec.name.to_utf8_string_lossy());

    if spec.lib.len() > 0 {
        let lib_ident = format_ident!("{}", spec.lib.to_utf8_string_lossy());
        return quote! { pub type #ident = ::#lib_ident::#ident; };
    }

    let variants = spec.cases.iter().map(|c| match c {
        ScSpecUdtUnionCaseV0::VoidV0(v) => {
            let v_ident = format_ident!("{}", v.name.to_utf8_string_lossy());
            quote! { #v_ident }
        }
        ScSpecUdtUnionCaseV0::TupleV0(t) => {
            let v_ident = format_ident!("{}", t.name.to_utf8_string_lossy());
            let v_types = t.type_.iter().map(|ty| gen_type_ident(ty));
            quote! { #v_ident(#(#v_types),*) }
        }
    });

    quote! {
        #[contracttype]
        #[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
        pub enum #ident { #(#variants,)* }
    }
}

pub(super) fn gen_enum(spec: &ScSpecUdtEnumV0) -> TokenStream {
    let ident = format_ident!("{}", spec.name.to_utf8_string_lossy());

    if spec.lib.len() > 0 {
        let lib_ident = format_ident!("{}", spec.lib.to_utf8_string_lossy());
        return quote! { pub type #ident = ::#lib_ident::#ident; };
    }

    let variants = spec.cases.iter().map(|c| {
        let v_ident = format_ident!("{}", c.name.to_utf8_string_lossy());
        let v_value = Literal::u32_unsuffixed(c.value);
        quote! { #v_ident = #v_value }
    });

    quote! {
        #[contracttype]
        #[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
        pub enum #ident { #(#variants,)* }
    }
}

pub(super) fn gen_error_enum(spec: &ScSpecUdtErrorEnumV0) -> TokenStream {
    let ident = format_ident!("{}", spec.name.to_utf8_string_lossy());

    if spec.lib.len() > 0 {
        let lib_ident = format_ident!("{}", spec.lib.to_utf8_string_lossy());
        return quote! { pub type #ident = ::#lib_ident::#ident; };
    }

    let variants = spec.cases.iter().map(|c| {
        let v_ident = format_ident!("{}", c.name.to_utf8_string_lossy());
        let v_value = Literal::u32_unsuffixed(c.value);
        quote! { #v_ident = #v_value }
    });

    quote! {
        #[contracterror]
        #[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
        pub enum #ident { #(#variants,)* }
    }
}

pub(super) fn gen_event(spec: &ScSpecEventV0) -> TokenStream {
    let ident = format_ident!("{}", spec.name.to_utf8_string_lossy());

    if spec.lib.len() > 0 {
        let lib_ident = format_ident!("{}", spec.lib.to_utf8_string_lossy());
        return quote! { type #ident = ::#lib_ident::#ident; };
    }

    let fields = spec.params.iter().map(|p| {
        let p_ident = format_ident!("{}", p.name.to_utf8_string_lossy());
        let p_type = gen_type_ident(&p.type_);
        match p.location {
            ScSpecEventParamLocationV0::TopicList => quote! {
                #[topic]
                pub #p_ident: #p_type
            },
            ScSpecEventParamLocationV0::Data => quote! {
                pub #p_ident: #p_type
            },
        }
    });

    quote! {
        #[soroban_sdk::contractevent]
        #[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
        pub struct #ident { #(#fields,)* }
    }
}

/// Maps an [`ScSpecTypeDef`] to its corresponding Rust type as a [`TokenStream`].
pub(crate) fn gen_type_ident(spec: &ScSpecTypeDef) -> TokenStream {
    match spec {
        ScSpecTypeDef::Val => quote! { soroban_sdk::Val },
        ScSpecTypeDef::U64 => quote! { u64 },
        ScSpecTypeDef::I64 => quote! { i64 },
        ScSpecTypeDef::U32 => quote! { u32 },
        ScSpecTypeDef::I32 => quote! { i32 },
        ScSpecTypeDef::U128 => quote! { u128 },
        ScSpecTypeDef::I128 => quote! { i128 },
        ScSpecTypeDef::Bool => quote! { bool },
        ScSpecTypeDef::Symbol => quote! { Symbol },
        ScSpecTypeDef::Error => {
            quote! { soroban_sdk::Error }
        }
        ScSpecTypeDef::Bytes => quote! { Bytes },
        ScSpecTypeDef::Address => quote! { Address },
        ScSpecTypeDef::MuxedAddress => quote! { MuxedAddress },
        ScSpecTypeDef::String => quote! { String },
        ScSpecTypeDef::Option(o) => {
            let value_ident = gen_type_ident(&o.value_type);
            quote! { Option<#value_ident> }
        }
        ScSpecTypeDef::Result(r) => {
            let ok_ident = gen_type_ident(&r.ok_type);
            let error_ident = gen_type_ident(&r.error_type);
            quote! { Result<#ok_ident, #error_ident> }
        }
        ScSpecTypeDef::Vec(v) => {
            let element_ident = gen_type_ident(&v.element_type);
            quote! { Vec<#element_ident> }
        }
        ScSpecTypeDef::Map(m) => {
            let key_ident = gen_type_ident(&m.key_type);
            let value_ident = gen_type_ident(&m.value_type);
            quote! { Map<#key_ident, #value_ident> }
        }
        ScSpecTypeDef::Tuple(t) => {
            let type_idents = t.value_types.iter().map(|ty| gen_type_ident(ty));
            quote! { (#(#type_idents,)*) }
        }
        ScSpecTypeDef::BytesN(b) => {
            let n = Literal::u32_unsuffixed(b.n);
            quote! { BytesN<#n> }
        }
        ScSpecTypeDef::Udt(u) => {
            let ident = format_ident!("{}", u.name.to_utf8_string_lossy());
            quote! { #ident }
        }
        ScSpecTypeDef::Void => quote! { () },
        ScSpecTypeDef::Timepoint => quote! { Timepoint },
        ScSpecTypeDef::Duration => quote! { Duration },
        ScSpecTypeDef::U256 => quote! { U256 },
        ScSpecTypeDef::I256 => quote! { I256 },
    }
}
