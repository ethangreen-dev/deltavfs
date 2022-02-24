extern crate core;

use proc_macro::TokenStream;

use quote::{format_ident, quote};
use syn::{parse_macro_input, ItemFn, AttributeArgs, Block, braced, Token, ItemImpl, ImplItem};
use syn::Item::Impl;

#[proc_macro_attribute]
pub fn define_hook(args: TokenStream, input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as ItemFn);
    let args = parse_macro_input!(args as AttributeArgs);

    let ItemFn {
        attrs,
        vis,
        sig,
        block,
    } = input;

    let module = args.get(0).expect("Expected module name, got nothing.");
    let func = args.get(1).expect("Expected function name, got nothing.");

    let stmts = &block.stmts;
    let args = &sig.inputs;
    let ret = &sig.output;
    let name = &sig.ident;

    let init_name = format_ident!("{}_init", &sig.ident);
    let recall_name = format_ident!("{}_RECALL", &sig.ident);

    let quoted = quote! {
        #(#attrs)* #vis #sig {
            type RecallType = fn(#args) #ret;
            let recall: RecallType = ::std::mem::transmute::<usize, RecallType>(*#recall_name.get().unwrap());

            #(#stmts)*
        }

        static #recall_name: ::once_cell::sync::OnceCell<usize> = ::once_cell::sync::OnceCell::new();

        fn #init_name() {
            unsafe {
                let target_addr = crate::pe::get_func_addr(#module, #func).unwrap();
                let recall = crate::hook::install_hook(target_addr, #name as _).unwrap();

                #recall_name.set(recall as _).expect("Failed to set recall value for #recall_name.")
            }
        }
    };

    TokenStream::from(quoted)
}

#[proc_macro_attribute]
pub fn define_hook_test(args: TokenStream, input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as ItemFn);
    let args = parse_macro_input!(args as AttributeArgs);

    let ItemFn {
        attrs,
        vis,
        sig,
        block,
    } = input;

    let module = args.get(0).expect("Expected module name, got nothing.");
    let func = args.get(1).expect("Expected function name, got nothing.");

    let stmts = &block.stmts;
    let args = &sig.inputs;
    let ret = &sig.output;
    let name = &sig.ident;

    let init_name = format_ident!("{}_init", &sig.ident);
    let recall_name = format_ident!("{}_RECALL", &sig.ident);

    let quoted = quote! {
        static #recall_name: ::once_cell::sync::OnceCell<fn(#args) #ret> = ::once_cell::sync::OnceCell::new();

        #(#attrs)* #vis #sig {
            type RecallType = fn(#args) #ret;
            let recall: fn(#args) #ret = #recall_name.get().unwrap();

            #(#stmts)*
        }

        fn #init_name() {
            unsafe {
                let target_addr = crate::pe::get_func_addr(#module, #func).unwrap();
                let recall_addr = crate::hook::install_hook(target_addr, #name as _).unwrap();

                type RecallType = fn(#args) #ret;
                let recall: RecallType = ::std::mem::transmute::<usize, fn(#args) #ret>(recall_addr as _);

                #recall_name.set(recall).expect("Failed to set recall value for #recall_name.")
            }
        }
    };

    TokenStream::from(quoted)
}

#[proc_macro_attribute]
pub fn test_struct_hook(args: TokenStream, input: TokenStream) -> TokenStream {
    // This macro will be placed before a struct, so the first token will be the struct itself.
    let struct_token = parse_macro_input!(input as ItemImpl);
    let struct_items = struct_token.items;

    // Iterate through each function, validating `fn hook()` is defined and parsing its TokenStream.
    let hook_token = struct_items.iter()
        .find(|item| match item {
            ImplItem::Method(item) => true && item.sig.ident == "hook",
            _ => false
        });

    // let hook_token = {
    //     for item in struct_items {
    //         let impl_item = match item {
    //             ImplItem::Method(x) => x,
    //             _ => continue
    //         };

    //         if impl_item.sig.ident != "hook" {
    //             continue;
    //         }
    //     }
    // };

    args
}