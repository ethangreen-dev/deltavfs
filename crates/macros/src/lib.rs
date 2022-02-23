use proc_macro::TokenStream;

use quote::{format_ident, quote};
use syn::{parse_macro_input, ItemFn, AttributeArgs};

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
