use proc_macro::TokenStream;

use quote::quote;
use syn::{parse_macro_input, ItemFn};

#[proc_macro_attribute]
pub fn hook(_: TokenStream, input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as ItemFn);
    let ItemFn {
        attrs,
        vis,
        sig,
        block,
    } = input;

    let stmts = &block.stmts;
    let args = &sig.inputs;
    let ret = &sig.output;

    let quoted = quote! {
        #(#attrs)* #vis #sig {
            type RecallType = fn(#args) #ret;
            let recall: RecallType = std::mem::transmute::<usize, RecallType>(*TEST_RECALL.get().unwrap());

            #(#stmts)*
        }
    };

    TokenStream::from(quoted)
}
