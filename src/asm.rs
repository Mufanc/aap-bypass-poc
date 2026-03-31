#[macro_export]
macro_rules! arm64asm {
     ($ops:ident $($t:tt)*) => {
         {
             #[allow(unused_imports)]
             use dynasmrt::{dynasm, DynasmApi, DynasmLabelApi};

             dynasm!($ops
                 ; .arch aarch64
                 ; .alias xtmp, x17
                 $($t)*
             )
         }
     }
}
