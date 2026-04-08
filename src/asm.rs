use anyhow::ensure;
use dynasmrt::aarch64::Aarch64Relocation;
use dynasmrt::{DynasmApi, VecAssembler};
use log::info;

#[macro_export]
macro_rules! arm64asm {
     ($ops:ident $($t:tt)*) => {
         {
             #[allow(unused_imports)]
             use dynasmrt::{dynasm, DynasmApi, DynasmLabelApi};

             dynasm!($ops
                 ; .arch aarch64
                 ; .alias xtm, x17
                 ; .alias wtm, w17
                 $($t)*
             )
         }
     }
}

pub fn is_pc_rel_insn(insn: u32) -> bool {
    // Branch instructions (B, BL, B_COND)
    (insn & 0xFC000000) == 0x14000000 || // B
    (insn & 0xFF000010) == 0x54000000 || // B_COND
    (insn & 0xFC000000) == 0x94000000 || // BL

    // Address generation instructions (ADR, ADRP)
    (insn & 0x9F000000) == 0x10000000 || // ADR
    (insn & 0x9F000000) == 0x90000000 || // ADRP

    // Literal load instructions (LDR_LIT)
    (insn & 0xFF000000) == 0x18000000 || // LDR_LIT_32
    (insn & 0xFF000000) == 0x58000000 || // LDR_LIT_64
    (insn & 0xFF000000) == 0x98000000 || // LDRSW_LIT
    (insn & 0xFF000000) == 0xD8000000 || // PRFM_LIT
    (insn & 0xFF000000) == 0x1C000000 || // LDR_SIMD_LIT_32
    (insn & 0xFF000000) == 0x5C000000 || // LDR_SIMD_LIT_64
    (insn & 0xFF000000) == 0x9C000000 || // LDR_SIMD_LIT_128

    // Conditional branch instructions (CBZ, CBNZ, TBZ, TBNZ)
    (insn & 0x7F000000) == 0x34000000 || // CBZ
    (insn & 0x7F000000) == 0x35000000 || // CBNZ
    (insn & 0x7F000000) == 0x36000000 || // TBZ
    (insn & 0x7F000000) == 0x37000000 // TBNZ
}

pub fn is_pacia_insn(insn: u32) -> bool {
    (insn & 0xFFFFDC00) == 0xDAC10000 || // PACIA, PACIZA
    (insn & 0xFFFFFDDF) == 0xD503211F // PACIA1716, PACIASP, PACIAZ
}

pub fn check_branch_offset(offset: i64) -> anyhow::Result<()> {
    ensure!(
        (-(1 << 25)..(1 << 25)).contains(&offset),
        "branch target out of range: offset={offset}"
    );

    Ok(())
}

pub fn encode_branch(src: u64, dst: u64) -> anyhow::Result<Vec<u8>> {
    let offset = dst as i64 - src as i64;

    check_branch_offset(offset)?;

    info!("branch offset: {offset:#x}");

    let mut ops: VecAssembler<Aarch64Relocation> = VecAssembler::new(0);

    arm64asm!(ops
        ; b #offset as i32
    );

    Ok(ops.finalize()?)
}

pub fn shellcode(shellcode_addr: u64, return_addr: u64, backup: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut ops: VecAssembler<Aarch64Relocation> = VecAssembler::new(0);

    arm64asm!(ops
        // https://cs.android.com/android/platform/superproject/+/android-latest-release:frameworks/av/services/audiopolicy/service/AudioPolicyService.cpp;l=1245-1274;drc=277d3cc7a0bcb34146e142736321c99faaac0500
        // if *((int *) (client + 0x12c)) == 0 && state == 0 {
        //     state = 1;
        // }
        ; ldr xtm, [x1]  // https://itanium-cxx-abi.github.io/cxx-abi/abi.html#non-trivial-parameters
        ; ldr wtm, [xtm, #0x12c]  // load uid from: 0x12c offset + 0x8 vptr + 0x4 pid
        // ; cmp wtm, #1000
        // ; b.gt >skip
        ; cbnz wtm, >skip
        ; cmp x2, #0
        ; cinc x2, x2, eq
        ; skip:
        ;; ops.extend(backup)
    );

    let offset = return_addr as i64 - (shellcode_addr + ops.offset().0 as u64) as i64;
    check_branch_offset(offset)?;
    info!("return offset: {offset:#x}");

    arm64asm!(ops
        ; b #offset as i32
    );

    Ok(ops.finalize()?)
}
