mod asm;
mod properties;

use anyhow::anyhow;
use dynasmrt::VecAssembler;
use dynasmrt::aarch64::Aarch64Relocation;
use log::info;
use nix::libc::pid_t;
use nix::unistd::{SysconfVar, sysconf};
use object::elf::PF_X;
use object::{Object, ObjectSegment, SegmentFlags};
use procfs::process::{MMapPath, Process};
use r3solvr::{BasicResolver, Query, SymbolResolver};
use std::sync::LazyLock;
use std::{env, fs};

static PAGE_SIZE: LazyLock<u64> =
    LazyLock::new(|| sysconf(SysconfVar::PAGE_SIZE).unwrap().unwrap() as u64);

fn get_audio_server_pid() -> anyhow::Result<pid_t> {
    properties::get("init.svc_debug_pid.audioserver")
        .ok_or_else(|| anyhow::anyhow!("failed to read property"))
        .and_then(|value| {
            value
                .parse::<i32>()
                .map_err(|err| anyhow!("failed to parse pid: {err}"))
        })
}

fn branch_to(shellcode_addr: u64) -> anyhow::Result<Vec<u8>> {
    let mut ops: VecAssembler<Aarch64Relocation> = VecAssembler::new(0);

    arm64asm!(ops
        ; ldr xtmp, #8
        ; br xtmp
        ;; ops.push_u64(shellcode_addr)
    );

    Ok(ops.finalize()?)
}

fn shellcode(func_addr: u64) -> anyhow::Result<Vec<u8>> {
    let mut ops: VecAssembler<Aarch64Relocation> = VecAssembler::new(0);

    arm64asm!(ops
        ; cmp x2, #0
        ; cinc x2, x2, eq
        ; ldr xtmp, #8
        ; br xtmp
        ;; ops.push_u64(func_addr + 16)
    );

    Ok(ops.finalize()?)
}

fn main() -> anyhow::Result<()> {
    unsafe {
        env::set_var("RUST_LOG", "debug");
    }

    env_logger::init();

    let pid = get_audio_server_pid()?;
    let proc = Process::new(pid)?;

    // 1. find the path and base addr of libaudiopolicy.so
    let mut lib_path = None;
    let mut base_addr = 0u64;

    for map in proc.maps()? {
        let MMapPath::Path(pathname) = &map.pathname else {
            continue;
        };

        if pathname
            .file_name()
            .is_some_and(|name| name == "libaudiopolicyservice.so")
        {
            lib_path = Some(pathname.clone());
            base_addr = map.address.0;
            break;
        }
    }

    let lib_path = lib_path.ok_or_else(|| anyhow!("libaudiopolicyservice.so not found"))?;

    info!("library: {}", lib_path.display());
    info!("base addr: {:#x}", base_addr);

    // 2. parse ELF to find mmap holes in executable segments
    let data = fs::read(&lib_path)?;
    let file = object::File::parse(data.as_slice())?;

    for segment in file.segments() {
        let SegmentFlags::Elf { p_flags } = segment.flags() else {
            continue;
        };

        if p_flags & PF_X == 0 {
            continue;
        }

        let (memory_offset, memory_size) = (segment.address(), segment.size());

        let vm_start = memory_offset & !(*PAGE_SIZE - 1);
        let vm_end = (memory_offset + memory_size).div_ceil(*PAGE_SIZE) * *PAGE_SIZE;

        info!(
            "executable segment: {:#x}-{:#x}",
            memory_offset,
            memory_offset + memory_size
        );

        if vm_start < memory_offset {
            let hole_size = memory_offset - vm_start;
            info!(
                "hole before segment: addr={:#x}, size={} bytes",
                base_addr + vm_start,
                hole_size
            );
        } else {
            info!("no hole before segment");
        }

        if vm_end > memory_offset + memory_size {
            let hole_size = vm_end - (memory_offset + memory_size);
            info!(
                "hole after segment: addr={:#x}, size={} bytes",
                base_addr + memory_offset + memory_size,
                hole_size
            );
        } else {
            info!("no hole after segment");
        }
    }

    // 3. inline hook android::AudioPolicyService::setAppState_l

    let func_offset = {
        let resolver = BasicResolver::from_file(lib_path)?;
        resolver.lookup_symbol(Query::new("_ZN7android18AudioPolicyService13setAppState_lENS_2spINS_5media11audiopolicy17AudioRecordClientEEE11app_state_t").with_debugdata(true))?.addr as u64
    };

    info!(
        "AudioPolicyService::setAppState_l offset: {:#x}",
        func_offset
    );

    // Todo:
    // 1. open proc/pid/maps
    // 2. find a hole enough to write shellcode (instructions should align to 4 bytes)
    // 3. write shellcode to hole, remember shell code address
    // 4. write branch to base_addr + func_offset, branch to shellcode
    // 5. all memory writes use writev to finish

    Ok(())
}
