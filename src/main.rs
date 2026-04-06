mod asm;
mod properties;
use anyhow::{anyhow, ensure};
use log::{debug, info};
use nix::libc::pid_t;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use nix::unistd::{SysconfVar, sysconf};
use object::elf::PF_X;
use object::{Object, ObjectSegment, SegmentFlags};
use procfs::process::{MMapPath, Process};
use r3solvr::{BasicResolver, Query, SymbolResolver};
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Seek, SeekFrom, Write as _};
use std::path::PathBuf;
use std::sync::LazyLock;

static PAGE_SIZE: LazyLock<u64> =
    LazyLock::new(|| sysconf(SysconfVar::PAGE_SIZE).unwrap().unwrap() as u64);

const TARGET_SYMBOL: &str = "_ZN7android18AudioPolicyService13setAppState_lENS_2spINS_5media11audiopolicy17AudioRecordClientEEE11app_state_t";

fn read_mem(pid: pid_t, addr: u64, buffer: &mut [u8]) -> anyhow::Result<()> {
    let mut file = File::open(format!("/proc/{pid}/mem"))?;

    file.seek(SeekFrom::Start(addr))?;
    file.read_exact(buffer)?;

    Ok(())
}

fn write_mem(pid: pid_t, addr: u64, data: &[u8]) -> anyhow::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .open(format!("/proc/{pid}/mem"))?;

    file.seek(SeekFrom::Start(addr))?;
    file.write_all(data)?;

    Ok(())
}

fn find_audio_server() -> anyhow::Result<pid_t> {
    properties::get("init.svc_debug_pid.audioserver")
        .ok_or_else(|| anyhow::anyhow!("failed to read property"))
        .and_then(|value| {
            value
                .parse::<i32>()
                .map_err(|err| anyhow!("failed to parse pid: {err}"))
        })
}

fn find_library(proc: &Process, name: &str) -> anyhow::Result<(PathBuf, u64)> {
    for map in proc.maps()? {
        let MMapPath::Path(pathname) = &map.pathname else {
            continue;
        };

        if pathname.file_name().is_some_and(|n| n == name) {
            info!("library: {}", pathname.display());
            info!("base addr: {:#x}", map.address.0);
            return Ok((pathname.clone(), map.address.0));
        }
    }

    Err(anyhow!("{name} not found"))
}

fn find_executable_holes(elf_data: &[u8], base_addr: u64) -> anyhow::Result<Vec<(u64, u64)>> {
    let file = object::File::parse(elf_data)?;
    let mut holes: Vec<(u64, u64)> = Vec::new();

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
            holes.push((base_addr + vm_start, hole_size));
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
            holes.push((base_addr + memory_offset + memory_size, hole_size));
        } else {
            info!("no hole after segment");
        }
    }

    Ok(holes)
}

fn analyze_hook_point(pid: pid_t, func_addr: u64) -> anyhow::Result<(u64, u64, [u8; 4])> {
    let mut buffer = [0u8; 4];
    read_mem(pid, func_addr, &mut buffer)?;

    let first_insn = u32::from_le_bytes(buffer);
    let hook_addr = if asm::is_pacia_insn(first_insn) {
        debug!("found PACIA instruction at function entry, skipping...");
        func_addr + 4
    } else {
        func_addr
    };

    let mut backup = [0u8; 4];
    if hook_addr == func_addr {
        backup = buffer;
    } else {
        read_mem(pid, hook_addr, &mut backup)?;
    }
    let hook_insn = u32::from_le_bytes(backup);

    ensure!(
        !asm::is_pc_rel_insn(hook_insn),
        "instruction at hook point ({hook_insn:#010x}) is PC-relative, cannot safely replace"
    );

    let return_addr = hook_addr + 4;

    Ok((hook_addr, return_addr, backup))
}

fn find_shellcode_slot(holes: &[(u64, u64)], size: u64) -> anyhow::Result<u64> {
    holes
        .iter()
        .filter_map(|&(addr, hole_size)| {
            let aligned_addr = (addr + 3) & !3;
            let padding = aligned_addr - addr;

            if hole_size <= padding {
                return None;
            }

            let available = hole_size - padding;

            if available >= size {
                Some(aligned_addr)
            } else {
                None
            }
        })
        .next()
        .ok_or_else(|| anyhow!("no suitable hole found"))
}

fn inject_hook(
    pid: pid_t,
    shellcode_addr: u64,
    shellcode: &[u8],
    hook_addr: u64,
    branch: &[u8],
) -> anyhow::Result<()> {
    let nix_pid = Pid::from_raw(pid);

    // stop the target process to avoid race conditions
    kill(nix_pid, Signal::SIGSTOP)?;

    // write shellcode to hole first
    write_mem(pid, shellcode_addr, shellcode)?;

    // then write branch trampoline to function entry
    write_mem(pid, hook_addr, branch)?;

    // resume the target process
    kill(nix_pid, Signal::SIGCONT)?;

    Ok(())
}

fn main() -> anyhow::Result<()> {
    env_logger::init();

    let pid = find_audio_server()?;
    let proc = Process::new(pid)?;
    info!("audio server pid: {}", pid);

    let (lib_path, base_addr) = find_library(&proc, "libaudiopolicyservice.so")?;

    let elf_data = fs::read(&lib_path)?;
    let holes = find_executable_holes(&elf_data, base_addr)?;

    // resolve target function symbol
    let func_offset = {
        let resolver = BasicResolver::from_data(elf_data)?;
        resolver
            .lookup_symbol(Query::new(TARGET_SYMBOL).with_debugdata(true))?
            .addr as u64
    };
    let func_addr = base_addr + func_offset;
    info!(
        "AudioPolicyService::setAppState_l: {:#x} (offset {:#x})",
        func_addr, func_offset
    );

    let (hook_addr, return_addr, backup) = analyze_hook_point(pid, func_addr)?;

    let shellcode_size = asm::shellcode(0, 0, &backup)?.len() as u64;
    let shellcode_addr = find_shellcode_slot(&holes, shellcode_size)?;
    info!("shellcode addr: {:#x}", shellcode_addr);

    let shellcode = asm::shellcode(shellcode_addr, return_addr, &backup)?;

    let branch = asm::encode_branch(hook_addr, shellcode_addr)?;

    inject_hook(pid, shellcode_addr, &shellcode, hook_addr, &branch)?;

    info!("hook installed!");
    Ok(())
}
