mod elf;
mod hooks;
mod stubs;
mod uc;

use anyhow::Result;
use env_logger::Env;
use log::LevelFilter;
use std::collections::HashMap;
use std::path::PathBuf;
use unicorn_engine_sys::{Prot, RegisterARM64};

use goblin::elf::reloc::{R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT};

const STACK_TOP: u64 = 0x7fff_0000;
const STACK_SIZE: u64 = 2 * 1024 * 1024;

const TA_BASE: u64 = 0x4000_0000;
const LIB_BASE: u64 = 0x6000_0000;
const STUB_BASE: u64 = 0x5000_0000;
const STUB_SIZE: u64 = 0x10000;

fn main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info"))
        .filter_level(LevelFilter::Info)
        .init();

    // --- Argument Parsing ---
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        anyhow::bail!(
            "Usage: {} <directory_in_blobs>",
            args.get(0).map_or("ta_emul_test", |s| s.as_str())
        );
    }
    let target_dir_name = &args[1];
    let base_path = PathBuf::from("blobs").join(target_dir_name);

    if !base_path.is_dir() {
        anyhow::bail!("Error: Directory not found at {}", base_path.display());
    }

    let so_pattern = base_path.join("*.so").to_string_lossy().to_string();
    let elf_pattern = base_path.join("*.elf").to_string_lossy().to_string();

    let lib_path = glob::glob(&so_pattern)?
        .next()
        .ok_or_else(|| anyhow::anyhow!(".so file not found in {}", base_path.display()))??;

    let ta_path = glob::glob(&elf_pattern)?
        .next()
        .ok_or_else(|| anyhow::anyhow!(".elf file not found in {}", base_path.display()))??;

    eprintln!("[*] Using lib: {}", lib_path.display());
    eprintln!("[*] Using ta:  {}", ta_path.display());
    // ---

    let uc = unsafe { uc::Uc::new_arm64()? };

    unsafe {
        uc.map(STACK_TOP - STACK_SIZE, STACK_SIZE, Prot::ALL)?;
        uc.set_sp(STACK_TOP)?;
    }

    let lib = unsafe { elf::load_and_collect(&uc, &lib_path.to_string_lossy(), LIB_BASE)? };
    eprintln!("[lib] dynsyms = {}", lib.dynsyms.len());

    let ta = unsafe { elf::load_and_collect(&uc, &ta_path.to_string_lossy(), TA_BASE)? };
    eprintln!("[ta ] got_relocs = {}", ta.got_relocs.len());

    unsafe { elf::dump_got_table(&uc, &ta)? };

    let mut stubspace = unsafe { stubs::StubSpace::new(&uc, STUB_BASE, STUB_SIZE)? };

    let plt_like: Vec<(u64, String)> = ta
        .got_relocs
        .iter()
        .filter(|(_, _, ty)| *ty == R_AARCH64_JUMP_SLOT || *ty == R_AARCH64_GLOB_DAT)
        .map(|(a, n, _)| (*a, n.clone()))
        .collect();

    unsafe { stubs::patch_got_with_lib_or_stub(&uc, &plt_like, &lib.dynsyms, &mut stubspace)? };

    unsafe { elf::dump_got_table(&uc, &ta)? };

    let _h1 = unsafe { hooks::install_unmapped_hook(uc.raw)? };
    let _h2 = unsafe { hooks::install_invalid_insn_hook(uc.raw)? };
    let _h3 = unsafe { hooks::install_intr_hook(uc.raw)? };

    // --- Detailed tracing for a single function ---
    const TRACE_TARGET: &str = "TPM_QuoteInfo_Store";
    eprintln!("\n\n--- Detailed trace for function: `{}` ---", TRACE_TARGET);

    if let Some(&addr) = ta.dynsyms.get(TRACE_TARGET) {
        // Install tracing hooks
        let h_mem_trace = unsafe { hooks::install_mem_tracer(uc.raw)? };
        let h_code_trace = unsafe { hooks::install_code_tracer(uc.raw)? };

        eprintln!("[*] Starting trace run for `{}` at {:#x}", TRACE_TARGET, addr);

        // Reset state
        unsafe {
            uc.set_sp(STACK_TOP)?;
            uc.reg_write(RegisterARM64::X0 as i32, 0)?;
            uc.reg_write(RegisterARM64::X1 as i32, 0)?;
        }

        let exec_result = unsafe { uc.start_icount(addr, 500) };

        // Remove tracing hooks
        unsafe {
            uc.hook_del(h_mem_trace)?;
            uc.hook_del(h_code_trace)?;
        }

        match exec_result {
            Ok(_) => {
                let ret_val = unsafe { uc.reg_read(RegisterARM64::X0 as i32)? };
                eprintln!("\n[+] Execution finished normally.");
                eprintln!("[+] Return value (x0) = {:#x}", ret_val);
            }
            Err(e) => {
                eprintln!("\n[!] Execution failed: {}", e);
            }
        }
    } else {
        eprintln!("[!] Could not find function `{}` to trace.", TRACE_TARGET);
    }
    // ---

    eprintln!("\n[*] done");

    Ok(())
}
