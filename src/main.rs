mod elf;
mod hooks;
mod stubs;
mod uc;

use anyhow::Result;
use env_logger::Env;
use log::LevelFilter;
use unicorn_engine_sys::Prot;

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

    // unicorn start
    let uc = unsafe { uc::Uc::new_arm64()? };

    // stack
    unsafe {
        uc.map(STACK_TOP - STACK_SIZE, STACK_SIZE, Prot::ALL)?;
        uc.set_sp(STACK_TOP)?;
    }

    // load ta, lib
    let lib = unsafe { elf::load_and_collect(&uc, "blobs/libcmnlib.so", LIB_BASE)? };
    eprintln!("[lib] dynsyms = {}", lib.dynsyms.len());

    let ta = unsafe { elf::load_and_collect(&uc, "blobs/widevine.elf", TA_BASE)? };
    eprintln!("[ta ] got_relocs = {}", ta.got_relocs.len());

    // dump got table
    unsafe { elf::dump_got_table(&uc, &ta)? };

    // stub
    let mut stubspace = unsafe { stubs::StubSpace::new(&uc, STUB_BASE, STUB_SIZE)? };

    // jump slot; glob_dat patch only
    let plt_like: Vec<(u64, String)> = ta
        .got_relocs
        .iter()
        .filter(|(_, _, ty)| *ty == R_AARCH64_JUMP_SLOT || *ty == R_AARCH64_GLOB_DAT)
        .map(|(a, n, _)| (*a, n.clone()))
        .collect();

    unsafe { stubs::patch_got_with_lib_or_stub(&uc, &plt_like, &lib.dynsyms, &mut stubspace)? };

    // dump got after patching
    unsafe { elf::dump_got_table(&uc, &ta)? };

    // got hook
    let _h1 = unsafe { hooks::install_unmapped_hook(uc.raw)? };
    let _h2 = unsafe { hooks::install_invalid_insn_hook(uc.raw)? };
    let _h3 = unsafe { hooks::install_intr_hook(uc.raw)? };

    // execute
    use unicorn_engine_sys::RegisterARM64;

    // 1. Call i_widevine_oemcrypto_initialize
    const INIT_FUNCTION: &str = "i_widevine_oemcrypto_initialize";
    if let Some(addr) = ta.dynsyms.get(INIT_FUNCTION) {
        eprintln!("\n[*] Calling initialization function: `{}` at {:#x}", INIT_FUNCTION, addr);
        unsafe { uc.start_icount(*addr, 1000)? };
        let init_ret_val = unsafe { uc.reg_read(RegisterARM64::X0 as i32)? };
        eprintln!("[+] Initialization finished. Return value (x0) = {:#x}", init_ret_val);
    } else {
        eprintln!("\n[*] Could not find initialization function `{}`", INIT_FUNCTION);
    }

    // 2. Call i_widevine_oemcrypto_get_api_version
    const TARGET_FUNCTION: &str = "i_widevine_oemcrypto_get_api_version";
    if let Some(addr) = ta.dynsyms.get(TARGET_FUNCTION) {
        eprintln!("\n[*] Calling target function: `{}` at {:#x}", TARGET_FUNCTION, addr);
        unsafe { uc.start_icount(*addr, 100)? };
        let ret_val = unsafe { uc.reg_read(RegisterARM64::X0 as i32)? };
        eprintln!("[+] Target function finished. Return value (x0) = {:#x} ({})", ret_val, ret_val);

        // Check if the return value is a plausible pointer and read memory
        if ret_val >= TA_BASE {
            eprintln!("[*] Return value looks like a pointer. Reading 16 bytes at {:#x}...", ret_val);
            match unsafe { uc.read_bytes(ret_val, 16) } {
                Ok(bytes) => {
                    // Try to print as a string
                    let s = String::from_utf8_lossy(&bytes);
                    eprintln!("[+] Memory content (as string): \"{}\"", s.trim_end_matches('\0'));
                    // Print as hex as well
                    eprintln!("[+] Memory content (as hex): {:02x?}", bytes);
                }
                Err(e) => {
                    eprintln!("[!] Failed to read memory: {}", e);
                }
            }
        }
    } else {
        eprintln!("\n[*] Could not find target function `{}`", TARGET_FUNCTION);
    }

    eprintln!("\n[*] done");

    Ok(())
}
