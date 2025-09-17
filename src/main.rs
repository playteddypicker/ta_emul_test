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

    unsafe {
        // unicorn start
        let uc = uc::Uc::new_arm64()?;

        // stack
        uc.map(STACK_TOP - STACK_SIZE, STACK_SIZE, Prot::ALL)?;
        uc.set_sp(STACK_TOP)?;

        // load ta, lib
        let lib = elf::load_and_collect(&uc, "blobs/libcmnlib.so", LIB_BASE)?;
        eprintln!("[lib] dynsyms = {}", lib.dynsyms.len());

        let ta = elf::load_and_collect(&uc, "blobs/widevine.elf", TA_BASE)?;
        eprintln!("[ta ] got_relocs = {}", ta.got_relocs.len());

        // dump got table
        elf::dump_got_table(&uc, &ta)?;

        // stub
        let mut stubspace = stubs::StubSpace::new(&uc, STUB_BASE, STUB_SIZE)?;

        // jump slot; glob_dat patch only
        let plt_like: Vec<(u64, String)> = ta
            .got_relocs
            .iter()
            .filter(|(_, _, ty)| *ty == R_AARCH64_JUMP_SLOT || *ty == R_AARCH64_GLOB_DAT)
            .map(|(a, n, _)| (*a, n.clone()))
            .collect();

        stubs::patch_got_with_lib_or_stub(&uc, &plt_like, &lib.dynsyms, &mut stubspace)?;

        // dump got after patching
        elf::dump_got_table(&uc, &ta)?;

        // got hook
        let _h1 = hooks::install_unmapped_hook(uc.raw)?;
        let _h2 = hooks::install_invalid_insn_hook(uc.raw)?;
        let _h3 = hooks::install_intr_hook(uc.raw)?;

        // execute
        let entry = ta.entry;
        eprintln!("[*] entry = 0x{:x}", entry);
        uc.start_icount(entry, 10_000)?;

        eprintln!("[*] done");
    }

    Ok(())
}
