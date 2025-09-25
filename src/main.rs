mod elf;
mod hooks;
mod stubs;
mod uc;

use anyhow::Result;
use env_logger::Env;
use log::LevelFilter;
use std::io::{self, Write};
use std::path::PathBuf;
use unicorn_engine_sys::Prot;


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
    // ---

    let uc = unsafe { uc::Uc::new_arm64()? };

    unsafe {
        uc.map(STACK_TOP - STACK_SIZE, STACK_SIZE, Prot::ALL)?;
        uc.set_sp(STACK_TOP)?;
    }

    let lib = unsafe { elf::load_and_collect(&uc, &lib_path.to_string_lossy(), LIB_BASE)? };
    let ta = unsafe { elf::load_and_collect(&uc, &ta_path.to_string_lossy(), TA_BASE)? };

    loop {
        println!("
[*] Target: {}", ta_path.display());
        println!("[*] Library: {}", lib_path.display());
        println!("---");
        println!("1. List library symbols");
        println!("2. List TA symbols");
        println!("3. (Not implemented)");
        println!("q. Quit");
        print!("> ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        match input.trim() {
            "1" => {
                println!("\n--- Library Symbols ---");
                let mut symbols: Vec<_> = lib.dynsyms.keys().collect();
                symbols.sort();
                for sym in symbols {
                    println!("{}", sym);
                }
                println!("-----------------------");
            }
            "2" => {
                println!("\n--- TA Symbols ---");
                let mut symbols: Vec<_> = ta.dynsyms.keys().collect();
                symbols.sort();
                for sym in symbols {
                    println!("{}", sym);
                }
                println!("--------------------");
            }
            "3" => {
                println!("\nOption 3 is not implemented yet.");
            }
            "q" => {
                break;
            }
            _ => {
                println!("\nInvalid option.");
            }
        }
    }

    eprintln!("\n[*] done");

    Ok(())
}
