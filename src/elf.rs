use anyhow::{Context, Result, bail};
use goblin::elf::dynamic::*;
use goblin::elf::reloc::{R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT};
use goblin::elf::{Elf, sym::STT_FUNC};
use std::collections::HashMap;
use unicorn_engine_sys::Prot;

use crate::uc::Uc;

// meta of memory-mapped elf
pub struct LoadedElf {
    pub path: String,
    pub entry: u64,                          // absolute addr
    pub dynsyms: HashMap<String, u64>,       // func name -> vaddr
    pub got_relocs: Vec<(u64, String, u32)>, // (GOT abs addr, symbol name, r_type)
}

fn page_down(x: u64) -> u64 {
    x & !0xfffu64
}
fn page_up(x: u64) -> u64 {
    (x + 0xfff) & !0xfffu64
}

fn vaddr_to_file_off(elf: &Elf, vaddr: u64) -> Option<usize> {
    for ph in &elf.program_headers {
        use goblin::elf::program_header::PT_LOAD;
        if ph.p_type != PT_LOAD {
            continue;
        }
        let p_vaddr = ph.p_vaddr;
        let p_offset = ph.p_offset;
        let p_filesz = ph.p_filesz;
        if vaddr >= p_vaddr && vaddr < p_vaddr + p_filesz {
            return Some((p_offset + (vaddr - p_vaddr)) as usize);
        }
    }
    None
}

/// extract DT_ tag map from PT_DYNAMIC, including vaddr value
fn parse_dynamic_tags(elf: &Elf, data: &[u8]) -> HashMap<i64, u64> {
    use goblin::elf::program_header::PT_DYNAMIC;
    let mut tags = HashMap::new();

    for ph in &elf.program_headers {
        if ph.p_type != PT_DYNAMIC {
            continue;
        }
        let off = ph.p_offset as usize;
        let size = ph.p_filesz as usize;
        let bytes = &data[off..off + size];

        // Elf64_Dyn: d_tag(i64) | d_val/d_ptr(u64)
        let mut i = 0usize;
        while i + 16 <= bytes.len() {
            let d_tag = i64::from_le_bytes(bytes[i..i + 8].try_into().unwrap());
            let d_val = u64::from_le_bytes(bytes[i + 8..i + 16].try_into().unwrap());
            i += 16;
            if d_tag == (DT_NULL as i64) {
                break;
            }
            tags.insert(d_tag, d_val);
        }
    }
    tags
}

/// parsing RELA table -> (r_offset, r_type, r_sym)
fn parse_rela_table(
    elf: &Elf,
    data: &[u8],
    rela_addr: u64,
    rela_sz: u64,
    rela_ent: u64,
) -> Vec<(u64, u32, usize)> {
    let Some(start_off) = vaddr_to_file_off(elf, rela_addr) else {
        return Vec::new();
    };
    let total = rela_sz as usize;
    let ent = if rela_ent == 0 { 24 } else { rela_ent as usize };
    let bytes = &data[start_off..start_off + total];

    let mut out = Vec::new();
    let mut i = 0usize;
    while i + ent <= bytes.len() {
        let r_offset = u64::from_le_bytes(bytes[i..i + 8].try_into().unwrap());
        let r_info = u64::from_le_bytes(bytes[i + 8..i + 16].try_into().unwrap());
        // let _addend = i64::from_le_bytes(bytes[i + 16..i + 24].try_into().unwrap());
        i += ent;
        let r_sym = (r_info >> 32) as usize;
        let r_type = (r_info & 0xffff_ffff) as u32;
        out.push((r_offset, r_type, r_sym));
    }
    out
}

/// parsing REL table -> (r_offset, r_type, r_sym)
fn parse_rel_table(
    elf: &Elf,
    data: &[u8],
    rel_addr: u64,
    rel_sz: u64,
    rel_ent: u64,
) -> Vec<(u64, u32, usize)> {
    // 파일 오프셋 변환
    let Some(start_off) = vaddr_to_file_off(elf, rel_addr) else {
        return Vec::new();
    };
    let total = rel_sz as usize;
    let ent = if rel_ent == 0 { 16 } else { rel_ent as usize };
    let bytes = &data[start_off..start_off + total];

    let mut out = Vec::new();
    let mut i = 0usize;
    while i + ent <= bytes.len() {
        // Elf64_Rel: r_offset(8) | r_info(8)
        let r_offset = u64::from_le_bytes(bytes[i..i + 8].try_into().unwrap());
        let r_info = u64::from_le_bytes(bytes[i + 8..i + 16].try_into().unwrap());
        i += ent;
        let r_sym = (r_info >> 32) as usize;
        let r_type = (r_info & 0xffff_ffff) as u32;
        out.push((r_offset, r_type, r_sym));
    }
    out
}

/// ELF를 base에 올리고, 동적 심볼/GOT 재배치 표 수집(PT_DYNAMIC 기반)
pub unsafe fn load_and_collect(uc: &Uc, path: &str, base: u64) -> Result<LoadedElf> {
    let data = std::fs::read(path).with_context(|| format!("read {}", path))?;
    let elf = Elf::parse(&data).context("ELF parse")?;

    // mapping PT_LOAD
    for ph in &elf.program_headers {
        use goblin::elf::program_header::{PF_W, PF_X, PT_LOAD};
        if ph.p_type != PT_LOAD {
            continue;
        }
        let off = ph.p_offset as usize;
        let filesz = ph.p_filesz as usize;
        let memsz = ph.p_memsz;
        let vaddr = ph.p_vaddr;

        if off + filesz > data.len() {
            bail!("bad phdr range");
        }
        let seg = &data[off..off + filesz];

        let start = page_down(base + vaddr);
        let end = page_up(base + vaddr + memsz);
        let size = end - start;

        unsafe {
            uc.map(start, size, Prot::ALL)?;
            uc.write(base + vaddr, seg)?;
        }

        let mut prot = Prot::READ;
        if (ph.p_flags & PF_W) != 0 {
            prot |= Prot::WRITE;
        }
        if (ph.p_flags & PF_X) != 0 {
            prot |= Prot::EXEC;
        }
        unsafe { uc.protect(start, size, prot)? };
    }

    let mut dynsyms = HashMap::new();
    for s in elf.dynsyms.iter() {
        if s.st_type() == STT_FUNC && s.st_value != 0 {
            if let Some(name) = elf.dynstrtab.get_at(s.st_name) {
                dynsyms.insert(name.to_string(), base + s.st_value);
            }
        }
    }
    for s in elf.syms.iter() {
        if s.st_type() == STT_FUNC && s.st_value != 0 {
            if let Some(name) = elf.strtab.get_at(s.st_name) {
                dynsyms.insert(name.to_string(), base + s.st_value);
            }
        }
    }

    let tags = parse_dynamic_tags(&elf, &data);

    // PLT-Side
    let jmprel_addr = tags.get(&(DT_JMPREL as i64)).copied();
    let pltrelsz = tags.get(&(DT_PLTRELSZ as i64)).copied().unwrap_or(0);
    let pltrel = tags.get(&(DT_PLTREL as i64)).copied(); // DT_REL or DT_RELA

    // Normal RELA/REL
    let rela_addr = tags.get(&(DT_RELA as i64)).copied();
    let relasz = tags.get(&(DT_RELASZ as i64)).copied().unwrap_or(0);
    let relaent = tags.get(&(DT_RELAENT as i64)).copied().unwrap_or(24);

    let rel_addr = tags.get(&(DT_REL as i64)).copied();
    let relsz = tags.get(&(DT_RELSZ as i64)).copied().unwrap_or(0);
    let relent = tags.get(&(DT_RELENT as i64)).copied().unwrap_or(16);

    let mut got_relocs_raw: Vec<(u64, u32, usize)> = Vec::new();

    // .plt
    if let (Some(addr), Some(kind)) = (jmprel_addr, pltrel) {
        if kind == (DT_RELA) {
            let list = parse_rela_table(&elf, &data, addr, pltrelsz, relaent);
            got_relocs_raw.extend(list);
        } else if kind == (DT_REL) {
            let list = parse_rel_table(&elf, &data, addr, pltrelsz, relent);
            got_relocs_raw.extend(list);
        }
    }

    // RELA
    if let Some(addr) = rela_addr {
        let list = parse_rela_table(&elf, &data, addr, relasz, relaent);
        got_relocs_raw.extend(list);
    }

    // REL
    if let Some(addr) = rel_addr {
        let list = parse_rel_table(&elf, &data, addr, relsz, relent);
        got_relocs_raw.extend(list);
    }

    // filter r_type and make abs addr (base + r_offset)
    let mut got_relocs: Vec<(u64, String, u32)> = Vec::new();
    for (r_off, r_type, r_sym) in got_relocs_raw {
        if r_type == R_AARCH64_JUMP_SLOT || r_type == R_AARCH64_GLOB_DAT {
            let got_abs = base + r_off;
            let name = elf
                .dynsyms
                .get(r_sym)
                .and_then(|s| elf.dynstrtab.get_at(s.st_name))
                .unwrap_or("<noname>")
                .to_string();
            got_relocs.push((got_abs, name, r_type));
        }
    }

    Ok(LoadedElf {
        path: path.to_string(),
        entry: base + elf.header.e_entry as u64,
        dynsyms,
        got_relocs,
    })
}

// dump GOT table : addr, type, symbol, current value
pub unsafe fn dump_got_table(uc: &Uc, elf: &LoadedElf) -> Result<()> {
    eprintln!("--- GOT table ({} entries) ---", elf.got_relocs.len());
    for (addr, name, rtype) in &elf.got_relocs {
        let val = unsafe { uc.read_u64(*addr)? };
        let t = match *rtype {
            R_AARCH64_JUMP_SLOT => "JUMP_SLOT",
            R_AARCH64_GLOB_DAT => "GLOB_DAT",
            _ => "OTHER",
        };
        eprintln!(
            "GOT {:#010x}  {:>10}  {:<32} -> {:#010x}",
            addr, t, name, val
        );
    }
    eprintln!("-------------------------------");
    Ok(())
}