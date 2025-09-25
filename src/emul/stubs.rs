use anyhow::{Context, Result};
use std::collections::HashMap;
use unicorn_engine_sys::Prot;

use crate::emul::uc::Uc;

///   movz x0, #0        (0xD2800000)
///   ret                (0xD65F03C0)
const MOVZ_X0_0: u32 = 0xD280_0000;
const RET: u32 = 0xD65F_03C0;

/// deploy continuously on one page
pub struct StubSpace {
    pub base: u64,
    pub size: u64,
    pub next_off: u64,
}

impl StubSpace {
    pub unsafe fn new(uc: &Uc, base: u64, size: u64) -> Result<Self> {
        unsafe { uc.map(base, size, Prot::READ | Prot::WRITE | Prot::EXEC)? };
        Ok(Self {
            base,
            size,
            next_off: 0,
        })
    }

    pub unsafe fn alloc_stub_ret0(&mut self, uc: &Uc) -> Result<u64> {
        let addr = self.base + self.next_off;
        let mut buf = [0u8; 8];
        buf[..4].copy_from_slice(&MOVZ_X0_0.to_le_bytes());
        buf[4..].copy_from_slice(&RET.to_le_bytes());
        unsafe { uc.write(addr, &buf)? };
        self.next_off += 0x10; // 16바이트 간격
        Ok(addr)
    }
}

pub unsafe fn patch_got_with_lib_or_stub(
    uc: &Uc,
    ta_relocs: &[(u64, String)],
    lib_syms: &HashMap<String, u64>,
    stubs: &mut StubSpace,
) -> Result<()> {
    for (got_addr, name) in ta_relocs {
        let target = if let Some(symaddr) = lib_syms.get(name) {
            *symaddr
        } else {
            unsafe { stubs.alloc_stub_ret0(uc)? }
        };
        unsafe {
            uc.write(*got_addr, &target.to_le_bytes())
                .with_context(|| format!("write GOT {:#x} <- {:#x} ({})", got_addr, target, name))?;
        }
    }
    Ok(())
}