use anyhow::Result;
use core::ffi::c_void;
use std::mem::transmute;
use unicorn_engine_sys::{
    HookType, MemType, Prot, uc_cb_hookinsn_invalid_t, uc_cb_hookintr_t, uc_cb_hookmem_t,
    uc_engine, uc_hook, uc_hook_add, uc_mem_map,
};

use crate::uc::check;

const PAGE_MASK: u64 = !0xfffu64;
#[inline]
fn page_down(x: u64) -> u64 {
    x & PAGE_MASK
}

pub unsafe fn install_unmapped_hook(uc: *mut uc_engine) -> Result<uc_hook> {
    unsafe extern "C" fn on_mem(
        uc: *mut uc_engine,
        kind: MemType,
        addr: u64,
        size: i32,
        value: i64,
        _user: *mut c_void,
    ) {
        eprintln!(
            "[MEM] {:?} addr=0x{:x} size={} val=0x{:x}",
            kind, addr, size, value
        );

        let p = page_down(addr);
        let _ = uc_mem_map(uc, p, 0x1000, (Prot::READ | Prot::WRITE | Prot::EXEC).0);
    }

    let mut h: uc_hook = 0;
    let cb: uc_cb_hookmem_t = Some(on_mem);
    let cb_ptr: *mut c_void = unsafe { transmute(cb) };

    unsafe {
        check(uc_hook_add(
            uc,
            &mut h,
            HookType::MEM_UNMAPPED.0 as i32,
            cb_ptr,
            core::ptr::null_mut(),
            0,
            u64::MAX,
        ))?;
    }
    Ok(h)
}

// if true it stops
pub unsafe fn install_invalid_insn_hook(uc: *mut uc_engine) -> Result<uc_hook> {
    unsafe extern "C" fn on_invalid(_uc: *mut uc_engine, _user: *mut c_void) -> bool {
        eprintln!("[INVALID INSN]");
        true // stop this emulator sucessfully
    }

    let mut h: uc_hook = 0;
    let cb: uc_cb_hookinsn_invalid_t = Some(on_invalid);
    let cb_ptr: *mut c_void = unsafe { transmute(cb) };

    unsafe {
        check(uc_hook_add(
            uc,
            &mut h,
            HookType::INSN_INVALID.0 as i32,
            cb_ptr,
            core::ptr::null_mut(),
            0,
            u64::MAX,
        ))?;
    }
    Ok(h)
}

pub unsafe fn install_intr_hook(uc: *mut uc_engine) -> Result<uc_hook> {
    unsafe extern "C" fn on_intr(_uc: *mut uc_engine, intno: u32, _user: *mut c_void) {
        eprintln!("[INTR] intno={}", intno);
    }

    let mut h: uc_hook = 0;
    let cb: uc_cb_hookintr_t = Some(on_intr);
    let cb_ptr: *mut c_void = unsafe { transmute(cb) };

    unsafe {
        check(uc_hook_add(
            uc,
            &mut h,
            HookType::INTR.0 as i32,
            cb_ptr,
            core::ptr::null_mut(),
            0,
            u64::MAX,
        ))?;
    }
    Ok(h)
}
