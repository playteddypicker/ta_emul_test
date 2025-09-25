use anyhow::Result;
use core::ffi::c_void;
use std::mem::transmute;
use unicorn_engine_sys::{uc_cb_hookcode_t, HookType, MemType, Prot, uc_cb_eventmem_t, uc_cb_hookinsn_invalid_t, uc_cb_hookintr_t, uc_engine, uc_hook, uc_hook_add, uc_mem_map};

use crate::emul::uc::{Uc, check};

#[inline]
fn page_down(x: u64) -> u64 {
    x & !0xfffu64
}

pub trait HookingStrategy {
    fn install_hooks(&self, uc: &Uc) -> Result<Vec<uc_hook>>;
}

pub struct DefaultHookingStrategy;

impl HookingStrategy for DefaultHookingStrategy {
    fn install_hooks(&self, uc: &Uc) -> Result<Vec<uc_hook>> {
        let mut installed_hooks = Vec::new();

        // install_unmapped_hook logic
        unsafe extern "C" fn on_mem(
            uc: *mut uc_engine,
            kind: MemType,
            addr: u64,
            size: i32,
            value: i64,
            _user: *mut c_void,
        ) -> bool {
            eprintln!(
                "[MEM] {:?} addr=0x{:x} size={} val=0x{:x}",
                kind, addr, size, value
            );

            let p = page_down(addr);
            unsafe {
                let _ = uc_mem_map(uc, p, 0x1000, (Prot::READ | Prot::WRITE | Prot::EXEC).0);
            }

            true
        }
        let mut h_unmapped: uc_hook = 0;
        let cb_unmapped: uc_cb_eventmem_t = Some(on_mem);
        let cb_ptr_unmapped: *mut c_void = unsafe { transmute(cb_unmapped) };
        unsafe {
            check(uc_hook_add(
                uc.raw,
                &mut h_unmapped,
                HookType::MEM_UNMAPPED.0 as i32,
                cb_ptr_unmapped,
                core::ptr::null_mut(),
                0,
                u64::MAX,
            ))?;
        }
        installed_hooks.push(h_unmapped);

        // install_invalid_insn_hook logic
        unsafe extern "C" fn on_invalid(_uc: *mut uc_engine, _user: *mut c_void) -> bool {
            eprintln!("[INVALID INSN]");
            true
        }
        let mut h_invalid: uc_hook = 0;
        let cb_invalid: uc_cb_hookinsn_invalid_t = Some(on_invalid);
        let cb_ptr_invalid: *mut c_void = unsafe { transmute(cb_invalid) };
        unsafe {
            check(uc_hook_add(
                uc.raw,
                &mut h_invalid,
                HookType::INSN_INVALID.0 as i32,
                cb_ptr_invalid,
                core::ptr::null_mut(),
                0,
                u64::MAX,
            ))?;
        }
        installed_hooks.push(h_invalid);

        // install_intr_hook logic
        unsafe extern "C" fn on_intr(_uc: *mut uc_engine, intno: u32, _user: *mut c_void) {
            eprintln!("[INTR] intno={}", intno);
        }
        let mut h_intr: uc_hook = 0;
        let cb_intr: uc_cb_hookintr_t = Some(on_intr);
        let cb_ptr_intr: *mut c_void = unsafe { transmute(cb_intr) };
        unsafe {
            check(uc_hook_add(
                uc.raw,
                &mut h_intr,
                HookType::INTR.0 as i32,
                cb_ptr_intr,
                core::ptr::null_mut(),
                0,
                u64::MAX,
            ))?;
        }
        installed_hooks.push(h_intr);

        Ok(installed_hooks)
    }
}

pub struct TracingHookingStrategy;

impl HookingStrategy for TracingHookingStrategy {
    fn install_hooks(&self, uc: &Uc) -> Result<Vec<uc_hook>> {
        let mut installed_hooks = Vec::new();

        // install_mem_tracer logic
        unsafe extern "C" fn on_mem_trace(
            _uc: *mut uc_engine,
            kind: MemType,
            addr: u64,
            size: i32,
            value: i64,
            _user: *mut c_void,
        ) -> bool {
            match kind {
                MemType::READ => {
                    eprintln!("[TRACE_MEM] READ at {:#x}, size {}", addr, size);
                }
                MemType::WRITE => {
                    eprintln!("[TRACE_MEM] WRITE at {:#x}, size {}, value {:#x}", addr, size, value);
                }
                _ => {}
            }
            true
        }
        let mut h_mem_trace: uc_hook = 0;
        let cb_mem_trace: uc_cb_eventmem_t = Some(on_mem_trace);
        let cb_ptr_mem_trace: *mut c_void = unsafe { transmute(cb_mem_trace) };
        unsafe {
            check(uc_hook_add(
                uc.raw,
                &mut h_mem_trace,
                (HookType::MEM_READ | HookType::MEM_WRITE).0 as i32,
                cb_ptr_mem_trace,
                core::ptr::null_mut(),
                1,
                0,
            ))?;
        }
        installed_hooks.push(h_mem_trace);

        // install_code_tracer logic
        unsafe extern "C" fn on_code_trace(
            _uc: *mut uc_engine,
            address: u64,
            size: u32,
            _user_data: *mut c_void,
        ) {
            eprintln!("[TRACE_CODE] Executing block at {:#x}, size {}", address, size);
        }
        let mut h_code_trace: uc_hook = 0;
        let cb_code_trace: uc_cb_hookcode_t = Some(on_code_trace);
        let cb_ptr_code_trace: *mut c_void = unsafe { transmute(cb_code_trace) };
        unsafe {
            check(uc_hook_add(
                uc.raw,
                &mut h_code_trace,
                HookType::BLOCK.0 as i32,
                cb_ptr_code_trace,
                core::ptr::null_mut(),
                1,
                0,
            ))?;
        }
        installed_hooks.push(h_code_trace);

        Ok(installed_hooks)
    }
}
