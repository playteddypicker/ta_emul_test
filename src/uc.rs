use anyhow::{Result, bail};
use std::ffi::CStr;
use unicorn_engine_sys::{
    Arch, Mode, Prot, RegisterARM64, uc_close, uc_emu_start, uc_engine, uc_error, uc_mem_map,
    uc_mem_protect, uc_mem_read, uc_reg_read, uc_mem_write, uc_open, uc_reg_write, uc_strerror,
};

pub struct Uc {
    pub raw: *mut uc_engine,
}

impl Uc {
    pub unsafe fn new_arm64() -> Result<Self> {
        let mut h: *mut uc_engine = std::ptr::null_mut();
        unsafe { check(uc_open(Arch::ARM64, Mode::LITTLE_ENDIAN, &mut h))? };
        Ok(Self { raw: h })
    }

    pub unsafe fn map(&self, addr: u64, size: u64, prot: Prot) -> Result<()> {
        unsafe { check(uc_mem_map(self.raw, addr, size, prot.0))? };
        Ok(())
    }

    pub unsafe fn read_bytes(&self, addr: u64, len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        unsafe {
            check(uc_mem_read(
                self.raw,
                addr,
                buf.as_mut_ptr() as *mut _,
                len as u64,
            ))?
        };
        Ok(buf)
    }

    pub unsafe fn read_u64(&self, addr: u64) -> Result<u64> {
        let b = unsafe { self.read_bytes(addr, 8)? };
        Ok(u64::from_le_bytes(b[..8].try_into().unwrap()))
    }

    pub unsafe fn write(&self, addr: u64, data: &[u8]) -> Result<()> {
        unsafe {
            check(uc_mem_write(
                self.raw,
                addr,
                data.as_ptr() as *const _,
                data.len() as u64,
            ))?
        };
        Ok(())
    }

    pub unsafe fn protect(&self, addr: u64, size: u64, prot: Prot) -> Result<()> {
        unsafe { check(uc_mem_protect(self.raw, addr, size, prot.0))? };
        Ok(())
    }

    pub unsafe fn set_sp(&self, sp: u64) -> Result<()> {
        unsafe {
            check(uc_reg_write(
                self.raw,
                RegisterARM64::SP as i32,
                &sp as *const _ as *const _,
            ))?
        };
        Ok(())
    }

    pub unsafe fn start_icount(&self, begin: u64, icount: u64) -> Result<()> {
        unsafe { check(uc_emu_start(self.raw, begin, 0, 0, icount as usize))? };
        Ok(())
    }

    pub unsafe fn reg_read(&self, regid: i32) -> Result<u64> {
        let mut value: u64 = 0;
        unsafe {
            check(uc_reg_read(
                self.raw,
                regid,
                &mut value as *mut _ as *mut _,
            ))?
        };
        Ok(value)
    }

    pub unsafe fn reg_write(&self, regid: i32, value: u64) -> Result<()> {
        unsafe {
            check(uc_reg_write(
                self.raw,
                regid,
                &value as *const _ as *const _,
            ))?
        };
        Ok(())
    }
}

impl Drop for Uc {
    fn drop(&mut self) {
        unsafe {
            let _ = uc_close(self.raw);
        }
    }
}

pub fn check(e: uc_error) -> Result<()> {
    if e == uc_error::OK {
        return Ok(());
    }
    let s = unsafe { CStr::from_ptr(uc_strerror(e)) };
    bail!("unicorn error: {}", s.to_string_lossy())
}