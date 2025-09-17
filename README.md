# TA Emulator Setup

This repository contains the code for emulating Trusted Applications (TA) using the Unicorn Engine and Rust.
## Requirements

- **Rust**: 
  - Rust stable
    ```
    rustup 1.28.2 (e4f3ad6f8 2025-04-28)
    ```

- **System Dependencies**:
  - Ubuntu 24.04 x86-64:
    ```bash
    sudo apt-get update
    sudo apt-get install -y clang llvm libclang-dev libssl-dev cmake build-essential libunicorn-dev
    ```

## Execution:
```bash
git clone https://github.com/your-repo/ta-emulator.git
cd ta-emulator
cargo run
