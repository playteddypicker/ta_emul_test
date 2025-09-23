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

## Usage

1.  Prepare your target files. Create a new directory inside the `blobs/` folder (e.g., `blobs/my_target`).
2.  Place the main `.elf` file and its required `.so` library file inside the directory you just created.
3.  Build and run the emulator. Pass the name of the directory you created as a command-line argument.

    ```sh
    cargo run -- <your_directory_name>
    ```

    For example, if you created `blobs/my_target`, you would run:

    ```sh
    cargo run -- my_target
    ```