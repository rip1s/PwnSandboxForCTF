# PwnSandboxForCTF
Yet another sandbox for CTF challenge in AWD mode

This is a ptrace sandbox. ~~(It was a chroot sandbox)~~

It will send PTRACE_KILL under certain circumstance:

* Child process attempting to open files with 'flag' in its name by open or openat. (/tmp/asdflagasd etc.)
* Child process attempting to call illegal syscall. (execve/execveat)

ELF64 and ELF32 supported, including PIE

## Installation
```bash
pip install pwnsandbox
```
## Usage

```bash
usage: pwn_sandbox [-h] input_bin

Yet another pwn sandbox for CTF by @unamer(https://github.com/unamer)

positional arguments:
  input_bin   /path/to/your/input binary

optional arguments:
  -h, --help  show this help message and exit
```
There will be a binary output named binary_sandbox in your binary's folder

## Requirement

* python 2.7
* pwntools
* lief

## Known issues

* ~~Centos **NOT supported**~~

## TODO

* ~~Find a clean method to jump back to oep~~
* ~~New method to support centos~~
