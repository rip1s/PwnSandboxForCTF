# PwnSandboxForCTF
Yet another sandbox for CTF challenge in AWD mode

This is a ptrace sandbox. ~~(It was a chroot sandbox)~~

It will send PTRACE_KILL under certain circumstances:

* Child process attempting to open files with 'flag' in its name by open/openat/name_to_handle_at. (/tmp/asdflagasd etc.)
* Child process attempting to create a symlink or hardlink for file with 'flag' in its name by symlink/symlinkat/link.
* Child process attempting to call illegal syscall. (execve/execveat/stub_execveat)

ELF64 and ELF32 supported, including PIE

## Installation
```bash
pip install pwnsandbox
```
or
```bash
python setup.py install
```
It will install a console script 'pwn_sandbox'.
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
* ~~lief~~ Already included in project cause newest lief [sucks](https://github.com/lief-project/LIEF/issues/143).

## Known issues

* ~~Centos **NOT supported**~~
* Might crash on ELF contains multi loadable segments. (I haven't seen this type of ELF yet)
* Sandbox might be bypassable, but it isn't designed as an impenetrable shield anyway. (issues are welcome.)
* DO NOT use newest lief or you will be fucked when processing non-pie ELF32 file.

## TODO

* ~~Find a clean method to jump back to oep~~
* ~~New method to support centos~~

## Changelog

### [0.3] - 2019-01-08
#### Added
- Various bug fix.
- Add more syscall in filter scope.

### [0.2] - 2019-01-07
#### Added
- Update project description.
- Revert lief version.

### [0.1] - 2019-01-05
#### Added
- Reconstruct project.
- Initial ptrace sandbox.
