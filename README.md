# PwnSandboxForCTF
Yet another sandbox for CTF challenge in AWD mode

Just chroot it! :)

ELF64 and ELF32 supported,including PIE

## Usage

```bash
python ./sandbox.py /path/to/your/binary
```
There will be a binary output named binary_sandbox in your binary's folder

## Requirement

* python 2.7
* pwntools

## Known issues

* Centos **NOT supported**

## TODO

* Find a clean method to jump back to oep 
* New method to support centos
