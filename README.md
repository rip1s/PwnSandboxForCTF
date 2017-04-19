# PwnSandboxForCTF
Yet another sandbox for CTF challenge in AWD mode

Just chroot it! :)

ELF64 and ELF32 supportd

## Usage

```bash
python ./sandbox.py /path/to/your/binary
```
There will be a file named test in your binary's folder

## Requirement

* python 2.7
* pwntools

## Known issues

* Not support for ELF32 with PIE enabled, it will just crash.If you know how to solve it,plz contact admin@00v.in.
* Ugly method in ELF64 with PIE enabled, even it just works.
