#!/usr/bin/env python
# -*- coding: utf-8 -*-
# __author__ = "unamer"

from pwn import *
import lief
import argparse


def sandbox(input):
    try:
        e = lief.parse(input)
    except:
        log.error('Fail to load elf!')
    is64 = 0
    if e.header.machine_type == lief.ELF.ARCH.x86_64:
        is64 = 1
    if is64:
        context.arch = 'amd64'
        asmcode = '''
            push    r15
            push    r14
            push    r13
            push    r12
            push    rbp
            push    rbx
            sub     rsp, 0x1118
            xor     eax, eax
            call    fork
            test    eax, eax
            jz      child
            lea     rax, [rsp+0x1148-0x1128]
            mov     dword ptr [rsp+0x1148-0x1050], 0x67616C66
            mov     byte ptr [rsp+0x1148-0x104C], 0
            lea     r14, [rsp+0x1148-0x112c]
            lea     r12, [rsp+0x1148-0x48]
            lea     r13, [rsp+0x1148-0x1050]
            mov     qword ptr [rsp+0x1148-0x1148], rax
            lea     rax, [rsp+0x1148-0x1048]
            mov     qword ptr [rsp+0x1148-0x1140], rax
            jmp     loc_400656
    
    loc_400618:                     
            cmp     rax, 0x101
            jz      loc_4006C1
            cmp     rax, 0x3B
            jz      loc_400798
            cmp     rax, 0x142
            jz      loc_400798
            cmp     rax, 0x38
            jz      loc_4007D1
    loc_400644:                     
    
            xor     ecx, ecx
            xor     edx, edx
            mov     esi, ebx
            mov     edi, 0x18
            xor     eax, eax
            call    ptrace
    loc_400656:                     
            mov     edx, 0x40000000  
            mov     rsi, r14        
            mov     edi, 0xFFFFFFFF
            call    waitpid
            test    eax, eax
            mov     ebx, eax
            jz      loc_4007AA
            test    byte ptr [rsp+0x1148-0x112c], 0x7F
            jz      loc_4007AA
            xor     ecx, ecx
            xor     edx, edx
            mov     esi, ebx
            mov     edi, 0x18
            xor     eax, eax
            call    ptrace
            xor     edx, edx        
            mov     rsi, r14        
            mov     edi, ebx        
            call    waitpid
            mov     rcx, [rsp+0x1148-0x1148]
            xor     edx, edx
            xor     eax, eax
            mov     esi, ebx
            mov     edi, 0xC
            call    ptrace
            mov     rax, [rsp+0x1148-0x10B0]
            cmp     rax, 2
            jnz     loc_400618
    loc_4006C1:                     
            cmp     rax, 2
            mov     rbp, qword ptr [rsp+0x1148-0x10B8]
            jz      loc_4006D7
            mov     rbp, qword ptr [rsp+0x1148-0x10C0]
    loc_4006D7:                     
            mov     rax, qword ptr[rsp+0x1148-0x1140]
            mov     r15, rax
            sub     rbp, rax
            jmp     loc_4006F5
    
    loc_4006E8:                     
            test    al, al
            jz      loc_40071A
            add     r15, 2
            cmp     r15, r12
            jz      loc_40071A
    loc_4006F5:                     
            lea     rdx, [rbp+r15+0]
            xor     ecx, ecx
            xor     eax, eax
            mov     esi, ebx
            mov     edi, 1
            call    ptrace
            mov     edx, eax
            mov     byte ptr [r15], al
            sar     edx, 8
            test    dl, dl
            mov     byte ptr [r15+1], dl
            jnz     loc_4006E8
    loc_40071A:                     
    
            mov     rdi, qword ptr [rsp+0x1148-0x1140]
            lea     rax, [r13+1]
    loc_400728:                     
            add     rax, 1
            add     rdi, 1
            cmp     byte ptr [rax], 0
            jnz     loc_400728
            cmp     byte ptr [rdi], 0
            mov     r8, qword ptr [rsp+0x1148-0x1140]
            jz      loc_400644
    loc_400748:                     
            cmp     byte ptr [r8], 0x66
            mov     rdx, r8
            mov     rax, r13
            jz      loc_40076D
            jmp     loc_400781
    
    loc_400760:                     
            movzx   esi, byte ptr [rax]
            cmp     cl, sil
            jnz     loc_40077C
            test    sil, sil
            jz      loc_40077C
    loc_40076D:                     
            add     rdx, 1
            movzx   ecx, byte ptr [rdx]
            add     rax, 1
            test    cl, cl
            jnz     loc_400760
    loc_40077C:                     
    
            cmp     byte ptr [rax], 0
            jz      loc_400798
    loc_400781:                     
            add     rdi, 1
            add     r8, 1
            cmp     byte ptr [rdi], 0
            jnz     loc_400748
            jmp     loc_400644
    
    loc_400798:                     
    
            xor     ecx, ecx
            xor     edx, edx
            mov     esi, ebx
            mov     edi, 8
            xor     eax, eax
            call    ptrace
    loc_4007AA:                     
    
            xor	rax, rax
            mov	al,  0x3C
            syscall
            ret
    
    loc_4007D1:                     
            mov     rcx, [rsp+0x1148-0x1148]
            xor     edx, edx
            mov     esi, ebx
            mov     edi, 0xD
            xor     eax, eax
            or      qword ptr [rsp+0x1148-0x10B8], 0x2000
            call    ptrace
            jmp     loc_400644
    
    waitpid:
            xor     r10, r10
            mov     rax, r10
            mov     al, 0x3D
            syscall
            ret
    
    fork:
            mov rax, 57
            syscall
            ret
    
    ptrace:
            sub     rsp, 0x68
            lea     r8d, [rdi-1]
            xor     eax, eax
            lea     rax, [rsp+0x68+8]
            mov     qword ptr [rsp+0x68-0x30], rsi
            mov     qword ptr [rsp+0x68-0x28], rdx
            mov     qword ptr [rsp+0x68-0x20], rcx
            lea     r10, [rsp+0x68-0x60]
            cmp     r8d, 3
            mov     qword ptr [rsp+0x68-0x50], rax
            lea     rax, [rsp+0x68-0x38]
            mov     qword ptr [rsp+0x68-0x58], 0x18
            mov     esi, [rax+8]    
            mov     rdx, [rax+0x10]  
            mov     [rsp+0x68-0x48], rax
            cmovnb  r10, [rax+0x18]  
            mov     eax, 0x65
            syscall     
            add     rsp, 0x68
            ret
    
    child:                     
            xor     ecx, ecx
            xor     edx, edx
            xor     esi, esi
            xor     edi, edi
            call    ptrace
            mov     eax, 0x27
            syscall
            mov     esi, 2
            mov     edi, eax
            mov     eax, 0x3e
            syscall
            xor     eax, eax
    return_oep:
        '''
    else:
        context.arch = 'i386'
        asmcode = '''
            lea     ecx, [esp+4]
            and     esp, 0xFFFFFFF0
            push    dword ptr [ecx-4]
            push    ebp
            mov     ebp, esp
            push    edi
            push    esi
            push    ebx
            push    ecx
            sub     esp, 0x1088
            xor     edi, edi
            call    fork
            test    eax, eax
            jz      child
            lea     eax, [ebp-0x106C]
            mov     dword ptr [ebp-0x1024], 0x67616C66
            mov     byte ptr [ebp-0x1020], 0
            mov     [ebp-0x1088], eax
            lea     eax, [ebp-0x1068]
            mov     [ebp-0x1094], eax
            lea     eax, [ebp-0x101C]
            mov     [ebp-0x1098], eax
            jmp     loc_8048352
    
    loc_8048310:                    
            cmp     eax, 0x127
            jz      loc_80483D4
            cmp     eax, 0x0B
            jz      loc_80484E0
            cmp     eax, 0x166
            jz      loc_80484E0
            cmp     eax, 0x78
            jz      loc_8048514
    loc_8048338:                    
    
            mov     ebx, [ebp-0x107C]
            push    0
            push    0
            push    dword ptr [ebp-0x1080]
            push    0x18
            call    ptrace
            add     esp, 0x10
    loc_8048352:                    
            sub     esp, 4
            mov     ebx, [ebp-0x107C]
            push    0x40000000
            push    dword ptr [ebp-0x1088]
            push    0x0FFFFFFFF
            call    waitpid
            add     esp, 0x10
            test    eax, eax
            mov     [ebp-0x1080], eax
            jz      loc_80484FA
            test    byte ptr [ebp-0x106C], 0x7F
            jz      loc_80484FA
            mov     edi, [ebp-0x107C]
            push    0
            mov     esi, eax
            push    0
            push    eax
            push    0x18
            mov     ebx, edi
            call    ptrace
            add     esp, 0x0C
            push    0
            push    dword ptr [ebp-0x1088]
            push    esi
            call    waitpid
            push    dword ptr [ebp-0x1094]
            push    0
            push    esi
            push    0x0C
            call    ptrace
            mov     eax, [ebp-0x103C]
            add     esp, 0x20
            cmp     eax, 5
            jnz     loc_8048310
    loc_80483D4:                    
            cmp     eax, 5
            mov     esi, [ebp-0x1064]
            cmovz   esi, [ebp-0x1068]
            mov     edx, [ebp-0x1098]
            mov     edi, esi
            mov     ecx, esi
            sar     edi, 0x1F
            add     ecx, 0x1000
            mov     ebx, edi
            mov     [ebp-0x1090], ecx
            adc     ebx, 0
            mov     [ebp-0x108C], ebx
            jmp     loc_8048435
    
    loc_8048410:                    
            test    al, al
            jz      loc_804846C
            mov     ecx, [ebp-0x1090]
            mov     ebx, [ebp-0x108C]
            add     esi, 2
            adc     edi, 0
            add     edx, 2
            mov     eax, ecx
            mov     ecx, ebx
            xor     eax, esi
            xor     ecx, edi
            or      ecx, eax
            jz      loc_804846C
    loc_8048435:                    
            sub     esp, 0x0C
            mov     ebx, [ebp-0x107C]
            mov     [ebp-0x1084], edx
            push    0
            push    edi
            push    esi
            push    dword ptr [ebp-0x1080]
            push    1
            call    ptrace
            mov     edx, [ebp-0x1084]
            mov     ecx, eax
            add     esp, 0x20
            sar     ecx, 8
            test    cl, cl
            mov     [edx], al
            mov     [edx+1], cl
            jnz     loc_8048410
    loc_804846C:                    
    
            mov     esi, [ebp-0x1098]
            lea     eax, [ebp-0x1023]
            nop
            lea     esi, [esi+0]
    loc_8048480:                    
            add     eax, 1
            add     esi, 1
            cmp     byte ptr [eax], 0
            jnz     loc_8048480
            cmp     byte ptr [esi], 0
            mov     edi, [ebp-0x1098]
            jz      loc_8048338
            lea     esi, [esi+0]
    loc_80484A0:                    
            cmp     byte ptr [edi], 0x66
            mov     edx, edi
            lea     eax, [ebp-0x1024]
            jz      loc_80484BB
            jmp     loc_80484CD
    
    loc_80484B0:                    
            movzx   ebx, byte ptr [eax]
            test    bl, bl
            jz      loc_80484C8
            cmp     cl, bl
            jnz     loc_80484C8
    loc_80484BB:                    
            add     edx, 1
            movzx   ecx, byte ptr [edx]
            add     eax, 1
            test    cl, cl
            jnz     loc_80484B0
    loc_80484C8:                    
    
            cmp     byte ptr [eax], 0
            jz      loc_80484E0
    loc_80484CD:                    
            add     esi, 1
            add     edi, 1
            cmp     byte ptr [esi], 0
            jnz     loc_80484A0
            jmp     loc_8048338
    
    loc_80484E0:                    
    
            mov     ebx, [ebp-0x107C]
            push    0
            push    0
            push    dword ptr [ebp-0x1080]
            push    8
            call    ptrace
            add     esp, 0x10
    loc_80484FA:
    
            mov     eax,0xfc
            int     0x80
            ret
    
    loc_8048514:                    
            mov     ebx, [ebp-0x107C]
            push    dword ptr [ebp-0x1094]
            push    0
            push    dword ptr [ebp-0x1080]
            push    0x0D
            or      dword ptr [ebp-0x1068], 0x2000
            call    ptrace
            add     esp, 0x10
            jmp     loc_8048338
    
    fork:
            mov     eax,2
            int     0x80
            ret
    ptrace:
            push    edi
            push    esi
            push    ebx
            sub     esp, 0x1c
            mov     eax, 0x1a
            mov     ebx, [esp+0x28+4]
            mov     ecx, [esp+0x28+8]
            mov     edx, [esp+0x28+0xc]
            lea     esi, [esp+0x4]
            lea     edi, [ebx-1]
            cmp     edi, 3
            cmovnb  esi, [esp+0x28+0x10]
            int     0x80
            cmp     edi,2
            ja      ptrace_ret
            mov     eax, [esp+0x4]
    ptrace_ret:
            add     esp, 0x1c
            pop     ebx
            pop     esi
            pop     edi
            ret
    waitpid:
            push    esi
            push    ebx
            mov     eax, 0x7
            mov     ebx, [esp+8+4]
            mov     ecx, [esp+8+8]
            mov     edx, [esp+8+0xc]
            int     0x80
            pop     ebx
            pop     esi
            ret
    
    child:                    
            mov     edi, [ebp-0x107C]
            push    0
            push    0
            push    0
            push    0
            mov     ebx, edi
            call    ptrace
            mov     eax,0x14
            int     0x80
            mov     ebx, eax
            mov     eax, 0x25
            mov     ecx, 2
            int     0x80
            add     esp, 0x10
    call_oep:
        '''
    # NOTE: here I assume your input contains only one LOAD segment!
    # Shellcode will be placed after this segment.
    s = e.get(lief.ELF.SEGMENT_TYPES.LOAD)
    s_size = s.virtual_size
    if s_size % 0x1000:
        s_size += 0x1000 - (s_size % 0x1000)
    log.success('Load segment memory size:' + hex(s_size))
    a = asm(asmcode)
    log.success('Original Entry Point:' + hex(e.entrypoint))
    if e.is_pie:
        log.info('PIE detected')
        if is64:
            final = asm('''
            call getaddr
            getaddr:
            pop rdi
            and rdi,0xfffffffffffff000
            mov rsi,0x1000
            mov rdx,5
            mov rax,10
            syscall
            mov rax,rdi
            /*Really ugly way...*/
            sub rax,0x11000
            sub rax,{}
            add rax,{}
            /*Now restore registers NOTE: RAX discarded*/
            add     rsp, 0x1118
            pop     rbx
            pop     rbp
            pop     r12
            pop     r13
            pop     r14
            pop     r15
            push    rax
            xor     rax,rax
            ret
            '''.format(hex(s_size), hex(e.entrypoint)))
        else:
            final = asm('''
            xor esi,esi
            call getaddr
        getaddr:
            pop ebx
            and ebx,0xfffff000
            sub ebx,0x11000
            sub ebx,{}
            add ebx,{}
            /*Now restore registers NOTE: EAX discarded*/
            mov eax,ebx
            lea     esp, [ebp-0x10]
            pop     ecx
            pop     ebx
            pop     esi
            pop     edi
            pop     ebp
            lea     esp, [ecx-4]
            push eax
            xor eax,eax
            ret
        mprotect:
            xor eax,eax
            mov al,125
            int 0x80
            ret
            '''.format(hex(s_size), hex(e.entrypoint)))
    else:
        if is64:
            final = asm('''
            call getaddr
            getaddr:
            pop rdi
            and rdi,0xfffffffffffff000
            mov rsi,0x1000
            mov rdx,5
            mov rax,10
            syscall
            mov rax,{}
            /*Now restore registers NOTE: RAX discarded*/
            add     rsp, 0x1118
            pop     rbx
            pop     rbp
            pop     r12
            pop     r13
            pop     r14
            pop     r15
            push rax
            xor rax,rax
            ret
            '''.format(hex(e.entrypoint)))
        else:
            final = asm('''
            mov eax,{}
            /*Now restore registers NOTE: EAX discarded*/
            lea     esp, [ebp-0x10]
            pop     ecx
            pop     ebx
            pop     esi
            pop     edi
            pop     ebp
            lea     esp, [ecx-4]
            push eax
            xor eax,eax
            ret
            '''.format(hex(e.entrypoint)))
    code = []
    for x in a:
        code.append(ord(x))
    for x in final:
        code.append(ord(x))
    log.info('Shellcode length:' + hex(len(code)))
    segment = lief.ELF.Segment()
    segment.type = lief.ELF.SEGMENT_TYPES.LOAD
    segment.add(lief.ELF.SEGMENT_FLAGS.R)
    segment.add(lief.ELF.SEGMENT_FLAGS.W)
    segment.add(lief.ELF.SEGMENT_FLAGS.X)
    segment.content = code
    segment.alignment = 8

    segment = e.add(segment, 0x10000)
    log.success('Add segment done.')
    e.header.entrypoint = segment.virtual_address
    log.success('New Entry Point:' + hex(segment.virtual_address))
    outfile = input + '_sandbox'
    e.write(outfile)
    st = os.stat(outfile)
    os.chmod(outfile, st.st_mode | 0111)


def main():
    parser = argparse.ArgumentParser(
        description="Yet another pwn sandbox for CTF by @unamer(https://github.com/unamer)")
    parser.add_argument("input_bin", help="/path/to/your/input binary")
    args = parser.parse_args()
    sandbox(args.input_bin)


if __name__ == '__main__':
    main()
