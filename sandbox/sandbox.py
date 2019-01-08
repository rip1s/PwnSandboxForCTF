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
    call    fork
    test    eax, eax
    jz      child
    lea     rax, byte ptr[rsp+0x1148-0x1128]
    lea     r13, byte ptr[rsp+0x1148-0x1048]
    mov     dword ptr[rsp+0x1148-0x1050], 0x67616C66
    mov     byte ptr[rsp+0x1148-0x104C], 0
    lea     r14, dword ptr[rsp+0x1148-0x112C]
    mov     qword ptr[rsp+0x1148-0x1140], rax
    lea     r12, [r13+0x1000]
    jmp     short loc_40064B
loc_400608:                  
    lea     rdx, [rax-0x56]
    test    rdx, 0x0FFFFFFFFFFFFFFFD
    jz      loc_4007D8
    cmp     rax, 0x3B
    jz      loc_4007E8
    cmp     rax, 0x142
    jz      loc_4007E8
    cmp     rax, 0x38
    jz      loc_40081B
loc_400639:                  
    xor     ecx, ecx
    xor     edx, edx
    mov     esi, ebx
    mov     edi, 0x18
    xor     eax, eax
    call    ptrace
loc_40064B:                  
    mov     edx, 0x40000000  
    mov     rsi, r14    
    mov     edi, 0x0FFFFFFFF 
    call    waitpid
    test    eax, eax
    mov     ebx, eax
    jz      loc_4007F4
    mov     eax, dword ptr[rsp+0x1148-0x112C]
    and     eax, 0x7F
    jz      loc_4007F4
    add     eax, 1
    cmp     al, 1
    jg      loc_4007F4
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
    mov     rcx, qword ptr[rsp+0x1148-0x1140]
    xor     edx, edx
    xor     eax, eax
    mov     esi, ebx
    mov     edi, 0x0C
    call    ptrace
    mov     rax, qword ptr[rsp+0x1148-0x10B0]
    cmp     rax, 0xffffffffffffffff
    jz      loc_4007F4
    lea     rcx, [rax-0x101]
    cmp     rax, 2
    setz    dl
    cmp     rcx, 0x2E
    ja      short loc_4006E3
    mov     rdi, 0x400000000201
    shr     rdi, cl
    mov     rcx, rdi
    and     ecx, 1
    or      edx, ecx
loc_4006E3:                  
    test    dl, dl
    jz      loc_400608
    cmp     rax, 2
    jz      loc_4007D8
    lea     rdx, [rax-0x56]
    test    rdx, 0x0FFFFFFFFFFFFFFFD
    jz      loc_4007D8
    cmp     rax, 0x10A
    mov     rbp, qword ptr[rsp+0x1148-0x10C0]
    jz      loc_4007D8
loc_40071A:                  
    mov     r15, r13
    sub     rbp, r13
    jmp     short loc_400735
loc_400728:                  
    test    al, al
    jz      short loc_40075A
    add     r15, 2
    cmp     r12, r15
    jz      short loc_40075A
loc_400735:                  
    lea     rdx, [rbp+r15+0]
    xor     ecx, ecx
    xor     eax, eax
    mov     esi, ebx
    mov     edi, 1
    call    ptrace
    mov     edx, eax
    mov     [r15], al
    sar     edx, 8
    test    dl, dl
    mov     [r15+1], dl
    jnz     short loc_400728
loc_40075A:                  
    lea     r9, dword ptr[rsp+0x1148-0x1050]
    mov     rdi, r13
    lea     rax, [r9+1]
loc_400770:                  
    add     rax, 1
    add     rdi, 1
    cmp     byte ptr [rax], 0
    jnz     short loc_400770
    cmp     byte ptr [rdi], 0
    mov     r8, r13
    jz      loc_400639
loc_400790:                  
    cmp     byte ptr [r8], 0x66
    mov     rdx, r8
    mov     rax, r9
    jz      short loc_4007AD
    jmp     short loc_4007C1
loc_4007A0:                  
    movzx   esi, byte ptr [rax]
    cmp     cl, sil
    jnz     short loc_4007BC
    test    sil, sil
    jz      short loc_4007BC
loc_4007AD:                  
    add     rdx, 1
    movzx   ecx, byte ptr [rdx]
    add     rax, 1
    test    cl, cl
    jnz     short loc_4007A0
loc_4007BC:                  
    cmp     byte ptr [rax], 0
    jz      short loc_4007E8
loc_4007C1:                  
    add     rdi, 1
    add     r8, 1
    cmp     byte ptr [rdi], 0
    jnz     short loc_400790
    jmp     loc_400639
loc_4007D8:                  
    mov     rbp, qword ptr[rsp+0x1148-0x10B8]
    jmp     loc_40071A
loc_4007E8:                  
    mov     esi, 9
    mov     edi, ebx
    call    kill
loc_4007F4:                  
    mov     eax,231
    syscall
    hlt

loc_40081B:                  
    mov     rcx, qword ptr[rsp+0x1148-0x1140]
    xor     edx, edx
    mov     esi, ebx
    mov     edi, 0x0D
    xor     eax, eax
    or      qword ptr[rsp+0x1148-0x10B8], 0x2000
    call    ptrace
    jmp     loc_400639
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
    cmp     r8d, 2
    ja      ptrace_ret
    mov     rax, [rsp+8]
ptrace_ret:
    add     rsp, 0x68
    ret

kill:
    mov     eax,0x3e
    syscall
    ret
    
child:                  
    xor     ecx, ecx
    xor     edx, edx
    xor     esi, esi
    xor     edi, edi
    call    ptrace
    mov     eax,39
    syscall
    mov     esi, 2
    mov     edi, eax
    call    kill
call_oep:
        '''
    else:
        context.arch = 'i386'
        asmcode = '''
    lea     ecx, dword ptr[esp+4]
    and     esp, 0x0FFFFFFF0
    push    dword ptr [ecx-4]
    push    ebp
    mov     ebp, esp
    push    edi
    push    esi
    push    ebx
    push    ecx
    mov     ebx, eax
    sub     esp, 0x1088
    mov     [ebp-0x1080], eax
    call    fork
    test    eax, eax
    jz      child
    lea     eax, [ebp-0x106C]
    mov     dword ptr [ebp-0x1024], 0x67616C66
    mov     byte ptr [ebp-0x1020], 0
    mov     [ebp-0x1090], eax
    lea     eax, [ebp-0x1068]
    mov     [ebp-0x1094], eax
    lea     eax, [ebp-0x101C]
    mov     [ebp-0x108C], eax
    jmp     loc_804838B
loc_8048310:                
    test    dl, dl
    jnz     loc_8048426
    cmp     eax, 0x53
    setz    dl
    cmp     eax, 0x130
    mov     ecx, edx
    jz      loc_8048434
    test    dl, dl
    jnz     loc_8048434
    cmp     eax, 9
    jz      loc_804843C
    cmp     eax, 0x155
    jz      loc_804843C
    cmp     eax, 0x0B
    setz    cl
    cmp     eax, 0x166
    setz    dl
    or      cl, dl
    jnz     loc_8048540
    cmp     eax, 0x142
    jz      loc_8048540
    cmp     eax, 0x78
    jz      loc_8048573
loc_8048371:                
    mov     ebx, [ebp-0x1080]
    push    0
    push    0
    push    dword ptr [ebp-0x1084]
    push    0x18
    call    ptrace
    add     esp, 0x10
loc_804838B:                
    sub     esp, 4
    mov     ebx, [ebp-0x1080]
    push    0x40000000
    push    dword ptr [ebp-0x1090]
    push    0x0FFFFFFFF
    call    waitpid
    add     esp, 0x10
    test    eax, eax
    mov     [ebp-0x1084], eax
    jz      loc_8048559
    mov     eax, [ebp-0x106C]
    and     eax, 0x7F
    jz      loc_8048559
    add     eax, 1
    cmp     al, 1
    jg      loc_8048559
    mov     esi, [ebp-0x1084]
    mov     edi, [ebp-0x1080]
    push    0
    push    0
    push    esi
    push    0x18
    mov     ebx, edi
    call    ptrace
    add     esp, 0x0C
    push    0
    push    dword ptr [ebp-0x1090]
    push    esi
    call    waitpid
    push    dword ptr [ebp-0x1094]
    push    0
    push    esi
    push    0x0C
    call    ptrace
    mov     eax, [ebp-0x103C]
    cmp     eax, 0xffffffff
    jz      loc_8048559
    add     esp, 0x20
    cmp     eax, 5
    setz    dl
    cmp     eax, 0x127
    jnz     loc_8048310
loc_8048426:                
    cmp     eax, 0x53
    setz    cl
    test    dl, dl
    jnz     loc_8048530
loc_8048434:                
    test    cl, cl
    jnz     loc_8048530
loc_804843C:                
    cmp     eax, 0x130
    jz      loc_8048530
    cmp     eax, 9
    jz      loc_8048530
    mov     esi, [ebp-0x1064]
    mov     edi, esi
    sar     edi, 0x1F
loc_804845B:                
    lea     eax, [ebp-0x1C]
    mov     edx, [ebp-0x108C]
    mov     [ebp-0x1088], eax
    jmp     short loc_8048485
loc_8048470:                
    test    cl, cl
    jz      short loc_80484BC
    add     esi, 2
    adc     edi, 0
    add     edx, 2
    cmp     [ebp-0x1088], edx
    jz      short loc_80484BC
loc_8048485:                
    sub     esp, 0x0C
    mov     ebx, [ebp-0x1080]
    mov     [ebp-0x107C], edx
    push    0
    push    edi
    push    esi
    push    dword ptr [ebp-0x1084]
    push    1
    call    ptrace
    mov     edx, [ebp-0x107C]
    mov     ecx, eax
    add     esp, 0x20
    sar     ecx, 8
    test    al, al
    mov     [edx], al
    mov     [edx+1], cl
    jnz     short loc_8048470
loc_80484BC:                
    mov     esi, [ebp-0x108C]
    lea     eax, [ebp-0x1023]
    nop
    lea     esi, [esi+0]
loc_80484D0:                
    add     eax, 1
    add     esi, 1
    cmp     byte ptr [eax], 0
    jnz     short loc_80484D0
    cmp     byte ptr [esi], 0
    mov     edi, [ebp-0x108C]
    jz      loc_8048371
    lea     esi, [esi+0]
loc_80484F0:                
    cmp     byte ptr [edi], 0x66
    mov     edx, edi
    lea     eax, [ebp-0x1024]
    jz      short loc_804850B
    jmp     short loc_804851D
loc_8048500:                
    movzx   ebx, byte ptr [eax]
    cmp     cl, bl
    jnz     short loc_8048518
    test    bl, bl
    jz      short loc_8048518
loc_804850B:                
    add     edx, 1
    movzx   ecx, byte ptr [edx]
    add     eax, 1
    test    cl, cl
    jnz     short loc_8048500
loc_8048518:                
    cmp     byte ptr [eax], 0
    jz      short loc_8048540
loc_804851D:                
    add     esi, 1
    add     edi, 1
    cmp     byte ptr [esi], 0
    jnz     short loc_80484F0
    jmp     loc_8048371
loc_8048530:                
    mov     esi, [ebp-0x1068]
    mov     edi, esi
    sar     edi, 0x1F
    jmp     loc_804845B
loc_8048540:                
    sub     esp, 8
    mov     ebx, [ebp-0x1080]
    push    9
    push    dword ptr [ebp-0x1084]
    call    kill
    add     esp, 0x10
loc_8048559:                
    mov     eax,0xfc
    int     0x80
    ret
loc_8048573:                
    mov     ebx, [ebp-0x1080]
    push    dword ptr [ebp-0x1094]
    push    0
    push    dword ptr [ebp-0x1084]
    push    0x0D
    or      dword ptr [ebp-0x1068], 0x2000
    call    ptrace
    add     esp, 0x10
    jmp     loc_8048371

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
kill:
    mov     edx,ebx
    mov     ebx,[esp+4]
    mov     ecx,[esp+8]
    mov     eax,0x25
    int     0x80
    mov     ebx,edx
    ret

child:                
    mov     edi, [ebp-0x1080]
    push    0
    push    0
    push    0
    push    0
    mov     ebx, edi
    call    ptrace
    mov     eax,0x14
    int     0x80
    pop     edx
    pop     ecx
    push    2
    push    eax
    call    kill
    add     esp, 0x10
call_oep:
        '''
    # NOTE: here I assume your input contains only one LOAD segment!
    # Shellcode will be placed after this segment.
    for s in e.segments:
        if s.type==lief.ELF.SEGMENT_TYPES.LOAD:
            s_size = s.virtual_size
            break
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
    segment.flag = lief.ELF.SEGMENT_FLAGS.PF_R | lief.ELF.SEGMENT_FLAGS.PF_W | lief.ELF.SEGMENT_FLAGS.PF_X
    segment.data = code
    segment.alignment = 8

    segment = e.add_segment(segment, base=0x10000, force_note=True)
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
