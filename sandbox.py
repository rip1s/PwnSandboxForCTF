from pwn import *
import sys
import lief

argc = len(sys.argv)
if argc < 2:
    log.error('No input!')
try:
    e = lief.parse(sys.argv[1])
except:
    log.error('Fail to load elf!')
is64 = 0
if e.header.machine_type == lief.ELF.ARCH.x86_64:
    is64 = 1
if is64:
    context.arch = 'amd64'
    asmcode = '''
        pop r15
        xor	r9d, r9d
        mov	r8, 0x0FFFFFFFFFFFFFFFF
        xor	edi, edi
        mov	ecx, 0x21
        mov	edx, 3
        mov	esi, 0x4000
        call	mmap
        jmp getaddr
    getaddr2:
        pop rdi
        lea	rsi, [rax+0x2000]
        mov rcx,r15
        mov	edx, 0x10000011
        call	clone
        xor	edx, edx
        mov	edi, eax
        xor	esi, esi
        xor	eax, eax
        call	waitpid
        xor	eax, eax
        ret


    clone	:
        sub	rsi, 0x10
        mov	[rsi+8], rcx
        mov	[rsi], rdi
        mov	rdi, rdx
        mov	rdx, r8
        mov	r8, r9
        mov	r10, [rsp+8]
        mov	rax, 0x38
        syscall
        ret


    waitpid	:
        xor	r10, r10
        mov	rax, r10
        mov	al, 0x3D
        syscall
        ret


    open	:
        xor	rax, rax
        mov	al, 2
        syscall
        ret


    write	:
        xor	rax, rax
        mov	al, 1
        syscall
        ret


    close	:
        xor	rax, rax
        mov	al, 3
        syscall
        ret


    chroot	:
        xor	rax, rax
        mov	al, 0x0A1
        syscall
        ret


    exit	:
        xor	rax, rax
        mov	al, 0x3C
        syscall
        ret


    mmap	:
        movsxd	r10, ecx
        movsxd	r8, r8d
        or	r10d, 0x40
        movsxd	r10, r10d
        xor	rax, rax
        mov	al, 9
        syscall
        ret

    getaddr:
        call getaddr2
    jail	:
        pop r15
        push 0x1010101 ^ 0x7061
        xor dword ptr [rsp], 0x1010101
        mov rax, 0x6d5f6469752f666c
        push rax
        mov rax, 0x65732f636f72702f
        push rax
        mov rdi,rsp
        mov	esi, 1
        call	open
        mov r10,rax
                        /* push '0 0 1' */
        mov rax, 0x101010101010101
        push rax
        mov rax, 0x101010101010101 ^ 0x3120302030
        xor [rsp], rax

        mov	rsi, rsp
        mov	edx, 5
        mov rax,r10
        mov	ebx, eax
        mov	edi, eax
        call	write
        mov	edi, ebx
        call	close
                /* push '/proc/self/gid_map' */
        push 0x1010101 ^ 0x7061
        xor dword ptr [rsp], 0x1010101
        mov rax, 0x6d5f6469672f666c
        push rax
        mov rax, 0x65732f636f72702f
        push rax

        mov	rdi, rsp
        mov	esi, 1
        call	open
            /* push '0 0 1' */
        mov r10,rax
        mov rax, 0x101010101010101
        push rax
        mov rax, 0x101010101010101 ^ 0x3120302030
        xor [rsp], rax

        mov	rsi, rsp
        mov	edx, 5
        mov rax,r10
        mov	ebx, eax
        mov	edi, eax
        call	write
        mov	edi, ebx
        call	close
            /* push './' */
        push 0x706d742f

        mov	rdi, rsp
        call	chroot
        test	eax, eax
        jz	 loc_795
        xor	edi, edi
        call	exit
    loc_795:
    '''
else:
    context.arch = 'i386'
    asmcode = '''
        pop ebp
        xor edi,edi
        dec edi
        xor	ebx,ebx
        mov	esi, 0x21
        mov	edx, 3
        mov	ecx, 0x8000
        call	mmap
        jmp getaddr
    getaddr2:
        lea	ecx, [eax+0x4000]
        sub ecx,0x1c
        pop eax
        mov [ecx+8],eax
        mov [ecx+0xc],ebp
        xor ebx,ebx
        mov [ecx+4],ebx
        mov	ebx, 0x10000011
        mov [ecx],ebx
        xor edx,edx
        mov esi,edx
        mov edi,esi
        mov eax,0x78
        int 0x80
        test eax,eax
        jz jail
        xor	edx, edx
        mov	ebx,eax
        mov ecx,edx
        xor	eax, eax
        mov al,0x7
        int 0x80
        xor	eax, eax
        inc eax
        int 0x80

    open	:
        xor	eax, eax
        mov	al, 5
        int 0x80
        ret


    write	:
        xor	eax, eax
        mov	al, 4
        int 0x80
        ret


    close	:
        xor	eax, eax
        mov	al, 6
        int 0x80
        ret


    chroot	:
        xor	eax, eax
        mov	al, 61
        int 0x80
        ret


    exit	:
        xor	eax, eax
        inc eax
        int 0x80
        ret


    mmap	:
        mov eax,0xc0
        int 0x80
        ret

    getaddr:
        call getaddr2
    jail	:
        pop ebp

        /* push '/proc/self/uid_map\\x00' */
        push 0x1010101
        xor dword ptr [esp], 0x1017160
        push 0x6d5f6469
        push 0x752f666c
        push 0x65732f63
        push 0x6f72702f

        mov ebx,esp
        mov	ecx, 1
        xor edx,edx
        call	open
        mov ebx,eax
        push 0x31
        push 0x20302030

        mov	ecx, esp
        mov	edx, 5
        call	write
        call	close

        /* push '/proc/self/gid_map\\x00' */
        push 0x1010101
        xor dword ptr [esp], 0x1017160
        push 0x6d5f6469
        push 0x672f666c
        push 0x65732f63
        push 0x6f72702f

        mov ebx,esp
        mov	ecx, 1
        xor edx,edx
        call	open
        mov ebx,eax
        push 0x31
        push 0x20302030

        mov	ecx, esp
        mov	edx, 5
        call	write
        call	close

        /* push './\\x00' */
        push 0x1010101
        xor dword ptr [esp], 0x1012e2f

        mov	ebx, esp
        call	chroot
        test	eax, eax
        jz	 loc_795
        call	exit
    loc_795:
    '''

a = asm(asmcode)
log.success('Original Entry Point:' + hex(e.entrypoint))
if e.is_pie:
    log.info('PIE detected')
    if is64:
        final = asm('''
        /*memory brute force method*/
        xor rbx,rbx
        mov rdi,0x0000555555550000
        mov rsi,0x1000
        mov rdx,5
    l:
        add rdi,0x1000
        call mprotect
        cmp rax,rbx
        jl l
        add rdi,{}
        jmp rdi
    mprotect:
        xor rax,rax
        mov al,10
        syscall
        ret
        '''.format(hex(e.entrypoint)))
    else:
        final = asm('''
        xor esi,esi
        mov ebx,esi
        mov ecx,0x1000
        mov edx,5
    l:
        add ebx,0x1000
        call mprotect
        cmp eax,esi
        jl l
        add ebx,{}
        jmp ebx
    mprotect:
        xor eax,eax
        mov al,125
        int 0x80
        ret
        '''.format(hex(e.entrypoint)))
else:
    if is64:
        final = asm("mov rax,{};jmp rax".format(hex(e.entrypoint)))
    else:
        final = asm("mov eax,{};jmp eax".format(hex(e.entrypoint)))
patch = []
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
segment = e.add_segment(segment, base=0x1000, force_note=True)
log.success('Add segment done.')
e.header.entrypoint = segment.virtual_address
log.success('New Entry Point:' + hex(segment.virtual_address))
e.write(sys.argv[1] + '_sandbox')
