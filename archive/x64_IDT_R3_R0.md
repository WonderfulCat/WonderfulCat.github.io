---
layout: default
---

# x64 使用IDT中断R3提权至R0调用

###### 内核版本: win10版本1703
## 一.创建IDT表

```c
创建一个21H中断：	
eq fffff800`54862210 4000ee00`00101110 
eq fffff800`54862218 1
我的测试环境中断代码地址为:0x0140001110
```

## 二. 修改CR4中SMEP,SMAP

![CR4寄存器](./x64_IDT_R3_R0/1ed16696e603477782c029445c031804.jpeg#pic_center)

```c
CR4第20位(SMEP)和21位(SMAP)会禁止0环执行\访问3环代码. 我们的中断执行代码就在3环,所以这里需要修改一下.
原始: 	cr4 = 0000000000170678
修改后: 	cr4 = 0000000000070678
```

## 三. KPTI内核页表隔离

```c
由于KPTI的存在,3环CR3和进入0环后CR3并不一致. 
所以想调用0环内核代码必须切换到内核的CR3. 
----------------------------------------
参考一下内核代码KiBreakpointTrapShadow中实现的CR3切换:
swapgs							;切换GS指向KPCR
mov     rsi, gs:7000h			;获取内核CR3
mov     cr3, rsi				;切换至内核CR3
```

```c
除了CR3切换外,还要注意页表是否有执行权限.必要时需要修改PXE,PPE,PDE,PTE属性.
我的测试环境是并没有这种情况发生,所以无需设置.
```
![页表属性](./x64_IDT_R3_R0/d6981073ced64b2e9fb3b567dd81da10.jpeg#pic_center)

## 四. 内核栈环境

这里我们参考一下KiBreakpointTrapShadow中的代码实现(只看关键代码):
  1.切换栈:
```c
lea     rsi, [rsp+38h]			;内核栈底
mov     rsp, gs:7008h			;内核线程栈指针
push    qword ptr [rsi-8]		;SS
push    qword ptr [rsi-10h]		;RSP
push    qword ptr [rsi-18h]		;RFLAGS
push    qword ptr [rsi-20h]		;CS
push    qword ptr [rsi-28h]		;RIP
mov     rsi, [rsi-38h]			;还原RSI
```
2. 下面我们来分析一下栈空间:

```c
进入内核后如果没有指定内核栈会使用TSS中默认栈,这里看一下进入内核后的栈情况:
使用GDTR得到默认栈底地址: 0xfffff80054866200 ,往上看一下栈内信息:

fffff800`548661c8  00000000`00000000	;rsi
fffff800`548661d0  00000000`00000000	;rax
fffff800`548661d8  00000001`40001114	;rip
fffff800`548661e0  00000000`00000033	;cs
fffff800`548661e8  00000000`00000246	;rflag
fffff800`548661f0  00000000`0014fee8	;rsp
fffff800`548661f8  00000000`0000002b	;ss
fffff800`54866200  00000000`00000000

此时rsp为fffff800`548661c8 + 38h = fffff800`54866200
lea     rsi, [rsp+38h]			;使RSI指向内核栈底
mov     rsp, gs:7008h			;切换至内核线程栈地址

使用RSI将内核栈内容转移到内核线程栈
push    qword ptr [rsi-8]		;SS
push    qword ptr [rsi-10h]		;RSP
push    qword ptr [rsi-18h]		;RFLAGS
push    qword ptr [rsi-20h]		;CS
push    qword ptr [rsi-28h]		;RIP

mov     rsi, [rsi-38h]			;还原RSI
到此为止内核环境己经建立好了. 此后就可以调用内核代码了.
```
3. 最后一步,返回需要还原栈环境及CR3:

```c
1.还原rsp
2.还原cr3
3.将PUSH进的寄存器POP出来等.
mov     rsp,RSP_ORG		;还原rsp
mov     rax,CR3_ORG		;还原cr3
mov     cr3,rax			
pop     rsi				;还原rsi
pop     rax				;还原rax

```
## 五. 结束
总结: 这种方法提权非常麻烦.