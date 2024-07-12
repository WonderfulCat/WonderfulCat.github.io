#### 头信息
```c
typedef struct elf32_hdr {
  unsigned char e_ident[EI_NIDENT];		//.ELF
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;					// 程序头偏移
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;				//程序头每个对象大小
  Elf32_Half e_phnum;					//程序头数组长度
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
} Elf32_Ehdr;
```


#### 程序头信息
```c
typedef struct elf32_phdr {
  Elf32_Word p_type;					//程序头类型
  Elf32_Off p_offset;					//相对于程序起始位置的偏移
  Elf32_Addr p_vaddr;					//虚拟地址
  Elf32_Addr p_paddr;					//物理地址(没用)
  Elf32_Word p_filesz;					//文件映射大小
  Elf32_Word p_memsz;					//内存映射大小
  Elf32_Word p_flags;					//读取,写,执行属性
  Elf32_Word p_align;					//对齐(没用,都是按CPU)
} Elf32_Phdr;
```
#### PT_PHDR (6) 必须在最前面**给出了程序头部表自身的大小和位置，既包括在文件中也包括在内存中的信息** 
#### PT_INERP(3) 加载器linker路径
#### PT_LOAD(1) 指示加载入内存的段信息 **只有PT_LOAD的段指示的信息才会加载入内存**
#### PT_GNU_RELRO (1685382482) 指示加载信息的某一段为只读
#### PT_DYNAMIC(2) 动态段 
动态段地址数据为数组, 结构如下: **以0数组表示结束**
```c
typedef struct dynamic {
  Elf32_Sword d_tag;				//key
  union {
    Elf32_Sword d_val;
    Elf32_Addr d_ptr;
  } d_un;							//val
} Elf32_Dyn;
```

---
##### 字符串表 DT_STRTAB(5)		//字符串表	0xCC8
---
##### 导入库表 DT_NEEDED(1) 	//导入库表 (会有多个导入库)	**d_val = 字符串表偏移**
---
##### 符号表 DT_SYMTAB(6) 		//符号表 06 00 00 00 48 01 00 00
地址数据 = 结构体数组.
第一个结构体全为0,不使用

```c
typedef struct efl32_sym{
	Elf32_Word 	st_name;		//字符串表中的偏移
	Elf32_Word	st_value;		//地址 
	Elf32_Word	st_size;		//大小
	unsigned char st_info;
	unsigned char st_other;
	Elf32_Half st_shndx;
}Elf32_Sym;
```

---
##### 导入表 DT_JMPREL(23) 			//导入表 17 00 00 00 94 33 00 00
```c
typedef struct elf32_rel {
  Elf32_Addr r_offset;
  Elf32_Word r_info;
} Elf32_Rel;
```
地址数据 = 结构体数组.(每项为8字节) . 
索引大小 = DT_PLTRELSZ / 8
```
78 8D 01 00 	//将需要的外部函数地址写入到此地址上
16				//导入类型 
5B 00 00		//符号表中的索引
```
##### 导入表大小 DT_PLTRELSZ(2)	 	//导入表大小 02 00 00 00 10 05 00 00
---
##### 重定位表 DT_REL(17)					//重定位表 11 00 00 00 FC 18 00 00
```c
typedef struct elf32_rel {
  Elf32_Addr r_offset;
  Elf32_Word r_info;
} Elf32_Rel;
```
地址数据 = 结构体数组.(每项为8字节) . 
索引大小 = DT_RELSZ / 8
```
70 40 00 00 	//虚拟地址
17 				//类型 
00 00 00 		//符号表中的索引
```
##### 重定位表大小 DT_RELSZ(18)		//重定位表大小	12 00 00 00 98 1A 00 00

---
##### 导出表 (HASH表)
**DT_HASH 4  #老版本 04 00 00 00 08 14 00 00
DT_GUN_HASH 0x6FFFFEF5 #新版本 **


```c
nbucket = ((unsigned *)(IMAGE_BASE + p->d_un.d_ptr))[0];				//4字节 hash table lengt
nchain = ((unsigned *)(IMAGE_BASE + p->d_un.d_ptr))[1];					//4字节 chain length
bucket = (unsigned *)(IMAGE_BASE + p->d_un.d_ptr + 8);					//跳过8字节后是bucket addr
chain = (unsigned *)(IMAGE_BASE + p->d_un.d_ptr + 8 + nbucket * 4);		//跳过bucket后是chain addr
```

0x00. hash table

| name  | hash_code  | index = hash_code % nbucket | bucket[index]|
| --- | --- |---|---|
| memmove    |  0x3c446b5   |	 0x3c446b5 % 0x83 = 0xC| bucket[C] = 0x2C	|
| optarg    |  0x767a887   |	 0x767a887 % 0x83 = 0xD| bucket[D] = 0x7D	|
| memset    |  0x73c49c4   |	 0x73c49c4 % 0x83 = 0xD| bucket[D] = 0x7D	|
| fprintf    |  0xd7905c6   |	 0xd7905c6 % 0x83 = 0xD| bucket[D] = 0x7D	|
| __dso_handle    |  0x3b3f175   |	 0x3b3f175 % 0x83 = 0xD| bucket[D] = 0x7D	|



0x01 chain table

|  index   |  val   |
| --- | --- |
|  0x2C   |  0x0   |
|	0x7D	|	0x2D |
|	0x2D	|	0x14	|
|	0x14	|	0x2	|
|	0x2	|	0x0	|

0x03 查找步骤

1. hash 需要查找的函数名称. **hash_code = elfhash(name);**
2. 计算hash_code在bucket中的索引. **index = hash_code % nbucket;**
3. 查找符号表索引. **symtab_offset = bucket[index];**
4. 查找符号表找到对应数据. **Elf32_Sym = symtab+symtab_offset**
5. 判断符号表中名称是否与需要查找的函数名称是否一致, **相等则表示成功找到 **. 
6. 使用符号表索引遍历查找 **symtab_offset = chain[symtab_offset]**.
7. 重复4~7步骤,直到找到为止.

例:  查找 __dso_handle 步骤:

```c
	char *fun_name = "__dso_handle";
	unsigned index = elfhash(fun_name) % nbucket;

	for (unsigned n = bucket[index]; n != 0; n = chain[n])
	{
		char *name = str_tab + (sym_table + n)->st_name;
		if (!strcmp(name, fun_name))
			printf("Found...\n");
	}
```

[参考代码](https://github.com/WonderfulCat/Elf_Loader)