#### 查找PID
遍历 **/proc/%zu/cmdline** 来根据进程名称查找pid.

#### 查找模块内存基地址
遍历 **/proc/%d/maps** 来查找指定模块的基址.

#### 查找dlopen, dlsym, dlerror,mmap函数地址
1. 使用第2步方法查找到**linker**,**libc.so**基址. 
> [!NOTE] 模块基址
> dlopen,dlsym,dlerror,mmap 的基址在不同版本系统中可能在不同的库中.
3. 目标函数地址 = 本地函数地址 - 本地模块基址 + 目标模块基址. (没有ASLR)

#### 使用ptrace
1. 附加进程.
2. 保存寄存器信息.
3. 使用 **ptrace_call** 调用**mmap**分配内存空间,将字符串参数写入其中. 
4. 使用 **ptrace_call** 调用**dlopen**, 加载需要注入的so文件.
5. 使用 **ptrace_call** 调用**dlsym**, 得到调用函数地址.
6. 使用 **ptrace_call** 调用函数.
7. 还原寄存器信息.
8. 停止附加进程.

#### 其他
1. 如果不想使用**mmap**分配空间保存字符串参数, 还可以使用栈来保存.
2. 修改pc时需要注意一下处理 thumb 和 arm 地址及T位.
3. 调用 **ptrace_call** 前修改LR寄存器为0, 目标进程在ret时会触发异常, 以便重新拿到控制权.

[参考代码](https://github.com/WonderfulCat/android_arm32_inject_so)