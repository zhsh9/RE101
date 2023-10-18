## 基础知识

### C语言标准

- K&R
- C89/C90
- C99
- C11

### C代码编写步骤

1. 确定需求
2. 设计程序
3. 编写代码
4. 运行
5. 测试和调试
6. 维护和修改

### 二进制代码生成步骤

1. 预处理：复制头文件内容，替换宏的内容等
2. 编译：将C代码编译为汇编代码
3. 汇编：将汇编代码汇编为二进制代码
4. 链接：加载启动代码和库文件等

```bash
# preprocess
gcc -E a.c -o a.i
# compile
gcc -S a.i -o a.s
# assemble
gcc -c a.s -o a.o
# link
gcc a.o -o a.out
```

```bash
# 32bit compile
gcc a.c -m32
# dependencies:
sudo apt install build-essential gcc-multilib g++-multilib gcc g++
```

### 进制和位

进制

- bin
- oct
- dec
- hex

位

- 32bit
- 64bit

字宽

- QWORD 64bit
- FWORD 48bit
- DWORD 32bit
- WORD 16bit
- BIT 1bit

### VS常规操作

- F5 运行
- F9 断点
- F10 单步步过
- F11 单步步入

### Clion常规操作

制作图标：

``` title="/usr/share/applications"
[Desktop Entry]
Encoding=UTF-8
Name=Clion
Comment=Clion-2023.2
Exec=/home/kali/opt/clion-2023.2/bin/clion.sh
Icon=/home/kali/opt/clion-2023.2/bin/clion.svg
Categories=Application;Development;Java;IDE
Version=2023.2
Type=Application
```

常规操作：

- Shift + F10 run
- Shift + F9 debug
- F7 步入
- F8 步过

### Windows API

- A: Ascii
- W: Unicode
- Ex: Extended version