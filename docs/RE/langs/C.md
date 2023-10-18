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

## 基础数据类型

### 基础数据类型

#### 整数

- short, 2B
- int, 4B
- long, 4B
- long long, 8B(x64)

#### 浮点数

- float, 4B
- double, 8B

#### 字符 字符串

- char (ascii), 1B
- wchar_t (unicode), 2B

sz on windows: string terminated with a zero

```c
char szBuffer[] = "hello";
char *szBuffer  = "hello";
wchar_t szBuffer[] = L"hello";
wchar_t *szBuffer  = L"hello";
```

#### 结构类型

- struct
- union
- enum

#### 特殊类型

- auto
- void
- []
- - 

#### 类型修饰

- static
- signed
- unsigned
- const

## 变量

变量名规则：

- 以英文字符或者下划线起始
- 不能包含 空格、标点、类型说明符、运算符
- 字母区分大小写
- 有效长度max 255
- 不能是关键字

命名方法：

- 匈牙利
- 驼峰

变量类型：

- 全局变量
- 局部变量
- 静态变量

## 输入和输出

### 输出

printf

- %c, %s, %S
- %u, %d (int), %lld (long long)
- %e, %f
- %x, %X
- %p

转义字符

- \r \n \t
- \\ \’ \” \?

sprintf

```c
sprintf(szBuffer, "hello %s!", szName);
```

### 输入

scanf

- “%d”, &nNumber
- “%s”, szBuffer

## 运算符

### 算数运算符

- =
- ==, ≠, <, ≤, >, ≥
- +, -, *, /, %
- ++, —
- +=, -=, *=, /=, %=

### 位运算符

- &, |, ~, ^
- <<, >>

### 逻辑运算符

- &&, ||, !
- ? :

### 运算符优先级

## 选择结构

- if () {} else if () {} else {}
- switch () { case 1: { break; } default: { break; } }
- goto tag;

## 循环结构

- while (expr) {}
- do {} while (expr)
- for ( ; ; ) {}

## 函数

- 声明
- 定义
- 参数
- 返回值
- 变参函数

### 参数的细节

- 形式参数
- 实际参数
- 变参函数

```c
int test(int optcount, ...)
{
	va_list ap;
	va_start(ap, optcount);
	int nCount = 0;
	for (int i = 0; i < optcount; i++)
	{
		nCount += va_arg(ap, int);
	}
	va_end(ap);
	return nCount;
}
```

### 递归函数

## 数组指针

- 一维数组
```c
int arr[5] = { 0,1,2,3,4 };
int arr[5] = { [3] = 4 };
int arr[]  = { 0,1,2,3 };
int arr[]  = { 1,[5]=2 };
```
- 多维数组

```c
int nArr[2][2] = 
{
	{0,1},
	{2,3}
}
```

## 字符串

### 声明

```c
char szStr[] = { 'a','b','c',0 };
char szStr[] = "abc";
char * szStr = "abc";
```

### 字符串操作

- strcat
- strcpy
- strcmp

## 指针

符号：

- *
- &
- →

指针运算：地址 + 数据类型的宽度 * n

```c
int arr[5] = { 0 };
int * p = arr;
// use p
printf("%d", *p);
printf("%d", p[3]);
```

函数指针

```c
int func1(int a);

typedef int (*FuncType1) (int a);
FuncType1 pfunc = func1;
pfunc(1);
```

数组 指针 作为函数参数

```c
int addAll(int * arr, int nCount);
int* addAll(int * arr, int nCount);
int addAll(int * arr, int nCount, int * nRes);
```

内存操作

- char * szBuffer = malloc(sizeof(char) * 100)
- memset(szBuffer, 0xCC, sizeof(char) * 100)
- free(szBuffer)

## 预处理

```c
#define MAX_VALUE 256

#if EXPR1
...
#elif EXPR2
...
#else
...
#endif
```

## 复杂数据类型

### 结构体

```c
struct _Info
{
	char szName[50];
	int age;
	char szGender[10];
};

typedef struct _Info
{
	char szName[50];
	int age;
	char szGender[10];
} Info, *PInfo;

typedef struct
{
	char szName[50];
	int age;
	char szGender[10];
} Info;
```

符号：

- .
- →

### 枚举

```c
enum MyEnum
{
	one,
	two,
	three
};
```

## 结构体对齐

对齐1 2 4 8 16

MSVC默认对齐8 /Zp8

成员偏移 member offset：相对于结构体首地址的偏移

对齐规则：

- member offset % min(ZpValue, sizeof(member type)) == 0
- size % max(member type) == 0

设置对齐长度

```cpp
#pragma pack(1)
```

## 指针进阶

二级指针：指向的每一个空间都是一个一级指针

二级数组：

```c
int nArr[3][4];
int (*p)[4];
p = nArr;
// when p + i -> p + sizeof(int) * 4
for (size_t i = 0; i < 3; i++)
	for (size_t j = 0; j < 4; j++)
		printf("%d\r\n", *(p[i] +  k));
```

## 文件操作

### 写文件

fopen(path, mode)

- r: 读取，文件不存在or找不到即为失败
- w: 打开用于写入的空文件；如果给定文件存在，内容会被销毁
- a: 文件末尾追加；新数据写入之前不移除EOF；文件不存在创建文件
- r+: 读取写入文件，文件须存在
- w+: 读取写入空文件；文件存在，内容销毁
- a+: 读取和追加；新输入写入前移除EOF；写入完成，EOF不会还原；文件不存在创建文件

```c
void WriteFile(char * szFilePath, char * szBuffer)
{
	FILE * pFile;
	if ((pFile = fopen(szFilePath, "w")) == NULL)
	{
		printf("failed to open file.\r\n");
		fclose(pFile);
		exit(0);
	}
	int nRet = fwrite(szBuffer, sizeof(char) * (strlen(szBuffer) + 1), 1, pFile);
	fclose(pFile);
}
```

### 读文件

fseek(stream, offset, origin)

- SEEK_CUR
- SEEK_END
- SEEK_SET

```c
char * ReadFile(char * szFilePath)
{
	FILE * pFile;
	char * szReadBuffer;
	int nReadFileSize = 0;
	if ((pFile = fopen(szFilePath, "r")) == NULL)
	{
		printf("failed to read file.\r\n");
		fclose(pFile);
		exit(0);
	}
	fseek(pFile, 0, SEEK_END);
	nReadFileSize = ftell(pFile);
	rewind(pFile);
	szReadBuffer = malloc(sizeof(char) * (nReadFileSize + 1));
	if (szReadBuffer == NULL)
	{
		printf("failed to malloc memory.\r\n");
		fclose(pFile);
		exit(0);
	}
	memset(szReadBuffer, 0, nReadFileSize);
	int nResLen = 0;
	nResLen = fread(szReadBuffer, 1, nReadFileSize, pFile);
	if (nResLen != nReadFileSize)
	{
		printf("failed to read file.\r\n");
		fclose(pFile);
		exit(0);
	}
	fclose(pFile);
	return szReadBuffer;
}
```

## 异或加密字符串

```c
void xorcode(char * szBuffer, int nSize, char cKey)
{
	for (size_t i = 0; i < nSize; i++)
	{
		szBuffer[i] ^= cKey;
	}
}
```