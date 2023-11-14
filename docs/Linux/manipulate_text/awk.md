## SYNOPSIS

```bash
awk [-W option] [-F value] [-v var=value] [--] 'program text' [file ...]
awk [-W option] [-F value] [-v var=value] [-f program-file] [--] [file ...]
```

**第n列的信息**

- `$0`
- `$1`, `$2`, …
- …, `$(NF-1)`, `$NF`

**分割符**

- 输入分隔符：默认空格，变量名FS(Field Seperator)
- 输出分隔符：OFS(Output Field Seperator)

```bash
awk -F ":" '{print $1, $2}' filename
awk -v FS=":" '{print $1, $2}' filename
awk -v OFS="-" '{print $1, $2}' filename
awk 'BEGIN {OFS=","} {print $1, $2}' filename
```

## Option

| option     | usage                              |
| ---------- | ---------------------------------- |
| -F val     | FS, field separator                |
| -v var=val | assign val to program variable var |
| -f file    | program text is read from file     |
| --         | indicate unambiguous end of opts   |

## Program variable

| Program variable | Usage                            |
| ---------------- | -------------------------------- |
| FS               | Field separator, ' '             |
| OFS              | Output field separator, ' '      |
| RS               | Record separator, initially '\n' |
| ORS              | Output record separator, '\n'    |
| NF               | Number of field                  |
| NR               | Number of record                 |
| FNR              | File number of record            |
| FILENAME         | Current filename                 |
| ARGC             | arg count                        |
| ARGV             | arg vector                       |

## Program structure

**Program** = sequence of pattern {action} pairs and user function definitions

**Pattern:**

- BEGIN
- END
- expr
- expr, expr