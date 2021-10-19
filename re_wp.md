# welcome_to_the_world_of_re

本体非常简单，共有两种做法

## 解法一

直接shift+f12查看字符串，直接就能找到flag

![](https://i.loli.net/2021/09/22/FEQSP96aAguwzkM.png)

## 解法二

一步一步查看函数列表，发现最后一个函数指针是验证字符串相等，就能直接找到flag

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int i; // [rsp+2Ch] [rbp-4h]

  sub_401800(argc, argv, envp);
  puts("<---  moectf2021  --->");
  puts(" [CheckIn] Welcome to moectf2021.");
  puts("This is a really eazy chall. I believe it is easy for you to get the flag");
  puts("Now input your flag and I will check it : ");
  scanf("%100s", &unk_407040);
  for ( i = 0; i <= 3; ++i )
    ((void (__fastcall *)(void *))funcs_4016DE[i])(&unk_407040);
  if ( byte_403020 )
  {
    puts("Congratulations!!!");
    puts("See you next chall!!!");
  }
  else
  {
    puts("Something went wrong!   QwQ");
    puts("Try againt!!!");
  }
  puts("按任意键以继续");
  getchar();
  getchar();
  return 0;
}
```

双击`funcs_4016DE`可以跟进

```
.data:0000000000403040 funcs_4016DE    dq offset sub_401550    ; DATA XREF: main+66↑o
.data:0000000000403040                                         ; main+6D↑r
.data:0000000000403040                 dq offset sub_401585
.data:0000000000403040                 dq offset sub_4015C5
.data:0000000000403040                 dq offset sub_401606
```

`funcs_4016DE`是函数列表，里面有四个函数指针，前三个分别验证flag的长度、头、尾，最后一个验证flag的内容，同样可以得到flag

`moectf{W31C0Me_t0_m03CTF_2021_w0o0o0oooo0ooooo0o0oooo0!!!}`

# A_game

数独题

```
check1();	行验证
check2();	列验证
check3();	对角线验证
```

数独如下

```
0 0 5 0 0 4 3 6 0 
0 0 0 0 5 0 0 2 4 
0 4 9 6 7 0 0 0 0 
1 0 6 0 2 0 0 3 0 
9 0 0 7 0 0 1 0 8 
0 3 0 0 0 5 0 9 0 
2 0 0 5 0 7 0 0 9 
7 0 4 0 0 0 8 0 0 
0 9 0 0 4 0 0 0 6 
```

选择手动解数独，或者去在线网站自动解数独，或者自己写脚本解数独

得到raw input : 8291767138932581849755263447186268341129653538127

输入到程序中得到flag

`moectf{S0_As_I_prAy_Un1imited_B1ade_WOrks---E1m1ya_Shiro}`

# 大佬请喝coffee

java逆向，用jadx或者jd-gui都可以看到源代码

本质上就是解一个方程组

![](https://i.loli.net/2021/09/22/aLW4jTGvpS12xed.png)

写出exp

```python
from z3 import *
bufArray = [Int("buf{}".format(i)) for i in range(9)]
s = Solver()
s.add(bufArray[0]*4778+bufArray[1]*3659+bufArray[2]*9011+bufArray[3]*5734+bufArray[4]*4076+bufArray[5]*6812+bufArray[6]*8341+bufArray[7]*6765+bufArray[8]*7435==5711942)
s.add(bufArray[0]*4449+bufArray[1]*5454+bufArray[2]*4459+bufArray[3]*5800+bufArray[4]*6685+bufArray[5]*6120+bufArray[6]*7357+bufArray[7]*3561+bufArray[8]*5199==4885863)
s.add(bufArray[0]*3188+bufArray[1]*6278+bufArray[2]*9411+bufArray[3]*5760+bufArray[4]*9909+bufArray[5]*7618+bufArray[6]*7184+bufArray[7]*4791+bufArray[8]*8686==6387690)
s.add(bufArray[0]*8827+bufArray[1]*7419+bufArray[2]*7033+bufArray[3]*9306+bufArray[4]*7300+bufArray[5]*5774+bufArray[6]*6588+bufArray[7]*5541+bufArray[8]*4628==6077067)
s.add(bufArray[0]*5707+bufArray[1]*5793+bufArray[2]*4589+bufArray[3]*6679+bufArray[4]*3972+bufArray[5]*5876+bufArray[6]*6668+bufArray[7]*5951+bufArray[8]*9569==5492294)
s.add(bufArray[0]*9685+bufArray[1]*7370+bufArray[2]*4648+bufArray[3]*7230+bufArray[4]*9614+bufArray[5]*9979+bufArray[6]*8309+bufArray[7]*9631+bufArray[8]*9272==7562511)
s.add(bufArray[0]*6955+bufArray[1]*8567+bufArray[2]*7949+bufArray[3]*8699+bufArray[4]*3284+bufArray[5]*6647+bufArray[6]*3175+bufArray[7]*8506+bufArray[8]*6552==5970432)
s.add(bufArray[0]*4323+bufArray[1]*4706+bufArray[2]*8081+bufArray[3]*7900+bufArray[4]*4862+bufArray[5]*9544+bufArray[6]*5211+bufArray[7]*7443+bufArray[8]*5676==5834523)
s.add(bufArray[0]*3022+bufArray[1]*8999+bufArray[2]*5058+bufArray[3]*4529+bufArray[4]*3940+bufArray[5]*4279+bufArray[6]*4606+bufArray[7]*3428+bufArray[8]*8889==4681110)
print(s.check())
print(s.model())
```

flag

`moectf{moectf{EXcalibur}}`

# baby_bc

题目附件是llvm ir code，直接阅读比较困难，所以先编译成可执行程序，这里在ubuntu编译

```bash
$ llvm-as chall.ll
$ llc chall.bc
$ clang chall.s
```

可以得到a.out，能直接拖进ida，定位到关键代码

```c
  if ( strlen(input) != 40 )
  {
    puts("Wrong length!");
    exit(0);
  }
  v10 = strlen(dest);
  func_114514(s, dest, v10);
  v11 = strlen(input);
  func_1919810(s, input, v11);
  v12 = strlen(input);
  HSencode(input, v12, v7);
  for ( i = 0; ; ++i )
  {
    v3 = i;
    if ( v3 >= strlen(v7) )
      break;
    if ( v7[i] != bytes_114514[i] )
    {
      printf("rua! you are wrong!");
      exit(0);
    }
  }
```

 func_114514和 func_1919810共同构成RC4加密

HSencode其实是一个类似base的加密，分析其加密逻辑之后发现是将输入的三个字符转换成四个字符

首先将断点打在RC4加密之后，获取RC4加密的结果，我输入的flag为40个A，得到的加密结果是exp中的table，table再异或ord('A')就能得到RC4加密过程中与明文异或的密钥。

```python
table=[0x20,0x77,0xDF,0x77,0x4C,0x72,0x2C,0x43,0x3D,0x52,0x86,0xD9,0x0C,0xBC,0x1E,0x9B,0x88,0x72,0xE9,0x45,0xA1,0x1D,0x6D,0x3B,0xB2,0xD2,0xD9,0xAE,0xA4,0x15,0x2E,0x16,0x1B,0x73,0x94,0xEB,0x11,0x84,0x4C,0xCE]
for i in range(len(table)):
    table[i] ^= ord('A')
en_flag="@BdxRTbRBbjIVf`PEyqe^\^\|cc|JRubaGLytHeRI@jgNegHU[Myy]=="
tmp = []
dest = [0]*100
flag=""
for i in en_flag:
    tmp.append(ord(i)-61)
for i in range(len(tmp)//4):
    dest[i*3] = (tmp[i*4]<<2) | (tmp[i*4+1]>>4)
    dest[i*3 + 1] = ((tmp[i*4+1]&0b1111)<<4) | (tmp[i*4+2]>>2)
    dest[i*3 + 2] = ((tmp[i*4+2]&0b11) << 6) | (tmp[i*4+3])
for i in range(40):
    flag+=chr((dest[i])^table[i])
print(flag)
```

得到flag

`moectf{Y0u_Kn0w_1lVm_ir_c0d3_A_l0t_!1!1}`