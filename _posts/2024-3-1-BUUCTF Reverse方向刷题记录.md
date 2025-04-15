---
title: BUUCTF Reverse方向刷题记录
date: 2024-3-1 00:00:00 +0800
categories: [刷题记录]
tags: [CTF, REVERSE]
---

[TOC]

## 不一样的flag

------

迷宫题，一个5x5的迷宫。

*1111

01000

01010

00010

1111#

222441144222

------



## SimpleRev

------

<img src="assets/img/2024/1/image-20240115145912318.png" alt="image-20240115145912318" style="zoom: 67%;" />

![image-20240115145950371](assets/img/2024/1/image-20240115145950371.png)

脚本

```c
#include<stdio.h>
#include<string.h>
int main(){
	char key[]="adsfkndcls",text[]="killshadow",j,flag[10];
	int i;
	for(i=0;i<10;i++){
		for(j='A';j<='z';j++){
			if((j - 39 - key[i] + 97) % 26 + 97==text[i]){
				flag[i]=j;
				break;
			}
		}
	}
	printf("%s",flag);
	return 0;
}
```

flag: flag{KLDQCUDFZO}

------





------

![image-20240116132926006](assets/img/2024/1/image-20240116132926006.png)

这里有两步，第一步：是在主函数`main`上输入flag，再调用`Encrypt`来进行加密

```java
    public static void main(String[] args) {
        Scanner s = new Scanner(System.in);
        System.out.println("Please input the flag ：");
        String str = s.next();
        System.out.println("Your input is ：");
        System.out.println(str);
        char[] stringArr = str.toCharArray();
        Encrypt(stringArr);
    }
```

第二步就是通过逆向`Encrypt`函数来获取flag

```java
public static void Encrypt(char[] arr) {
        ArrayList<Integer> Resultlist = new ArrayList<>();
        for (char c : arr) {
            int result = (c + '@') ^ 32;	//输入的每个字符都加上64 ^ 32
            Resultlist.add(Integer.valueOf(result));
        }
        int[] KEY = {180, 136, 137, 147, 191, 137, 147, 191, 148, 136, 133, 191, 134, 140, 129, 135, 191, 65};
        ArrayList<Integer> KEYList = new ArrayList<>();
        for (int i : KEY) {
            KEYList.add(Integer.valueOf(i));
        }
        System.out.println("Result:");
        if (Resultlist.equals(KEYList)) {	//和KEY进行比较
            System.out.println("Congratulations！");
        } else {
            System.err.println("Error！");
        }
    }
```

脚本

```c
#include<stdio.h>
#include<string.h>
int main(){
	int KEY[18] = {180, 136, 137, 147, 191, 137, 147, 191, 148, 136, 133, 191, 134, 140, 129, 135, 191, 65};
	char flag[18];
	int i;
	for(i=0;i<18;i++){
		flag[i]=(KEY[i]^32)-64;
	}
	printf("%s",flag);
	return 0;
}
```

------



## [GXYCTF2019]luck_guy

------

<img src="assets/img/2024/1/image-20240116164408671.png" alt="image-20240116164408671" style="zoom:50%;" />

f2脚本

```c
#include<stdio.h>
int main(){
	char f2[]="icug`ofF7x\\";
	for (int j = 0; j <= 7; ++j )
	{
		if ( j % 2 == 1 )
			f2[j] -= 2;
		else
			--f2[j];
	}
	printf("%s",f2);
	return 0;
}
```

f1后面接f2就是flag，记得把外面的GXY改成flag。flag: flag{do_not_hate_me}

------



## 刮开有奖

------

在伪代码中，有a1+ 4 * i，a1+4 *result，这样的字符。int占四个字节，所以需要乘4。如果是char类型，就不需要。`*(a1+4*i)`，也就是a1[i]，a1+4 * result，也就是a1[result]。将伪代码的寻址方式改为数组寻址，然后将(_DWORD*) 删掉，因为这是汇编的表示。所以伪代码变成了C语言代码。

```c
#include<stdio.h>
#include<string.h>
int __cdecl sub_4010F0(char a1[], int a2, int a3);

int main(){
	char v7[11]="ZJSECaNH3ng";
	sub_4010F0(v7, 0, 10);
	for(int i=0;i<11;i++)
		printf("%c",(char)v7[i]);
	return 0;
}

int __cdecl sub_4010F0(char a1[], int a2, int a3)
{
	int result; // eax
	int i; // esi
	int v5; // ecx
	int v6; // edx
	
	result = a3;
	for ( i = a2; i <= a3; a2 = i )
	{
		v5 = i;
		v6 = *(i + a1);
		if ( a2 < result && i < result )
		{
			do
			{
				if ( v6 > *(a1 + result) )
				{
					if ( i >= result )
						break;
					++i;
					*(v5 + a1) = *(a1 + result);
					if ( i >= result )
						break;
					while ( *(a1 + i) <= v6 )
					{
						if ( ++i >= result )
							goto LABEL_13;
					}
					if ( i >= result )
						break;
					v5 = i;
					*(a1 + result) = *(i + a1);
				}
				--result;
			}
			while ( i < result );
		}
		LABEL_13:
		*(a1 + result) = v6;
		sub_4010F0(a1, a2, i - 1);
		result = a3;
		++i;
	}
	return result;
}
```

得到加密之后的字符：3CEHJNSZagn

String567是jMp，String234是WP1。

flag{UJWP1jMp}

------



## 简单注册器

------

![image-20240125142828885](assets/img/2024/1/image-20240125142828885.png)

脚本

```c
#include<stdio.h>
int main(){
	char x[] = "dd2940c04462b4dd7c450528835cca15";
	x[2] = (char) ((x[2] + x[3]) - 50);
	x[4] = (char) ((x[2] + x[5]) - 48);
	x[30] = (char) ((x[31] + x[9]) - 48);
	x[14] = (char) ((x[27] + x[28]) - 97);
	for (int i = 0; i < 16; i++) {
		char a = x[31 - i];
		x[31 - i] = x[i];
		x[i] = a;
	}
	printf("flag",x);
	return 0;
}
```

flag{59acc538825054c7de4b26440c0999dd}

------



## [GWCTF 2019]pyre

------

```python
# Visit https://www.lddgo.net/string/pyc-compile-decompile for more information
# Version : Python 2.7

print 'Welcome to Re World!'
print 'Your input1 is your flag~'
l = len(input1)
for i in range(l):
    num = ((input1[i] + i) % 128 + 128) % 128
    code += num

for i in range(l - 1):
    code[i] = code[i] ^ code[i + 1]

print code
code = [
    '\x1f',
    '\x12',
    '\x1d',
    '(',
    '0',
    '4',
    '\x01',
    '\x06',
    '\x14',
    '4',
    ',',
    '\x1b',
    'U',
    '?',
    'o',
    '6',
    '*',
    ':',
    '\x01',
    'D',
    ';',
    '%',
    '\x13']

```

脚本

```c
#include<stdio.h>
int main(){
	char code[] = {
		'\x1f',
		'\x12',
		'\x1d',
		'(',
		'0',
		'4',
		'\x01',
		'\x06',
		'\x14',
		'4',
		',',
		'\x1b',
		'U',
		'?',
		'o',
		'6',
		'*',
		':',
		'\x01',
		'D',
		';',
		'%',
		'\x13'};
	int i;
	for(i=21;i>=0;i--){
		code[i]^=code[i+1];
	}
	for(i=0;i<=22;i++){
		if(code[i]<=20)
			code[i]+=128;
		code[i]-=i;
	}
	printf("%s",code);
	return 0;
}
```

flag{Just_Re_1s_Ha66y!}

------



## [ACTF新生赛2020]easyre

------

脱壳![image-20240125152648132](assets/img/2024/1/image-20240125152648132.png)

![image-20240125155506512](assets/img/2024/1/image-20240125155506512.png)

![image-20240125155559796](assets/img/2024/1/image-20240125155559796.png)

脚本

```c
#include<stdio.h>
#include<string.h>
int main(){
	char s[]={126,
		125, 124, 123, 122, 121, 120, 119, 118, 117, 116, 
		115, 114, 113, 112, 111, 110, 109, 108, 107, 106, 
		105, 104, 103, 102, 101, 100,  99,  98,  97,  96, 
		95,  94,  93,  92,  91,  90,  89,  88,  87,  86, 
		85,  84,  83,  82,  81,  80,  79,  78,  77,  76, 
		75,  74,  73,  72,  71,  70,  69,  68,  67,  66, 
		65,  64,  63,  62,  61,  60,  59,  58,  57,  56, 
		55,  54,  53,  52,  51,  50,  49,  48,  47,  46, 
		45,  44,  43,  42,  41,  40,  39,  38,  37,  36, 
		35,  32,  33,  34,   0
	};
	char v4[]="*F'\"N,\"(I?+@",flag[99];
	int i;
	for ( i = 0; i <= 11; ++i ){
		flag[i]=strchr(s,v4[i])-&s[0]+1;
	}
	printf("%s",flag);
	return 0;
}
```

------



## findit

------

![image-20240125161958337](assets/img/2024/1/image-20240125161958337.png)

脚本

```c
#include<stdio.h>
int main(){
	char a[] = {'T', 'h', 'i', 's', 'I', 's', 'T', 'h', 'e', 'F', 'l', 'a', 'g', 'H', 'o', 'm', 'e'};
	char x[17];
	for (int i = 0; i < 17; i++) {
		if ((a[i] < 'I' && a[i] >= 'A') || (a[i] < 'i' && a[i] >= 'a')) {
			x[i] = (char) (a[i] + 18);
		} else if ((a[i] >= 'A' && a[i] <= 'Z') || (a[i] >= 'a' && a[i] <= 'z')) {
			x[i] = (char) (a[i] - '\b');
		} else {
			x[i] = a[i];
		}
	}
	printf("%s",x);
	return 0;
}
```

输入LzakAkLzwXdsyZgew得到flag<img src="assets/img/2024/1/image-20240125162121032.png" alt="image-20240125162121032" style="zoom: 33%;" />flag{c164675262033b4c49bdf7f9cda28a75}

------



## [ACTF新生赛2020]rome

------

![image-20240126144332781](assets/img/2024/1/image-20240126144332781.png)

对字母进行加密，原文和密文的对应关系脚本

```c
#include<stdio.h>
int main(){
	char v1[]="ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	char v2[]="abcdefghijklmnopqrstuvwxyz";
	char v3[26],v4[26];
	int i,a,b;
	for(i=0;i<26;i++){
		v3[i]=(v1[i]-51)%26+65;
		v4[i]=(v2[i]-79)%26+97;
	}
	printf("%s\n%s\n\n%s\n%s",v1,v3,v2,v4);
	return 0;
}
```

```
原文：	ABCDEFGHIJKLMNOPQRSTUVWXYZ
密文：	OPQRSTUVWXYZABCDEFGHIJKLMN

原文：	abcdefghijklmnopqrstuvwxyz
密文：	stuvwxyzabcdefghijklmnopqr

密文：	  Qsw3sj_lz4_Ujw@l
flag:	Cae3ar_th4_Gre@t
```

------



## rsa

------

IDA打开pub.key后，转换里面的十六进制为字符串，提取出公钥。

```
-----BEGIN PUBLIC KEY-----
MDwwDQYJKoZIhvcNAQEBBQADKwAwKAIhAMAzLFxkrkcYL2wch21CM2kQVFpY9+7+
/AvKr1rzQczdAgMBAAE=
-----END PUBLIC KEY-----
```

在http://tool.chacuo.net/cryptrsakeyparse对公钥进行解析

<img src="assets/img/2024/1/image-20240126174900117.png" alt="image-20240126174900117" style="zoom:50%;" />

获取到e = 10001，n=86934482296048119190666062003494800588905656017203025617216654058378322103517(模数转换为十进制)

使用yahu或者http://www.factordb.com/index.php?query=86934482296048119190666062003494800588905656017203025617216654058378322103517 通过n解析p,q

![image-20240126175117244](assets/img/2024/1/image-20240126175117244.png)

用rsa tool2<img src="assets/img/2024/1/image-20240126175212507.png" alt="image-20240126175212507" style="zoom:67%;" />

解密脚本

```python
import gmpy2
import rsa

e = 65537
n = 86934482296048119190666062003494800588905656017203025617216654058378322103517
p = 285960468890451637935629440372639283459
q = 304008741604601924494328155975272418463

phin = (q-1)*(p-1)
d = gmpy2.invert(e, phin)

key = rsa.PrivateKey(n, e, int(d), p, q)

with open("xxx\\flag.enc", "rb+") as f:
    f = f.read()
    print(rsa.decrypt(f, key))

```

flag{decrypt_256}

------



## [FlareOn4]login

------

```html
<!DOCTYPE Html />
<html>
    <head>
        <title>FLARE On 2017</title>
    </head>
    <body>
        <input type="text" name="flag" id="flag" value="Enter the flag" />
        <input type="button" id="prompt" value="Click to check the flag" />
        <script type="text/javascript">
            document.getElementById("prompt").onclick = function () {
                var flag = document.getElementById("flag").value;
                var rotFlag = flag.replace(/[a-zA-Z]/g, function(c){return String.fromCharCode((c <= "Z" ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26);});
                if ("PyvragFvqrYbtvafNerRnfl@syner-ba.pbz" == rotFlag) {
                    alert("Correct flag!");
                } else {
                    alert("Incorrect flag, rot again");
                }
            }
        </script>
    </body>
</html>
```

charCodeAt(0)是返回当前字符的Unicode 编码
String.fromCharCode返回Unicode对应的字符串

var rotFlag = flag.replace(/[a-zA-Z]/g, function(c){return String.fromCharCode((c <= "Z" ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26);});这句代码的意思就是将字符后移13位，越界了就转到26个字母的开头（超过Z循环回A），循环进行，最后得到了字符串PyvragFvqrYbtvafNerRnfl@syner-ba.pbz。这个叫做ROT13加密。
<img src="assets/img/2024/1/image-20240128121227450.png" alt="image-20240128121227450" style="zoom: 50%;" />

flag{ClientSideLoginsAreEasy@flare-on.com}

------



## [WUSTCTF2020]level1

------

<img src="assets/img/2024/1/image-20240128122758737.png" alt="image-20240128122758737" style="zoom: 67%;" />

写脚本。（注意循环是从1开始的，txt中只有19位，首位没有，先随便写一个）

```c
#include<stdio.h>
int main(){
	int ptr[]={0,198,
		232,
		816,
		200,
		1536,
		300,
		6144,
		984,
		51200,
		570,
		92160,
		1200,
		565248,
		756,
		1474560,
		800,
		6291456,
		1782,
		65536000};
	int i;
	for ( i = 1; i <= 19; ++i ){
		if ( (i & 1) != 0 )
			printf("%c", (char)(ptr[i] >> i));
		else
			printf("%c", (char)(ptr[i]/i));
	}
	return 0;
}
```

flag{d9-dE6-20c}

------



## [GUET-CTF2019]re

------

upx脱壳

<img src="assets/img/2024/1/image-20240128130938740.png" alt="image-20240128130938740" style="zoom:50%;" /><img src="assets/img/2024/1/image-20240128131008897.png" alt="image-20240128131008897" style="zoom:50%;" />

脚本，网上说a1[6]=1;

```c
#include<stdio.h>
int main(){
	char a1[31];
	a1[0] = 166163712/1629056;
	a1[1] = 731332800/6771600;
	a1[2] = 357245568/3682944;
	a1[3] = 1074393000/10431000;
	a1[4] = 489211344/3977328;
	a1[5] = 518971936/5138336;
	a1[6]='1';
	a1[7] = 406741500/7532250;
	a1[8] = 294236496/5551632;
	a1[9] = 177305856/3409728;
	a1[10] = 650683500/13013670;
	a1[11] = 298351053/6088797;
	a1[12] = 386348487/7884663;
	a1[13] = 438258597/8944053;
	a1[14] = 249527520/5198490;
	a1[15] = 445362764/4544518;
	a1[17] = 174988800/3645600;
	a1[16] = 981182160/10115280;
	a1[18] = 493042704/9667504;
	a1[19] = 257493600/5364450;
	a1[20] = 767478780/13464540;
	a1[21] = 312840624/5488432;
	a1[22] = 1404511500/14479500;
	a1[23] = 316139670/6451830;
	a1[24] = 619005024/6252576;
	a1[25] = 372641472/7763364;
	a1[26] = 373693320/7327320;
	a1[27] = 498266640/8741520;
	a1[28] = 452465676/8871876;
	a1[29] = 208422720/4086720;
	a1[30] = 515592000/9374400;
	a1[31] = 719890500/5759124;
	printf("%s",a1);
	return 0;
}
```

flag{e165421110ba03099a1c039337}

------



## CrackRTF

------

<img src="assets/img/2024/1/image-20240130164748900.png" alt="image-20240130164748900" style="zoom:50%;" />

加密函数1<img src="assets/img/2024/1/image-20240130165530923.png" alt="image-20240130165530923" style="zoom:50%;" />

加密函数2<img src="assets/img/2024/1/image-20240130165625074.png" alt="image-20240130165625074" style="zoom:50%;" />

使用hash函数加密，猜测是md5加密，将两串md5值解密，分别是123321@DBApp和~!3a@0123321@DBApp。第一个密码是123321，第二个是~!3a@0，运行exe输入两个密码得到含flag的文件。

------



## [2019红帽杯]easyRE

------

第一部分是一个异或<img src="assets/img/2024/1/image-20240201145712337.png" alt="image-20240201145712337" style="zoom: 67%;" />

脚本

```c
#include<stdio.h>
#include<string.h>
int main(){
	char v1[]={'I','o','d','l','>','Q','n','b','(','o','c','y',127,'y','.','i',127,'d','`','3','w','}','w','e','k','9','{','i','y','=','~','y','L','@','E','C',0};
	for(int i=0;i<strlen(v1);i++){
		//TODO
		v1[i]^=i;
	}
	printf("%s",v1);
	return 0;
}//结果是Info:The first four chars are `flag`
```

第二部分<img src="assets/img/2024/1/image-20240201150024544.png" alt="image-20240201150024544" style="zoom:67%;" />

sub_400E44

![image-20240201150054135](assets/img/2024/1/image-20240201150054135.png)

![image-20240201150128405](assets/img/2024/1/image-20240201150128405.png)

推测这个函数是base64加密。off_6CC090是这一堆，对其进行10次base64解密。

![image-20240201150250591](assets/img/2024/1/image-20240201150250591.png)

结果是https://bbs.pediy.com/thread-254172.html，似乎是假的flag。发现off_6CC090后面有一个函数。

![image-20240201150450270](assets/img/2024/1/image-20240201150450270.png)

![image-20240201150536346](assets/img/2024/1/image-20240201150536346.png)

脚本

```c
#include<stdio.h>
int main(){
	char v1[]={
		64,  53,  32,  86,  93,  24,  34,  69,  23,  47, 
		36, 110,  98,  60,  39,  84,  72, 108,  36, 110, 
		114,  60,  50,  69,  91,   0
	};
	char v2[]="flag",v3[4];
	int i,j;
	for(i=0;i<4;i++){
		v3[i]=v1[i]^v2[i];
	}
	for ( j = 0; j <= 24; ++j )
		v1[j] ^= v3[j % 4];
	printf("%s",v1);
	return 0;
}
```

flag{Act1ve_Defen5e_Test}

------



## [MRCTF2020]Transform

------

<img src="assets/img/2024/1/image-20240201153419782.png" alt="image-20240201153419782" style="zoom:67%;" />

脚本

```c
#include<stdio.h>
int main(){
	int s[]={103, 121, 123, 127, 117,  43,  60,  82,  83, 121, 
		87,  94,  93,  66, 123,  45,  42, 102,  66, 126, 
		76,  87, 121,  65, 107, 126, 101,  60,  92,  69, 
		111,  98,  77,   0};
	int key[]={9,
		10,
		15,
		23,
		7,
		24,
		12,
		6,
		1,
		16,
		3,
		17,
		32,
		29,
		11,
		30,
		27,
		22,
		4,
		13,
		19,
		20,
		21,
		2,
		25,
		5,
		31,
		8,
		18,
		26,
		28,
		14,
		0};
	char flag[33];
	int i;
	for(i=0;i<=32;i++){
		s[i]^=key[i];
	}
	for(i=0;i<=32;i++){
		flag[key[i]]=s[i];
	}
	printf("%s",flag);
	return 0;
}
```

flag{Tr4nsp0sltiON_Clph3r_1s_3z}

------



## [WUSTCTF2020]level2

------

upx脱壳

------



## [SUCTF2019]SignIn

------

rsa加密

------



## [ACTF新生赛2020]usualCrypt

------

发现密码表，是base64加密。先对flag进行base64加密，再大小写转换后与密文比较。

------



## [HDCTF2019]Maze

------

存在花指令。下方有个奇怪的jnz指令，它跳转到了下一行，相当于没跳

![img](https://img-blog.csdnimg.cn/20201202143519998.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L21jbXV5YW5nYQ==,size_16,color_FFFFFF,t_70)

它call了一个奇怪的地址，ida没法分析出来。先把jnz指令nop掉，再选call指令按d将其先转换为字节数据。

<img src="assets/img/2024/1/image-20240218144750290.png" alt="image-20240218144750290" style="zoom: 67%;" />

db 0E8h是添加花指令，继续nop掉。然后选择剩下的按c让ida识别为指令，再选择main函数的所有指令按p变为函数。

<img src="assets/img/2024/1/image-20240218150539738.png" alt="image-20240218150539738" style="zoom: 67%;" />

看样子是迷宫。找到代表迷宫的字符串。

![image-20240218153822605](assets/img/2024/1/image-20240218153822605.png)

```
*******+**
******* **
****    **
**   *****
** **F****
**    ****
**********
```

flag{ssaaasaassdddw}

------



## [MRCTF2020]Xor

------

main函数F5 发现报错了，不能F5。首先我们看到 这里压入了byte_4212C0和%s。这个我们就知道 flag其实储存在byte_4212C0中

<img src="assets/img/2024/1/image-20240218180741018.png" alt="image-20240218180741018" style="zoom:50%;" />

然后我们看到 loc_4010B6 我们可以知道 edx寄存器不断自增,最后退出循环,然后再与27 进行比较,这个时候我们就知道,flag的长度就为27

如果输入的长度 大于27 那么就提示错误。

<img src="assets/img/2024/1/image-20240218180859150.png" alt="image-20240218180859150" style="zoom:67%;" />

如果不小于 那么先与eax异或 然后 再与byte_41EA08进行比较。

脚本

```c
#include<stdio.h>
int main(){
	char s[]={77,  83,  65,  87,  66, 126,  70,  88,  90,  58, 
		74,  58,  96, 116,  81,  74,  34,  78,  64,  32, 
		98, 112, 100, 100, 125,  56, 103,   0};
	for(int i=0;i<27;i++){
		s[i]^=i;
	}
	printf("%s",s);
	return 0;
}
```

------



## [MRCTF2020]hello_world_go

------

直接能找到flag。

------



## [WUSTCTF2020]level3

------

base64加密，改了密码表<img src="assets/img/2024/1/image-20240219190917857.png" alt="image-20240219190917857" style="zoom: 67%;" />

脚本跑出密码表后解密

```c
include<stdio.h>
int main(){
	char base64_table[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	char v1;
	int i,result;
	for ( i = 0; i <= 9; ++i )
	{
		v1 = base64_table[i];
		base64_table[i] = base64_table[19 - i];
		result = 19 - i;
		base64_table[result] = v1;
	}
	printf("%s",base64_table);
	return 0;
}
```

------



## Youngter-drive

------

先upx脱壳。

<img src="assets/img/2024/1/image-20240225164509261.png" alt="image-20240225164509261" style="zoom:67%;" />

开了两个线程，第一个是加密，第二个是跳过一位，也就是奇数位加密偶数位不加密。

<img src="assets/img/2024/1/image-20240225164608508.png" alt="image-20240225164608508" style="zoom:67%;" />

脚本

```c
#include<stdio.h>
#include<string.h>
int main(){
	char Source[29]="TOiZiZtOrYaToUwPnToBsOaOapsyS";
	char key[]="QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm";
	int a;
	for(int i=1;i<29;i+=2){
		a=strchr(key,Source[i])-&key[0];	
		if((a+38) <= 'Z' && (a+38) >= 'A')
			Source[i]=a+38;
		else if((a+96) < 'z' && (a+96) >= 'a')
			Source[i]=a+96;
		else
			Source[i]=a;
	}
	printf("%s",Source);
	return 0;
}
```

跑出来的flag是ThisisthreadofwindowshahaIsES，少了最后一位，网上说是E。flag{ThisisthreadofwindowshahaIsESE}

------



## 相册

------

apk文件，习惯用apkide打开，看它反编译成了jar，就换jadx-gui打开，题目提示找邮箱，因此在导航栏里搜索mail


看到了sendMailByJavaMail（java里的实现邮件发送），跟进，右击点击查找


选择其中一个点击转到


右击MAILSERVER查看引用，发现是一个base64解密

之后没有找到什么敏感的信息，就去apkide里查看了一下libcore.so文件（C代码写的库文件，一般放在lib文件下。android是基于java的 但也可以调用c代码，so就是）
刚刚在jadx-gui里看到了有base64解密，碰巧在字符串里看到了几个类似base64加密的字符串，拿去解密一下
题目给的提示flag是一个邮箱，`MTgyMTg0NjUxMjVAMTYzLmNvbQ==`解密后就是一个邮箱地址

------



## [FlareOn4]IgniteMe

------

<img src="assets/img/2024/1/image-20240227193749383.png" alt="image-20240227193749383" style="zoom: 50%;" /><img src="assets/img/2024/1/image-20240227193831320.png" alt="image-20240227193831320" style="zoom:50%;" />

加密逻辑是这样：

s[38]=v4^flag[38]

v4=flag[38]

s[37]=v4^flag[37]

一开始v4的值不知道，但根据Hint:本题解出相应字符串后请用flag{}包裹，形如：flag{123456@flare-on.com}，flag的最后一位是m，计算一下m^105=4

脚本

```c
#include<stdio.h>
int main(){
	unsigned char s[] ={13,  38,  73,  69,  42,  23, 120,  68,  43, 108, 
		93,  94,  69,  18,  47,  23,  43,  68, 111, 110, 
		86,   9,  95,  69,  71, 115,  38,  10,  13,  19, 
		23,  72,  66,   1,  64,  77,  12,   2, 105,   0};
	char flag[40];
	int v4=4;
	for (int i = 38; i >= 0; --i )
	{
		flag[i] = v4 ^ s[i];
		v4 = flag[i];
	}
	printf("%s",flag);
	return 0;
}
```

------



## [WUSTCTF2020]Cr0ssfun

------

题目里把flag的每一位都给出来了。

------



## [GWCTF 2019]xxor

------

<img src="assets/img/2024/1/image-20240228144538023.png" alt="image-20240228144538023" style="zoom:50%;" /><img src="assets/img/2024/1/image-20240228144827339.png" alt="image-20240228144827339" style="zoom:50%;" /><img src="assets/img/2024/1/image-20240228145038579.png" alt="image-20240228145038579" style="zoom:50%;" /><img src="assets/img/2024/1/image-20240228144935898.png" alt="image-20240228144935898" style="zoom:50%;" />

check函数里有方程组，解方程组得到加密后v7。脚本

```c
#include<stdio.h>
int main(){
	long int a1[6]={3746099070,550153460,3774025685,1548802262,2652626477,2230518816};
	int a2[4]={2,2,3,4};
	int result; // rax
	unsigned int v3; // [rsp+1Ch] [rbp-24h]
	unsigned int v4; // [rsp+20h] [rbp-20h]
	long long int v5; // [rsp+24h] [rbp-1Ch]
	unsigned int i;
	for(int j=0;j<=4;j+=2){
		v3 = a1[j];
		v4 = a1[j+1];
		v5 = 1166789954*64;
		for ( i = 0; i <= 63; ++i )
		{
			v4 -= (v3 + v5 + 20) ^ ((v3 << 6) + a2[2]) ^ ((v3 >> 9) + a2[3]) ^ 16;
			v3 -= (v4 + v5 + 11) ^ ((v4 << 6) + a2[0]) ^ ((v4 >> 9) + a2[1]) ^ 32;
			v5 -= 1166789954;
		}
		a1[j] = v3;
		a1[j+1] = v4;
	}
	for(int i=0;i<=5;i++){
		printf("%x ",a1[i]);
	}
	return 0;
}
```

得到flag的16进制是：666c61 677b72 655f69 735f67 726561 74217d，就是

------



## [UTCTF2020]basic-re

------

string里面直接找到flag

------



## [FlareOn6]Overlong

------

<img src="assets/img/2024/1/image-20240228185941460.png" alt="image-20240228185941460" style="zoom:50%;" />

发现原本长度不短的unk_402008变量，在函数中只用到了前28位，有理由怀疑，是否在进行变量操作时，函数取的变量位数过少

尝试将28改为80，脚本

```c
#include<stdio.h>
char unk_402008[]={224, 129, 137, 192, 160, 193, 174, 224, 129, 165, 
	193, 182, 240, 128, 129, 165, 224, 129, 178, 240, 
	128, 128, 160, 224, 129, 162, 114, 111, 193, 171, 
	101, 224, 128, 160, 224, 129, 180, 224, 129, 168, 
	193, 165,  32, 193, 165, 224, 129, 174,  99, 193, 
	175, 224, 129, 164, 240, 128, 129, 169, 110, 193, 
	167, 192, 186,  32,  73, 240, 128, 129, 159, 193, 
	161, 193, 159, 193, 141, 224, 129, 159, 193, 180, 
	240, 128, 129, 159, 240, 128, 129, 168, 193, 159, 
	240, 128, 129, 165, 224, 129, 159, 193, 165, 224, 
	129, 159, 240, 128, 129, 174, 193, 159, 240, 128, 
	129, 131, 193, 159, 224, 129, 175, 224, 129, 159, 
	193, 132,  95, 224, 129, 169, 240, 128, 129, 159, 
	110, 224, 129, 159, 224, 129, 167, 224, 129, 128, 
	240, 128, 129, 166, 240, 128, 129, 172, 224, 129, 
	161, 193, 178, 193, 165, 240, 128, 128, 173, 240, 
	128, 129, 175, 110, 192, 174, 240, 128, 129, 163, 
	111, 240, 128, 129, 173,   0};
int __cdecl sub_401000(char *a1, char *a2)
{
	int v3; // [esp+0h] [ebp-8h]
	char v4; // [esp+4h] [ebp-4h]
	
	if ( (int)(unsigned __int8)*a2 >> 3 == 30 )
	{
		v4 = a2[3] & 0x3F | ((a2[2] & 0x3F) << 6);
		v3 = 4;
	}
	else if ( (int)(unsigned __int8)*a2 >> 4 == 14 )
	{
		v4 = a2[2] & 0x3F | ((a2[1] & 0x3F) << 6);
		v3 = 3;
	}
	else if ( (int)(unsigned __int8)*a2 >> 5 == 6 )
	{
		v4 = a2[1] & 0x3F | ((*a2 & 0x1F) << 6);
		v3 = 2;
	}
	else
	{
		v4 = *a2;
		v3 = 1;
	}
	*a1 = v4;
	return v3;
}
unsigned int __cdecl sub_401160(char *a1, char *a2, unsigned int a3)
{
	unsigned int i; // [esp+4h] [ebp-4h]
	
	for ( i = 0; i < a3; ++i )
	{
		a2 += sub_401000(a1, a2);
		if ( !*a1++ )
			break;
	}
	return i;
}
int main(){
	char Text[128];
	sub_401160(Text, unk_402008, 80);
	printf("%s",Text);
	return 0;
}
```

I never broke the encoding: I_a_M_t_h_e_e_n_C_o_D_i_n_g@flare-on.com

------



## [FlareOn3]Challenge1

------

简单的base64

------



## 特殊的 BASE64

------

简单的base64

------



## [ACTF新生赛2020]Oruga

------

<img src="assets/img/2024/1/image-20240301120806929.png" alt="image-20240301120806929" style="zoom:50%;" />

迷宫题，WEMJ控制上右下左，byte_201020是地图，从左上角开始到33(!)。

```
    #       ####
   ##   OO      
        OO PP   
   L OO OO PP   
   L OO OO P    
  LL OO    P    
     OO    P    
#               
            #   
      MMM   #   
       MMM    EE
   0 M M M    E 
              EE
TTTI M M M    E 
 T I M M M    E 
 T I M M M!   EE
```

第二个while是说：

在最左的一列不能左走

在最右的一列不能右走

在最下的一列不能下走

在最上的一列不能上走

flag{MEWEMEWJMEWJM}

------



## [ACTF新生赛2020]Universe_final_answer

------

第一个函数要求输入满足这些条件，要用z3解。

![image-20240706183108132](assets/img/2024/1/image-20240706183108132.png)

```python
from z3 import *

m = BitVec('m',8)
v0,v1,v2,v3,v4,v5,v6,v7,v8,v9= BitVecs('v0 v1 v2 v3 v4 v5 v6 v7 v8 v9', 8)
s = Solver()#初始化一个Solver类
s.add(-85 * v8 + 58 * v7 + 97 * v6 + v5 + -45 * v4 + 84 * v3 + 95 * v0 - 20 * v1 + 12 * v2 == 12613)
s.add(30 * v9 + -70 * v8 + -122 * v6 + -81 * v5 + -66 * v4 + -115 * v3 + -41 * v2 + -86 * v1 - 15 * v0 - 30 * v7 == -54400)
s.add(-103 * v9 + 120 * v7 + 108 * v5 + 48 * v3 + -89 * v2 + 78 * v1 - 41 * v0 + 31 * v4 - (v6 << 6) - 120 * v8 == -10283)
s.add(71 * v6 + (v5 << 7) + 99 * v4 + -111 * v2 + 85 * v1 + 79 * v0 - 30 * v3 - 119 * v7 + 48 * v8 - 16 * v9 == 22855)
s.add(5 * v9 + 23 * v8 + 122 * v7 + -19 * v6 + 99 * v5 + -117 * v4 + -69 * v2 + 22 * v1 - 98 * v0 + 10 * v3 == -2944)
s.add(-54 * v9 + -23 * v7 + -82 * v2 + -85 * v0 + 124 * v1 - 11 * v3 - 8 * v4 - 60 * v5 + 95 * v6 + 100 * v8 == -2222)
s.add(-83 * v9 + -111 * v5 + -57 * v0 + 41 * v1 + 73 * v2 - 18 * v3 + 26 * v4 + 16 * v6 + 77 * v7 - 63 * v8 == -13258)
s.add(81 * v9 + -48 * v8 + 66 * v7 + -104 * v6 + -121 * v5 + 95 * v4 + 85 * v3 + 60 * v2 + -85 * v0 + 80 * v1 == -1559)
s.add(101 * v9 + -85 * v8 + 7 * v6 + 117 * v5 + -83 * v4 + -101 * v3 + 90 * v2 + -28 * v1 + 18 * v0 - v7 == 6308)
s.add(99 * v9 + -28 * v8 + 5 * v7 + 93 * v6 + -18 * v5 + -127 * v4 + 6 * v3 + -9 * v2 + -93 * v1 + 58 * v0 == -1697)
check = s.check()#检测是否有解（有解sat、无解unsat）
print(check)
model = s.model()#取出所有结果，一个ModelRef类，
print(model)
```

得到

```
v0 = 70,
 v1 = 48,
 v6 = 95,
 v4 = 84,
 v2 = 117,
 v3 = 82,
 v5 = 121,
 v7 = 55,
 v9 = 64,
 v8 = 119
```

整理一下是F0uRTy_7w@

然后直接在linux系统上跑一下<img src="assets/img/2024/1/image-20240706191052320.png" alt="image-20240706191052320" style="zoom:67%;" />

------



## [BJDCTF2020]BJD hamburger competition

------

[BUUCTF------[BJDCTF2020\]BJD hamburger competition_[bjdctf2020]bjd hamburger competition1-CSDN博客](https://blog.csdn.net/qq_64558075/article/details/122754468)

------



## [Zer0pts2020]easy strcmp

------

<img src="assets/img/2024/1/image-20240303155257447.png" alt="image-20240303155257447" style="zoom:50%;" />

这个函数对输入进行了加密，不知道为什么交叉引用没结果。

<img src="assets/img/2024/1/image-20240303155401370.png" alt="image-20240303155401370" style="zoom:50%;" />

就是把输入的每一位减去key。

<img src="assets/img/2024/1/image-20240303155532208.png" alt="image-20240303155532208" style="zoom:50%;" />

选这个才能是正常的顺序，否则是小端序，反过来的。脚本如下

```c
#include<stdio.h>
int main(){
	int key[]={0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x09, 
		0x4A, 0x49, 0x35, 0x43, 0x0A, 0x41, 0xF0, 0x19, 0xE6, 0x0B, 
		0xF5, 0xF2, 0x0E, 0x0B, 0x2B, 0x28, 0x35, 0x4A, 0x06, 0x3A, 
		0x0A, 0x4F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	char flag[]="zer0pts{********CENSORED********}";
	for(int i=0;i<=31;i++){
		flag[i]+=key[i];
	}
	printf("%s",flag);
	return 0;
}
```

输出是zer0pts{l3ts_m4k3^4^DDSOUR_t0d4y}，正确的flag内容应该是l3ts_m4k3_4_DETOUR_t0d4y，不知道为什么有几位少加了1。

------



## [WUSTCTF2020]level4

------

IDA打开找到主函数，看描述说这是一个数据结构的算法，而且有left以及rleft，这不就是数据结构里面的左子树和右子树么

动调看两个输出

<img src="assets/img/2024/1/image-20240311172511622.png" alt="image-20240311172511622" style="zoom:50%;" />

这type1和type2就是中序遍历和后序遍历（中序和后续都是从左子树开始），那么猜测type3就是前序遍历了，找到这个已知中序遍历和后序遍历求前序遍历 改下脚本

已知前序中序输出后序

```c++
#include<iostream>  
using namespace std;  
int pre[] = {1, 2, 3, 4, 5, 6};  
int mid[] = {3, 2, 4, 1, 6, 5};  
void post(int root, int start, int end) 
{  
    if(start > end)   
        return ;  
    int i = start;  
    while(i < end && mid[i] != pre[root]) i++;  //定位根在中序的位置
    post(root + 1, start, i - 1);  //递归处理左子树
    post(root + 1 + i - start, i + 1, end);  //递归处理右子树
    //cout<<pre[root];  //访问当前树的根
    cout<<mid[i];
}  

int main() 
{  
    post(0, 0, 5);  
    return 0;  
}  
```

已知后序中序输出前序

```c++
#include<iostream>  
using namespace std;  
int post[] = {3, 4, 2, 6, 5, 1};  
int mid[] = {3, 2, 4, 1, 6, 5};  
void pre(int root, int start, int end) 
{  
    if(start > end)   
        return ;  
    int i = start;  
    while(i < end && mid[i] != post[root]) i++;  //定位根在中序的位置
    cout<<mid[i];  //访问当前处理的树的根
    pre(root-1-(end-i), start, i - 1);  //递归处理左子树
    pre(root-1, i + 1, end);  //递归处理右子树  
}  

int main()
 {  
    pre(5, 0, 5);  
    return 0;  
}  
```

脚本

```c++
#include<iostream>  
using namespace std;  
char post[] = "20f0Th{2tsIS_icArE}e7__w";  
char mid[] = "2f0t02T{hcsiI_SwA__r7Ee}";  
void pre(int root, int start, int end) 
{  
	if(start > end)   
		return ;  
	int i = start;  
	while(i < end && mid[i] != post[root]) i++;  //定位根在中序的位置
	cout<<mid[i];  //访问当前处理的树的根
	pre(root-1-(end-i), start, i - 1);  //递归处理左子树
	pre(root-1, i + 1, end);  //递归处理右子树  
}  

int main()
{  
	pre(23, 0, 23);  
	return 0;  
}  
```



------



## [羊城杯 2020]easyre

------

三层加密，第一层base64，第二层交换换位，第三层凯撒加密。脚本

```c
//EmBmP5Pmn7QcPU4gLYKv5QcMmB3PWHcP5YkPq3=cT6QckkPckoRG
//BjYjM2Mjk4NzMR1dIVHs2NzJjY0MTEzM2VhMn0=zQ3NzhhMzhlOD
#include<stdio.h>
#include<string.h>
int main(){
	char encode3[]="EmBmP5Pmn7QcPU4gLYKv5QcMmB3PWHcP5YkPq3=cT6QckkPckoRG";
	char encode2[52],encode1[52];
	for (int i = 0; i < strlen(encode3); ++i )
	{
		if ( encode3[i] <= '@' || encode3[i] > 'Z' )
		{
			if ( encode3[i] <= '`' || encode3[i] > 'z' )
			{
				if ( encode3[i] <= '/' || encode3[i] > '9' )
					encode2[i] = encode3[i];
				else
					encode2[i] = (encode3[i] - 48 + 7) % 10 + 48;
			}
			else
			{
				encode2[i] = (encode3[i] - 97 + 23) % 26 + 97;
			}
		}
		else
		{
			encode2[i] = (encode3[i] - 65 + 23) % 26 + 65;
		}
	}
	char *a1=encode1;
	char *a3=encode2;
	strncpy(a1 + 26, a3, 13);
	strncpy(a1, a3 + 13, 13);
	strncpy(a1 + 39, a3 + 26, 13);
	strncpy(a1 + 13, a3 + 39, 13);
	printf("%s",encode1);
	return 0;
}
```



------



## [网鼎杯 2020 青龙组]singal

------

<img src="assets/img/2024/1/image-20240324111452340.png" alt="image-20240324111452340" style="zoom:67%;" />

vm_operad里的参数v4在上面一行调用了qmemcpy函数，百度上说逆向里的qmemcpy=memcpy，memcpy在c语言里的拷贝函数，在unk_403040中拷贝了0x1C8字节的数据给v4

<img src="assets/img/2024/1/image-20240324111611856.png" alt="image-20240324111611856" style="zoom: 67%;" />

```c++
int __cdecl vm_operad(int *a1, int a2)
{
  int result; // eax
  char Str[200]; // [esp+13h] [ebp-E5h] BYREF
  char v4; // [esp+DBh] [ebp-1Dh]
  int v5; // [esp+DCh] [ebp-1Ch]
  int v6; // [esp+E0h] [ebp-18h]
  int v7; // [esp+E4h] [ebp-14h]
  int v8; // [esp+E8h] [ebp-10h]
  int v9; // [esp+ECh] [ebp-Ch]

  v9 = 0;
  v8 = 0;
  v7 = 0;
  v6 = 0;
  v5 = 0;
  while ( 1 )
  {
    result = v9;
    if ( v9 >= a2 )
      return result;
    switch ( a1[v9] )
    {
      case 1:
        Str[v6 + 100] = v4;
        ++v9;
        ++v6;
        ++v8;
        break;
      case 2:
        v4 = a1[v9 + 1] + Str[v8];
        v9 += 2;
        break;
      case 3:
        v4 = Str[v8] - LOBYTE(a1[v9 + 1]);
        v9 += 2;
        break;
      case 4:
        v4 = a1[v9 + 1] ^ Str[v8];
        v9 += 2;
        break;
      case 5:
        v4 = a1[v9 + 1] * Str[v8];
        v9 += 2;
        break;
      case 6:
        ++v9;
        break;
      case 7:
        if ( Str[v7 + 100] != a1[v9 + 1] )
        {
          printf("what a shame...");
          exit(0);
        }
        ++v7;
        v9 += 2;
        break;
      case 8:
        Str[v5] = v4;
        ++v9;
        ++v5;
        break;
      case 10:
        read(Str);
        ++v9;
        break;
      case 11:
        v4 = Str[v8] - 1;
        ++v9;
        break;
      case 12:
        v4 = Str[v8] + 1;
        ++v9;
        break;
      default:
        continue;
    }
  }
}
```

当值等于7时str数组的值会与a1数组的下一位进行比较，相等继续，不等报错。7后面的数字就是正确输入进行加密后需要与之比较的值，刚好7这个值在a1数组的最后

------



## crackMe

------



<img src="assets/img/2024/1/image-20240324125820416.png" alt="image-20240324125820416" style="zoom: 50%;" />

由此处的while和最里层的那个break可知，要从该循环跳出，这俩if都得满足

首先分析第一个if，点进sub_401830并开始分析

<img src="assets/img/2024/1/image-20240324132151266.png" alt="image-20240324132151266" style="zoom: 50%;" />

因为这个if要成立，所以这个return后面的表达式必须成立，及v14==43924成立，此处逆向分析

<img src="assets/img/2024/1/image-20240324132541132.png" alt="image-20240324132541132" style="zoom:50%;" />

此处出现了很多很多if判断，按照经验可以把if后面的数字按r转换成字符，此处猜测if全部满足后结果刚好等于43924

可以写个c脚本验证一下猜测

```c
#include<stdio.h>
int main(){
	int s=0;
	s|=4;
	s|=0x14;
	s|=0x84;
	s|=0x114;
	s|=0x380;
	s|=0xA04;
	s|=0x2310;
	s|=0x8A10;
	printf("%d",s);
	return 0;
}
```

a2[5]要选择='s'的那个，结果确实是43924，由此得出v16为"dbappsec"

继续反推

<img src="assets/img/2024/1/image-20240324141709048.png" alt="image-20240324141709048" style="zoom:50%;" />

这里两个if是反调试函数，动调时要改一下跳过它们。接下来动调获得byte_8E6050，在xor下断点

<img src="assets/img/2024/1/image-20240324142044422.png" alt="image-20240324142044422" style="zoom:50%;" />

ecx就是byte_8E6050，每次都记录下，byte_8E6050: 0x2A, 0xD7, 0x92, 0xE9, 0x53, 0xE2, 0xC4, 0xCD

然后继续回推

<img src="assets/img/2024/1/image-20240324143824165.png" alt="image-20240324143824165" style="zoom:67%;" />

下面那个if无所谓管不管，直接可以写代码了

```c
#include<stdio.h>
int main(){
	char str[]="dbappsec";
	int key[]={0x2A, 0xD7, 0x92, 0xE9, 0x53, 0xE2, 0xC4, 0xCD},flag[8];
	for(int i=0;i<=7;i++){
		flag[i]=str[i]^key[i];
		printf("%x",flag[i]);
	}
	return 0;
}
```

得到4eb5f3992391a1ae，进行MD5的32位小写哈希加密，得到d2be2981b84f2a905669995873d6a36c，包上flag{ }提交。

------



## [BJDCTF 2nd]easy

------

进入 `___main` 函数只有初始化信息。

猜测 flag 藏在左侧函数列表中且没被调用。此时发现 `_main` 上面的 `_ques` 函数非常可疑（看上去就不像是调用的函数，像是自定义的），进入查看。发现有 `putchar` 函数，且会输出 `*` 和空格，基本可以确定是关键函数，接下来需要考虑如何处理

`_main` 函数里直接调用了 `___main` 函数。可以通过将此处调用的 `___main` 函数更改为 `_ques` 来实现让程序自己调用该函数

在 `_main` 函数中找到 `call ___main` 命令，右键选择 `Assemble`。将 `call ___main` 命令更改为 `cal _ques`。然后再右击选择 `Apply patches`。

------



## [V&N2020 公开赛]CSRe

------

例行检查，无壳儿，但是有NET混淆，使用de4dot工具进行处理。

之后用dnSpy打开，从入口点开始看程序。

找到有关flag的信息。flag由str+text组成。

str根据`if (Class3.smethod_0("3" + str + "9") != "B498BFA2498E21325D1178417BEA459EB2CD28F8")`可以推算出来
看一下Class3.smethod_0，是sha1加密。

sha1解密得到str，str=1415。程序一开始没有给我们text的值，但是我们知道re+text进行了sha1加密后是`63143B6F8007B98C53CA2149822777B3566F9241`，老样子先sha1解密一下。text=‘turn’。

------



## [DASCTF 2023 & 0X401七月暑期挑战赛]controlflow

------

程序通过改变栈里面的返回地址来控制程序的控制流，从而达到混淆的效果。

在每个关键的函数开头设置断点，然后动调观察程序的运行流程。随便输入DASCTF{abcdefghijklmnopqrstuvwxyz012345}

先是main函数里的异或

<img src="assets/img/2024/1/image-20240526155639911.png" alt="image-20240526155639911" style="zoom:67%;" />

flag[i]+=i*i，下一个函数传入的是flag[10]

<img src="assets/img/2024/1/image-20240526152054057.png" alt="image-20240526152054057" style="zoom: 67%;" />

从flag[10]开始：flag[i]^=i*(i+1)

<img src="assets/img/2024/1/image-20240526153008119.png" alt="image-20240526153008119" style="zoom:67%;" />

flag[i]-=i

<img src="assets/img/2024/1/image-20240526161835690.png" alt="image-20240526161835690" style="zoom:67%;" />

flag[i]*=3;

<img src="assets/img/2024/1/image-20240526162041822.png" alt="image-20240526162041822" style="zoom:67%;" />

交换相邻的元素，dword_254474是flag[10]
<img src="assets/img/2024/1/image-20240526154811444.png" alt="image-20240526154811444" style="zoom:67%;" />

最后进check函数

脚本

```c
#include<stdio.h>
int main(){
	int flag[40],t;
	flag[0] = 3279;
	flag[1] = 3264;
	flag[2] = 3324;
	flag[3] = 3288;
	flag[4] = 3363;
	flag[5] = 3345;
	flag[6] = 3528;
	flag[7] = 3453;
	flag[8] = 3498;
	flag[9] = 3627;
	flag[10] = 3708;
	flag[11] = 3675;
	flag[12] = 3753;
	flag[13] = 3786;
	flag[14] = 3930;
	flag[15] = 3930;
	flag[16] = 4017;
	flag[17] = 4173;
	flag[18] = 4245;
	flag[19] = 4476;
	flag[20] = 4989;
	flag[21] = 4851;
	flag[22] = 5166;
	flag[23] = 5148;
	flag[24] = 4659;
	flag[25] = 4743;
	flag[26] = 4596;
	flag[27] = 5976;
	flag[28] = 5217;
	flag[29] = 4650;
	flag[30] = 6018;
	flag[31] = 6135;
	flag[32] = 6417;
	flag[33] = 6477;
	flag[34] = 6672;
	flag[35] = 6891;
	flag[36] = 7056;
	flag[37] = 7398;
	flag[38] = 7650;
	flag[39] = 7890;
	for(int i=10;i<30;i+=2){
		t=flag[i];
		flag[i]=flag[i+1];
		flag[i+1]=t;
	}
	for(int i=0;i<40;i++){
		flag[i]/=3;
		flag[i]+=i;
	}
	for(int i=0;i<20;i++){
		flag[i+10]^=i*(i+1);
	}
	for(int i=0;i<40;i++){
		flag[i]-=i*i;
		flag[i]^=0x401;
	}
	for(int i=0;i<40;i++){
		printf("%c",flag[i]);
	}
	return 0;
}
```

