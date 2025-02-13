---
title: 使用 GitHub Pages 和 Jekyll 搭建个人博客
date: 2025-02-13 20:45:00 +0800
categories: [其他, ]
tags: []
---

本篇文章将介绍使用 GitHub Pages 和 Jekyll 搭建个人博客的方法，其优势在于相对简单且免费。

## 准备工作

1. **注册 GitHub 账号** 如果还没有 GitHub 账号，需要先在[GitHub 官网](https://github.com/)注册一个账号。
2. **确定博客名称和主题** 想好自己博客的名称、主题和风格，这将有助于你在后续的选择模板和定制博客时更有方向。

## 搭建博客

### 找到Jekyll主题

可以去GitHub [github.com/topics/jekyll-theme](https://github.com/topics/jekyll-theme) 或 jekyllthemes.org 寻找适合自己的主题。

我选择的是https://chirpy.cotes.page/

### Using the Chirpy Starter

操作步骤如下：（建议直接参考作者给出的预览demo中的文章，一般都会有教程说明如何操作）

1. 创建git仓库

   仓库URL: https://github.com/cotes2020/chirpy-starter，进入仓库后点右上角 Use this template > Create a new repository跳转进入创建页面，修改仓库名称为 `USERNAME.github.io`

2. 配置github仓库

   进入自己创建好的仓库，点 Settings Pages Settings 后，点 Build and deployment 下面的 Source 中的选项 Github Actions

3. 修改项目配置

   _config.yml中的变量，url，avatar，timezone，lang，主要是这四个配置

   正常都会在1分钟内部署完成，这时候访问`USERNAME.github.io`，即刚刚创建的仓库名，即可看到对应的网页。如果能正常看到类似demo的网页，那说明部署成功了。

## 更新与维护

一般更新文章可以直接上传，也可以现在本地调试好后再上传。

### 写文章

在_posts文件夹下创建一个md格式文件，文件名格式使用YYYY-MM-DD-TITLE.md

需要在文章顶部填写如下的 YAML Front Matter：

```yaml
---
title: TITLE
date: YYYY-MM-DD HH:MM:SS +/-TTTT
categories: [TOP_CATEGORIE, SUB_CATEGORIE]
tags: [TAG]     # TAG names should always be lowercase
---
```

上传文章前需要先上传相关图片等媒体资源，建议在/assets/image路径下。上传文章可能会由于图片路径配置不当而报错，这时需要先在github上删除该文章，修改后再重新上传，否则后续其他更新操作也无法进行。