# Sublime XssEncode

Converts characters from one encoding to another using a transformation.

**Convert the region you selected or convert all characters.**

Installation
----
1. Open the Sublime Text Packages folder
    * OS X: ~/Library/Application Support/Sublime Text 3/Packages/
    * Windows: %APPDATA%/Sublime Text 3/Packages/
    * Linux: ~/.Sublime Text 3/Packages/ or ~/.config/sublime-text-3/Packages

2. clone this repo
	
	```
	git clone https://github.com/Medicean/SublimeXssEncode.git
	```

Commands
----

* `html_escape`

	Converts characters to their HTML entity.
	
	**eg:**
	
	`a1@&` => `a1@&amp;`

* `html10_encode`
	
	Converts characters to html entity with decimal.
	
	**eg:**
	
	`a1@&` => `&#97;&#49;&#64;&#38;`

* `html16_encode`

	Converts characters to html entity with hexadecimal.

	**eg:**
	
	`a1@&` => `&#x61;&#x31;&#x40;&#x26;`

* `html_unescape`

	Converts html entity to characters.
	
	**eg:**
	
	`a&#97;&#x61;&amp;` => `aaa&`

* `base64_encode`

	Uses base64 to encode into base64
	
	**eg:**
	
	`a1@&` => `YTFAJg==`

* `base64_decode`

	**eg:**
	
	`YTFAJg==` => `a1@&`

* `url_encode`

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
	
	Convert characters with function chr.
	
	**eg:**
	
	Support we have a php backdoor, and the content is `<?php @eval($_REQUEST[cmd]);?>`
	
	if you want to execute some commands which includes special chars, you can convert it.
	
	`ls -al` => `CHR(108).CHR(115).CHR(32).CHR(45).CHR(97).CHR(108)`
	
	now you can request the url below:
	
	`http://127.0.0.1/backdoor.php?cmd=system(CHR(108).CHR(115).CHR(32).CHR(45).CHR(97).CHR(108));`
	
* `string_to_hex`

	Convert string to hexadecimal, it's more useful for sql injection.

	**eg:**
	
	`root` => `726f6f74`

	now you can excute the sql commands below.

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
