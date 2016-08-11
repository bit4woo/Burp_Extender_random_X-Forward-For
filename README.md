# Burp_Extender_random_X-Forward-For
a Burp Extender that add an random X-Forward-For IP address in header for each request. to bypass the protection which use X-Forward-For field to prevent from brute force.


这个插件的主要作用是在http和https请求的header部分添加一个X-Forward-For字段，而字段中的IP地址是随机生成的。用于绕过使用该字段来防护暴力破解等的场景.
