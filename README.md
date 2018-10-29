# Apache-FLucid

This impelmentation is based on : https://arxiv.org/abs/0904.3789

**apache_flucid_encoder** is a simple program to turn Apache access logs into Forensic Lucid observations.
As Apache rotatelog, it is made to be run as a piped log program: https://httpd.apache.org/docs/2.4/en/programs/rotatelogs.html


- Conversion can be done statically, by passing a LogFile formated in httpd.conf as below:
*LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined*

- Conversion can be done dynamically, by using the piped log option with Apache in httpd.conf as below (wip):
 *CustomLog "|/usr/sbin/apache_flucid_encoder -D" combined*
 

Exemple of Raw access log:
```
172.16.16.4 - - [05/Mar/2018:19:32:17 -0500] "GET /theme/eldy/img/tick.png HTTP/1.1" 200 980 "http://example.com/install/check.php" "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:57.0) Gecko/20100101 Firefox/57.0"
```

Exemple of Forensic Lucid Observation :
```
observation access_o_30 = ([src-ip:"172.16.16.4" , access-date:"05/Mar/2018:19:32:17" , timezone:"0500" , http-identd:"-" , http-userid:"-" , http-method:"GET" , http-path:"/theme/eldy/img/tick.png" , http-protocol:"HTTP/1.1" , http-code:"200" , object-size:"980" , http-referer:"http://example.com/install/check.php" , user-agent:"Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:57.0) Gecko/20100101 Firefox/57.0"] 1 , 0 , 1 . 0 ,"05/Mar/2018:19:32:17" 
```


