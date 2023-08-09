# PowerOneLiner
powershell一句话上线便捷生成器。使用powershell远程获取shellcode，并由RC4解密后内存加载。支持32位shellcode和64位shellcode。

# 使用场景
需要以文件不落地的方式加载自己的shellcode时。

# 食用教程
```
usage: one_liner_generator.py [-h] -input INPUT -arch {0,1} [-output OUTPUT]

powershell一句话上线便捷生成器.

optional arguments:
  -h, --help      show this help message and exit
  -input INPUT    输入的shellcode文件
  -arch {0,1}     输入的shellcode的位数(0为32位 1为64位)
  -output OUTPUT  输出的ps1文件名
```

# 免责声明
本工具仅面向合法授权的企业安全建设行为，在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。

如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。

除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要使用本工具。您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。