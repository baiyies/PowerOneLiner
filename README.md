# PowerOneLiner
[中文][url-doczh]

PowerShell one-liner reverse shell generator. Utilizes PowerShell to remotely fetch shellcode and loads it into memory after decryption with RC4. Supports both 32-bit and 64-bit shellcode.

# Use case
Loading your own shellcode in a non-persistent manner without writing to disk.

# Usage
```
usage: one_liner_generator.py [-h] -input INPUT -arch {0,1} [-output OUTPUT]

powershell one-liner generator.

optional arguments:
  -h, --help      show this help message and exit
  -input INPUT    input shellcode file name
  -arch {0,1}     shellcode arch(0 for 32 bit, 1 for 64bit)
  -output OUTPUT  out ps1 file name
```

# Disclaimer
This tool is only intended for legally authorized enterprise security activities. When using this tool for detection, you should ensure that such activities comply with local laws and regulations and that you have obtained sufficient authorization.

If you engage in any illegal activities while using this tool, you will be solely responsible for the consequences, and we will not assume any legal or joint liability.

Unless you have read, fully understood, and accepted all the terms of this agreement, please do not use this tool. Your use of this tool or any other express or implied acceptance of this agreement will be deemed as your acknowledgment and agreement to be bound by this agreement.

[url-doczh]: README_ZH.md