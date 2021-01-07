from ctypes import *
import platform
from asn1crypto.x509 import Certificate
import asn1

if platform.system() == 'Windows':
    skf = windll.LoadLibrary("./64/SKFAPI00001.dll")
    gea = windll.LoadLibrary("./64/GEA00001.dll")
elif platform.system() == 'Linux':
    skf = cdll.LoadLibrary("./64/SKFAPI00001.dll")
    gea = cdll.LoadLibrary("./64/GEA00001.dll")

# 枚举设备，调用两次SKF_EnumDev
pulSize = c_ulong()
szNamelist = ((c_char*20)*10)()

print(skf.SKF_EnumDev(True, None, pointer(pulSize)))
print(pulSize.value)
print(skf.SKF_EnumDev(True, szNamelist, pointer(pulSize)))
'''for szName in szNamelist:
    print(szName.value)
    print(szName.raw)'''
print("设备名称", szNamelist[0].value)
# 连接设备，使用枚举设备获取的设备名
phDev = c_void_p()

print(skf.SKF_ConnectDev(szNamelist[0], byref(phDev)))
print("设备句柄", phDev.value)

# 锁定设备
ulTimeOut = c_ulong(1000)

print(skf.SKF_LockDev(phDev, ulTimeOut))

# 枚举应用名称
AppNameList = ((c_char*20)*5)()

print(skf.SKF_EnumApplication(phDev, None, pointer(pulSize)))
print(skf.SKF_EnumApplication(phDev, AppNameList, pointer(pulSize)))
'''for AppName in AppNameList:
    print(AppName.value)
    print(AppName.raw)'''
print("应用名称", AppNameList[0].value)

# 打开应用
phApplication = c_void_p()

print(skf.SKF_OpenApplication(phDev, AppNameList[0], byref(phApplication)))
print("应用名称句柄", phApplication.value)


# 枚举容器
ContainerNameList = ((c_char*40)*5)()

print(skf.SKF_EnumContainer(phApplication, None, pointer(pulSize)))
print(skf.SKF_EnumContainer(phApplication, ContainerNameList, pointer(pulSize)))
"""for ContainerName in ContainerNameList:
    print(ContainerName.value)
    print(ContainerName.raw)"""
print(ContainerNameList[0].value)

# 打开容器

phContainer = c_void_p()

print(skf.SKF_OpenContainer(phApplication, ContainerNameList[0], byref(phContainer)))
print("容器句柄", phContainer.value)

# 导出证书,True是签名证书，False是加密证书
pulCertLen = c_ulong()

# 签名证书
print(skf.SKF_ExportCertificate(phContainer, True, None, pointer(pulCertLen)))
# print(pulCertLen.value)
pbCert1 = (c_ubyte*pulCertLen.value)()
print(skf.SKF_ExportCertificate(phContainer, True, byref(pbCert1), byref(pulCertLen)))
# print(bytes(x) for x in pbCert1)
# Cert1 = (' '.join(hex(x) for x in pbCert1))
Cert1 = bytes(pbCert1)
print(Cert1)
# CERT = ' '.join(str(x) for x in Cert1)
# print(Cert1.decode())
# 加密证书
print(skf.SKF_ExportCertificate(phContainer, False, None, pointer(pulCertLen)))
# print(pulCertLen.value)
pbCert0 = (c_ubyte*pulCertLen.value)()
print(skf.SKF_ExportCertificate(phContainer, False, byref(pbCert0), byref(pulCertLen)))

# 解析证书(尝试自行解析）
cert1 = Certificate.load(Cert1)
sig = cert1.signature
print(bytes.decode(sig, "gbk"))


'''# 校验pin码
password = b'111111'
pwdRetryNum = c_ulong()
re = gea.HSVerifyUserPin(phDev, password, byref(pwdRetryNum))
print(re)

# 调用gea解析证书
# 证书结构
class  HT_cert_st(Structure):
    _fields_ = [
        ("chVer", c_byte*4),
        ("szC", c_byte*64),
        ("szOU", c_byte*64),
        ("szO", c_byte*64),
        ("szCN", c_byte*64),
        ("szL", c_char*256),
        ("szS", c_char*256),
        ("szTimeFrom", c_byte*64),
        ("szTimeTo", c_byte*64),
        ("szIssuer", c_byte*64),
        ("szReserved1", c_byte*64),
        ("szReserved2", c_byte*64)
    ]


print(gea.HSGetCertInfo(byref(pbCert1), pulCertLen, byref(HT_cert_st())))
ht_cert_st = HT_cert_st()
# print(ht_cert_st.szReserved2)
for i in ht_cert_st.chVer:
    print(i, end='')
'''
