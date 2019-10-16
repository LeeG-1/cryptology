from gmssl import sm3
import sm3function


# 长度扩展攻击过程
# 已知hash(secret)=f2c01fe71e407f888399b0373c86576807dd07341d35f16194b58b07ee510a58,len(secret)=8,未知secret
# sm3为大端方式，修改第二轮IV为hash(secret),可用于求hash(secret||padding||length||x)
# 构造任意str使得len(str)=len(secret),第一轮计算截断后，结果IV修改为hash(secret)的分组，再进行第二轮，即可求得用于求hash(secret||padding||length||x)

# 字符串转ASCII码
def str_to_ASCII(string):
    li = []
    for s in string:
        li.append(ord(s))
    return li


if __name__ == '__main__':
    # hash('test')==f2c01fe71e407f888399b0373c86576807dd07341d35f16194b58b07ee510a58
    # strA='password'
    # strSecond='RomanovS'

    strA = input('please input string to sm3:')  # 输入secret的值，后面计算中secret当做未知，仅知道其长度和hash值
    strSecond = input('please input second part message:')  # 输入第二轮计算的字符串

    length = len(strA)  # 计算secret长度
    y = sm3.sm3_hash(str_to_ASCII(strA))  # 计算secret的hash值用于修改第二轮IV，存于y中

    # 对hash(secret)进行分组，用于求二轮的IV，分组存在liNum中
    liStr = []
    liNum = []
    count = 0
    for i in range(0, len(y) + 1):
        if count % 8 == 0 and count != 0:
            liStr.append('0x' + y[i - 8:i])
        count = count + 1
    for x in liStr:
        liNum.append(int(x, 16))

    strARandom = 'a' * length  # 填充第一轮中的secret部分，长度相等即可
    strPadding = '\x80' + '\x00' * (56 - length - 1)  # 填充第一轮剩余部分
    strLength = '\x00' * 6  # 第一轮数据长度前半部分
    # 根据第一轮secret长度分类填写长度部分
    if length * 8 < 256:
        strLength = strLength + '\x00' + bytes([length * 8]).decode('utf-8')
    else:
        strLength = strLength + bytes([(length - 32) * 8]).decode('utf-8') + '\xff'

    # 输出hash(secret||padding||length||x)用于对比验证攻击是否成功
    y2 = sm3.sm3_hash(str_to_ASCII(strA + strPadding + strLength + strSecond))
    print('hash(secret||padding||length||x)为：')
    print(y2)

    # 将新的IV，即liNum传入sm3function进行攻击
    y1 = sm3function.sm3_hash(str_to_ASCII(strARandom + strPadding + strLength + strSecond), liNum)
    print('使得 length(random) == length(secret), 并利用 hash(secret) 修改IV进行攻击后 hash(random || padding || length || x)为：')
    print(y1)  # 若secret='password',x='RomanovS',值为f2c01fe71e407f888399b0373c86576807dd07341d35f16194b58b07ee510a58
