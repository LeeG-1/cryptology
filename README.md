# cryptology

cryptology homework

SM3哈希函数的长度扩展攻击
长度扩展攻击（length extension attack），是指针对某些允许包含额外信息的加密散列函数的攻击手段。对于满足以下条件的散列函数，都可以作为攻击对象：
① 加密前将待加密的明文按一定规则填充到固定长度（例如512或1024比特）的倍数；
② 按照该固定长度，将明文分块加密，并用前一个块的加密结果，作为下一块加密的初始向量（Initial Vector）。
满足上述要求的散列函数称为Merkle–Damgård散列函数。

如果攻击者知道SM3(salt+data)的值并可控制data的值，攻击者可以设定data为与data+padding+append等长的任意字符串，然后计算SM3(str+append)。我们知道，MD5需要先填充再运算，攻击者可以在程序计算append所在块之前，将SM3(salt+data)的值直接替换掉初始的链变量，就能够算出SM3(salt+data+padding+append)的值了。设SM3(CV,data)表示以链变量CV计算data的SM3值，那么（为简便起见，这里设append的长度不超过448比特，超过的原理也类似）

SM3(IV, salt+data+padding+append) = SM3(SM3(IV, salt+data), append)。

之所以要知道salt的长度，是为了确保salt+data+padding+append和攻击者输入的data拥有相同的填充，以确保最后一步的运算得到相同的结果。

SM4可逆性证明：轮秘钥逆用即可。
