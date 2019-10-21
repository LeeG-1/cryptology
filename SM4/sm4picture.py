# SM4加密解密图片

from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
import base64

def bytes_to_picture(res, name):
    # 字节转换为图片
    img = base64.b64decode(res)
    file = open(name, 'wb')
    file.write(img)
    file.close()

def picture_to_bytes():
    # 图片转换为字节
    with open(r'logo/PKU.jpg', 'rb') as f:
        res = base64.b64encode(f.read())
    return res


res = picture_to_bytes()  # 将图片转换为字节
key = b'3l5butlj26hvv313'
value = res  # bytes类型
iv = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # bytes类型
crypt_sm4 = CryptSM4()

# ECB模式对logo进行加密
crypt_sm4.set_key(key, SM4_ENCRYPT)
encrypt_value = crypt_sm4.crypt_ecb(value)  # bytes类型
bytes_to_picture(encrypt_value, 'EBC_encrypt.jpg')

# ECB对logo进行解密
crypt_sm4.set_key(key, SM4_DECRYPT)
decrypt_value = crypt_sm4.crypt_ecb(encrypt_value)  # bytes类型
bytes_to_picture(decrypt_value, 'EBC_decrypt.jpg')


# CBC模式对logo进行加密
crypt_sm4.set_key(key, SM4_ENCRYPT)
encrypt_value = crypt_sm4.crypt_cbc(iv, value)  # bytes类型
bytes_to_picture(encrypt_value, 'CBC_encrypt.jpg')

# CBC模式对logo进行解密
crypt_sm4.set_key(key, SM4_DECRYPT)
decrypt_value = crypt_sm4.crypt_cbc(iv, encrypt_value)  # bytes类型
bytes_to_picture(decrypt_value, 'CBC_decrypt.jpg')
