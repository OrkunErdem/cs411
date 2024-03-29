# -*- coding: utf-8 -*-
"""
Created on Sat Nov  6 23:17:25 2021

@author: Orkun
"""


#!pip install pycryptodome

from Crypto.Cipher import Salsa20


ctext = b'1v-\xdda\x9d\x13\xf5y\xd4M\xcc\xc2\xd5\xc9\xe8\xca\xfcF\xe1\x7f\xdd\xabM,=c\xa6\x9e\xd2M\x11;9Bpna\x91\xb8\xf5z>\x0cZ\x83\x11\xa7\x01\x1b\xc2\xc5$>\x10\xa2>"#\xc0\x98\xa4\xc2\xbd\xa1\xce\x0f\x17]\x8c_\xee\xadT|'
ctext2= b'\x9d\x131v-\xdda\xe9\xf3,\xca\x02\xd1\xc9\x9a\xda\xe1\xce\xfcM\xed1\xdb\xb9\r,\x1b-\xa6\x88\x84JTo7N>p}\x9b\xfb\xa6e?\x0bQ\xc6_\xa7\x1d\x1a\x87\x8c78\x1a\xa9\x7f!!\xce\xdd\xe9\xd6\xbd\xf5\x9a\t\x17G\xc9K\xf2\xecDl\xb0\xca\x86\xa6\xd7\xde\xe5zxf\xd0\xado\xea'
ctext3= b"\x00\x04\x00\x00\x00\x00\xfd7\xc1\x02\xcf\xc9\x82\xc4\xe1\xc7\xf1D\xef\x7f\xdd\xab\x10,\x00,\xea\x9d\xc1IC!qJ1ma\x9b\xba\xe7f>\x01N\x83\x0b\xa7\x0c\t\xde\xc537\x1b\xfby='\xca\x89\xe8\xda\xee\xf3\xdf\x14\x06V\xc5[\xf5\xadOj\xa9\xc1\x86\xb4\xdd\x8d\xff}|f\xd2\xado\xe6r\xf6\xcf\xe3\xf1H\xa6\xdaA\xcb\x17"
secret = 314159265358979323
key = secret.to_bytes(32, byteorder='big')

ctext_nonce = ctext[:8]
ctext_nonce2 = ctext2[:8]
ctext_nonce3 = ctext3[:8]
ciphertext = ctext3[8:]
ciphertext2 = ctext3[8:]
ciphertext3 = ctext3[8:]
cipher = Salsa20.new(key, nonce=ctext_nonce)
dtext = cipher.decrypt(ciphertext)


cipher2 = Salsa20.new(key, nonce=ctext_nonce2)
dtext2 = cipher2.decrypt(ciphertext3)

cipher3 = Salsa20.new(key, nonce=ctext_nonce3)
dtext3 = cipher3.decrypt(ciphertext3)

print("decoded text: ", dtext.decode('UTF-8'))


print("decoded text: ", dtext2.decode('UTF-8'))


print("decoded text: ", dtext3.decode('UTF-8'))