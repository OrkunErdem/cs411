# -*- coding: utf-8 -*-
"""
Created on Sat Nov  6 20:54:35 2021

@author: Orkun
"""

import random
import requests

API_URL = 'http://10.36.52.109:6000'
#API_URL = 'http://cryptlygos.pythonanywhere.com'

my_id=20701

import requests
import math

def phi(n):
    amount = 0
    for k in range(1, n + 1):
        if math.gcd(n, k) == 1:
            amount += 1
    return amount

def gcd(a, b):
    """Calculate the Greatest Common Divisor of a and b.

    Unless b==0, the result will have the same sign as b (so that when
    b is divided by it, the result comes out positive).
    """
    while b:
        a, b = b, a%b
    return a

def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
    gcd = b
    return gcd, x, y

def modinv(a, m):
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None  # modular inverse does not exist
    else:
        return x % m



p = 23736540918088479407817876031701066644301064882958875296167214819014438374011661672830210955539507252066999384067356159056835877781419479023313149139444707
q = 62179896404564992443617709894241054520624355558658288422696178839274611833136662241430162694076231401545584449128278988404970580015985140542451087049794069
e=1395972458563002865773278165397705182379226840944182963467500494247426096011662521385435089134463960565758060080027413622289432056794784076303781282751337633281028391292118692605586729819778602695411701472465140208799413503487136767611224635228489749491483511398890565966489213952806574591436530660379633874831
c= 1108976125814837009432942535307936341422291657984742622666179099865728304369267210256361407820525607348192829732569045253181249137565011151925383192867726066753728251272081221068710563159295325289544304414451236616576996003805691715132565089594759467186070837322039607865498610169221859643941689057183990024147
n = p*q
d = modinv(e, (p-1)*(q-1))

int_result = pow(c,d,n)
byte_result = int_result.to_bytes(math.ceil(int_result.bit_length()/8), byteorder = "big")
string_result = byte_result.decode()
print(string_result)



m = int_result	
m_ = string_result


def checkQ2(ptext):  #check your answer for Question 1 part c
  response = requests.put('{}/{}'.format(API_URL, "checkQ2"), json = {"ID": my_id, "msg":ptext})
  print(response.json())
  
checkQ2(string_result)