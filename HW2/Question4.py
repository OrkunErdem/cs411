# -*- coding: utf-8 -*-
"""
Created on Sat Nov  6 21:03:06 2021

@author: Orkun
"""

import math

def phi(n):
    amount = 0
    for k in range(1, n + 1):
        if math.gcd(n, k) == 1:
            amount += 1
    return amount

def gcd(a, b):
    

 
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
    
    
    
## a ##
n1 = 100433627766186892221372630785266819260148210527888287465731
a1 = 336819975970284283819362806770432444188296307667557062083973
b1 = 25245096981323746816663608120290190011570612722965465081317

gcd1 =  gcd(a1,n1)
print("GCD is:", gcd1)

a1_inv = modinv(a1, n1)
print("B % GCD is:", b1%gcd1) 

b1_divided_d = b1//(gcd1)
a1_divided_d = a1//(gcd1)
n1_divided_d = n1//gcd1
inv1 = modinv(a1_divided_d, n1_divided_d)
xbar1 = (b1_divided_d*inv1) % n1_divided_d
for i in range(0,1):
  print("Solution", i+1, "is:", xbar1+i*n1_divided_d )
  print("//////////////////////////////////////////")
## b ##
n2 = 301300883298560676664117892355800457780444631583664862397193
a2 = 1070400563622371146605725585064882995936005838597136294785034
b2 = 1267565499436628521023818343520287296453722217373643204657115

gcd2 =  gcd(a2,n2)
print("GCD is:", gcd2)
print("B % GCD is:", b2%gcd2)

print("no solution.")
print("//////////////////////////////////////////")
## c ##

n3 = 301300883298560676664117892355800457780444631583664862397193
a3 = 608240182465796871639779713869214713721438443863110678327134
b3 = 721959177061605729962797351110052890685661147676448969745292

gcd3 =  gcd(a3,n3)
print("GCD is:", gcd3)


b3_divided_d = b3//(gcd3)
a3_divided_d = a3//(gcd3)
n3_divided_d = n3//gcd3
inv3 = modinv(a3_divided_d, n3_divided_d)
xbar3 = (b3_divided_d*inv3) % n3_divided_d
for i in range(0,3):
  print("Solution", i+1, "is:", xbar3+i*n3_divided_d )




