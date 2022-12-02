# -*- coding: utf-8 -*-
"""
Created on Fri Dec 24 18:07:15 2021

@author: Orkun
"""
import math
import time
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve, Point
from Crypto.Hash import HMAC, SHA3_256,SHA256
from Crypto.Cipher import AES
from Crypto import Random  # a bit better secure random number generation
import requests
import json
import sys
"""
I use json for memorize to data 
I implement all sections of phase1s
Kendi numaranı girip çalıştır gelen mailldeki kodları girki senide kaydetsin json'a
EGE karelerin içindeki yerleri değiştirmeye çalış formatı bozma ama parametrelerin adını değiştirebilirsin yda
syntax şeklinle oynayabilirsin
Bende yapabilirim ancak hem iki kişi yazmış gibi olsun hemde plag yeme ihtimalimiz sıfıra düşsün
line olarak 145 ve 186 arası ve 366'dan sonrası böyle yüklersen sıkıntı yaşayabiliriz 
Bide görsel çıktıları düzeltebilirsin 
ne kadar değiştirirsen o kadar iyi olur 
"""
API_URL = 'http://10.92.52.175:5000/'

x = input('Enter your name:')
stuID=20701 #buraya kendi numaranı girip çalıştır
if x=="orkun":
#    stuID=20701, # ıt do not work because datatype
    y=0
if x=="ege":
 #   stuID=28370,
    y=1
with open('memory.json', 'r') as myfile:
    data=myfile.read()
datas = json.loads(data)
sample = datas["samples"][y]

def IKRegReq(h, s, x, y):
    mes = {'ID': stuID, 'H': h, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegReq"), json=mes)
    if ((response.ok) == False): print(response.json())
def IKRegVerify(code):
    mes = {'ID': stuID, 'CODE': code}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegVerif"), json=mes)
    if ((response.ok) == False): raise Exception(response.json())
    print(response.json())
def SPKReg(h, s, x, y):
    mes = {'ID': stuID, 'H': h, 'S': s, 'SPKPUB.X': x, 'SPKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SPKReg"), json=mes)
    if ((response.ok) == False):
        print(response.json())
    else:
        res = response.json()
        return res['SPKPUB.X'], res['SPKPUB.Y'], res['H'], res['S']
def OTKReg(keyID,x,y,hmac):
    mes = {'ID':stuID, 'KEYID': keyID, 'OTKI.X': x, 'OTKI.Y': y, 'HMACI': hmac}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "OTKReg"), json = mes)
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetIK(rcode):
    mes = {'ID': stuID, 'RCODE': rcode}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetIK"), json=mes)
    print(response.json())
    if ((response.ok) == False):
        return False
    else:
        return True
def ResetSPK(h, s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetSPK"), json=mes)
    print(response.json())
    if ((response.ok) == False):
        return False
    else:
        return True
def ResetOTK(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetOTK"), json = mes)
    if((response.ok) == False): print(response.json())
def PseudoSendMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "PseudoSendMsg"), json = mes)
    print(response.json())
def ReqMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json = mes)
    print(response.json())
    if((response.ok) == True):
        res = response.json()
        return res["IDB"], res["OTKID"], res["MSGID"], res["MSG"], res["EK.X"], res["EK.Y"]
def Checker(stuID, stuIDB, msgID, decmsg):
    mes = {'IDA':stuID, 'IDB':stuIDB, 'MSGID': msgID, 'DECMSG': decmsg}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "Checker"), json = mes)
    print(response.json())

E = Curve.get_curve('secp256k1')

def n():
    ret = E.order
    return ret
def p():
    ret = E.field
    return ret
def P():
    ret = E.generator
    return ret

#funcs 
def egcd(a, b): # egcd function which that we use lesson
    x, y, u, v = 0, 1, 1, 0
    while a != 0:
        q, r = b // a, b % a
        m, n = x - u * q, y - v * q
        b, a, x, y, u, v = a, r, u, v, m, n
    gcd = b
    return gcd, x, y
def modinv(a, m):# moduler inverse function which that we use lesson
    if a < 0:
        a = a + m
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None  # modular inverse does not exist
    else:
        return x % m
##################################################################################
def GenerateSignature(P, M, S_a):
  
    k = randint(1, n() - 2)
    R = k * P
    r = R.x % n()
    r_byte = r.to_bytes((r.bit_length() + 7) // 8, byteorder='big')
    M_byte = M.to_bytes((M.bit_length() + 7) // 8, byteorder='big')
    hash_byte = r_byte + M_byte
    hash = SHA3_256.new(hash_byte)  # hash it
    digest = int.from_bytes(hash.digest(), byteorder='big')
    h = digest % n()
    s = (k - (S_a * h)) % n()
    return (h, s)
def KeyGeneration(Public):
    s_A = randint(1, n() - 2)

    Q_A = s_A * Public

    return s_A, Q_A
#Signature function
#verification function
def VerifySignature(Signature, M, Q_a):
    h, s = Signature[0], Signature[1]
    V = s * P() + h * Q_a
    v = V.x % n()
    v_bytes = v.to_bytes((v.bit_length() + 7) // 8, byteorder='big')
    M_bytes = M.to_bytes((M.bit_length() + 7) // 8, byteorder='big')
    hash_bytes = v_bytes + M_bytes
    hash = SHA3_256.new(hash_bytes)  # hash it
    digest = int.from_bytes(hash.digest(), byteorder='big')
    h_ = digest % n()

    return h == h_
def concatenateIntPair(SPKPUB_x, SPKPUB_y):
    SPKPUB_x_bytes = SPKPUB_x.to_bytes((SPKPUB_x.bit_length() + 7) // 8, byteorder='big')
    SPKPUB_y_bytes = SPKPUB_y.to_bytes((SPKPUB_y.bit_length() + 7) // 8, byteorder='big')
    concat_bytes = SPKPUB_x_bytes + SPKPUB_y_bytes
    message = int.from_bytes(concat_bytes, byteorder='big')

    return message
################################################################################
def GenerateHMACKey():
    T = privKeySPK * serverSPKPUB
    Tx_bytes = T.x.to_bytes((T.x.bit_length() + 7) // 8, byteorder='big')
    Ty_bytes = T.y.to_bytes((T.y.bit_length() + 7) // 8, byteorder='big')
    U = Tx_bytes + Ty_bytes + b'NoNeedToRideAndHide'

    hash = SHA3_256.new(U)  
    HMACkey_int = int.from_bytes(hash.digest(), byteorder='big') % n()
    return HMACkey_int

def GenerateOTKArray():
    OTK= []
    for i in range(0,10):
        OTKprivate, OTKpub = KeyGeneration(P())
        OTKpair = (OTKprivate, (OTKpub.x,OTKpub.y))
        OTK.append(OTKpair)
    return OTK

def GenerateHMACArray(OTK,HMACkey):
    HMACarray = []
    for OTKpair in OTK:
        OTKprivate, OTKpub = OTKpair
        concatOTKpub = concatenateIntPair(OTKpub[0],OTKpub[1])
        concatOTKpub_bytes = concatOTKpub.to_bytes((concatOTKpub.bit_length() + 7) // 8, byteorder='big')

        HMACkey_bytes = HMACkey.to_bytes((HMACkey.bit_length() + 7) // 8, byteorder='big')
        hash = HMAC.new(key=HMACkey_bytes, msg=concatOTKpub_bytes, digestmod=SHA256)
        digest = hash.hexdigest()
        HMACarray.append(digest)
    return HMACarray

print("2.1")#2.1
ServPubIK = Point(93223115898197558905062012489877327981787036929201444813217704012422483432813,8985629203225767185464920094198364255740987346743912071843303975587695337619,E)
privKey = 0
IKPUB_x = 0
IKPUB_y = 0
IKPUB =0
h=0
s=0
if(sample["IKprivate"]==0):
        private, ikpub = KeyGeneration(P())
        print("Identitiy Key is created")
        print("IKey is a long term key and shouldn't be changed and private part should be kept secret. But this is a datas run, so here is my private IKey: ", private)
        print("My ID number is ",stuID," Converted my ID to bytes in order to sign it: b'FW' ")
        print("h= ", ikpub.x)
        print("s= ", ikpub.y)
        privKey = private
        IKPUB_x = ikpub.x
        IKPUB_y = ikpub.y
        print(" IDENTITIY KEY IS CREATING...")
        #creating key
        signature = GenerateSignature(P(), stuID, privKey)
        h, s = signature[0], signature[1]
        IKRegReq(h, s, IKPUB_x, IKPUB_y)
        CODE = int(input("REGISTRATION Code: "))
        IKRegVerify(CODE)
        RESET = int(input("RESET CODE: "))
        sample["privKey"] = privKey
        sample["IKPUB"] = [IKPUB_x, IKPUB_y]
        sample["CODE"] = CODE
        sample["RESET"] = RESET
        datas["samples"][y] = sample
        with open('memory.json', 'w', encoding='utf-8') as f:
            json.dump(datas, f, ensure_ascii=False, indent=4)
else:
   x = input('reset or next? ')

   if x=="reset":    
        ResetIK(sample["RESET"])
        sample["privKey"] = 0
        sample["IKPUB"] = 0
        sample["SPKprivate"] = 0
        sample["SPKpublic"] = 0
        sample["OTKarray"] = 0
        sample["HMACarray"] = 0
        sample["HMACkey"] = 0
        sample["RESET"] = 0
        sample["CODE"] = 0
        datas["samples"][y] = sample
        with open('memory.json', 'w', encoding='utf-8') as f:
            json.dump(datas, f, ensure_ascii=False, indent=4)
        sys.exit()  
   else:
        privKey = sample["IKprivate"]
        IKPUB_x = sample["IKpublic"][0]
        IKPUB_y = sample["IKpublic"][1]
        IKPUB = Point(IKPUB_x, IKPUB_y, E)

print("2.2")

privKeySPK = 0
SPKPUB_x = 0
SPKPUB_y = 0
SPKPUB = 0
if sample["SPKprivate"] == 0:
    print("Generating SPK...")
   
    privKeySPK, SPKPUB = KeyGeneration(P())
    SPKPUB_x = SPKPUB.x
    SPKPUB_y = SPKPUB.y
    print("Private SPK: ",privKeySPK)
    print("Private SPK.x: ",SPKPUB_x)
    print("Private SPK.y: ",SPKPUB_y)
    
    sample["SPKprivate"] = privKeySPK
    sample["SPKpublic"] = [SPKPUB_x, SPKPUB_y]

    datas["samples"][y] = sample
    with open('memory.json', 'w', encoding='utf-8') as f:
        json.dump(datas, f, ensure_ascii=False, indent=4)
    print("Convert SPK.x and SPK.y to bytes in order to sign them then concatenate them result will be like:",SPKPUB) 
else:
    print("SPK IS DONE")

    privKeySPK = sample["SPKprivate"]
    SPKPUB_x = sample["SPKpublic"][0]
    SPKPUB_y = sample["SPKpublic"][1]
    SPKPUB = Point(IKPUB_x,IKPUB_y, E)
    

message = concatenateIntPair(SPKPUB_x, SPKPUB_y)
signature2 = GenerateSignature(P(), message, privKey)
h2, s2 = signature2[0], signature2[1]


result = SPKReg(h2, s2, SPKPUB_x, SPKPUB_y)

serverSPKPUB_x, serverSPKPUB_y, h, s = result
serverSPKPUB = Point(serverSPKPUB_x, serverSPKPUB_y, E)
signature = (h, s)
M = concatenateIntPair(serverSPKPUB_x, serverSPKPUB_y)
print("Server's SPK Verification \n Recreating the message(SPK) signed by the serverVerifying the server's SPK...\n If server's SPK is verified we can move to the OTK generation step")
if VerifySignature(signature, M, ServPubIK):
    print("Is SPK verified?:  True")
else:
    print("Is SPK verified?:  False")

print("2.3")

HMACkey =0
OTKarray =0
HMACarray =0
if sample["OTKarray"] == 0:
        print("Creating OTKs starting from index 0...")
        HMACkey = GenerateHMACKey(privKeySPK, serverSPKPUB)
        OTKarray = GenerateOTKArray()
        HMACarray = GenerateHMACArray(OTKarray, HMACkey)

        for i in range(0, len(OTKarray)):
            OTKpair = OTKarray[i]
            OTKpub = OTKpair[1]
            OTKReg(i, OTKpub[0], OTKpub[1], HMACarray[i])
            print("OTK with ID number",i," is registered successfully")

        sample["OTKarray"] = OTKarray
        sample["HMACarray"] = HMACarray
        sample["HMACkey"] = HMACkey
        datas["samples"][y] = sample
        with open('memory.json', 'w', encoding='utf-8') as f:
            json.dump(datas, f, ensure_ascii=False, indent=4)

else:
    x = input('reset or next? ')

    if x=="reset":
        h,s = GenerateSignature(P(), stuID, privKey)
        ResetOTK(h,s)
        sample["OTKarray"]=0
        sample["HMACarray"] = 0
        sample["HMACkey"] = 0

        datas["samples"][y] = sample
        with open('memory.jsono', 'w', encoding='utf-8') as f:
            json.dump(datas, f, ensure_ascii=False, indent=4)       
    else:
        HMACkey = sample["HMACkey"]
        OTKarray = sample["OTKarray"]
        HMACarray = ["HMACarray"]
        print("condinued")
############################################
print("phase 2")

def GenerateSessionKey(OTK,EKpublic):
    OTKprivate,OTKpublic = OTK
    T = OTKprivate * EKpublic
    Tx, Ty = T.x, T.y
    Tx_bytes = Tx.to_bytes((Tx.bit_length() + 7) // 8, byteorder='big')
    Ty_bytes = Ty.to_bytes((Ty.bit_length() + 7) // 8, byteorder='big')
    U = Tx_bytes + Ty_bytes + b'MadMadWorld'
    hash = SHA3_256.new(U)  # hash it
    digest = int.from_bytes(hash.digest(), byteorder='big')
    return digest 
print("3.1.2")

def KeyDerivation(K_KDF):
    #STEP1
    K_KDFkey_byte = K_KDF.to_bytes((K_KDF.bit_length() + 7) // 8, byteorder='big')
    # concatenation
    toHash = K_KDFkey_byte + b'LeaveMeAlone'
    hash = SHA3_256.new(toHash)
    digest = int.from_bytes(hash.digest(), byteorder='big')
    K_ENC = digest #% n()

    #STEP2
    K_ENC_byte = K_ENC.to_bytes((K_ENC.bit_length() + 7) // 8, byteorder='big')
    toHash = K_ENC_byte + b'GlovesAndSteeringWheel'
    hash = SHA3_256.new(toHash)
    digest = int.from_bytes(hash.digest(), byteorder='big')
    K_HMAC = digest #% n()

    #STEP3
    K_HMAC_byte = K_HMAC.to_bytes((K_HMAC.bit_length() + 7) // 8, byteorder='big')
    toHash = K_HMAC_byte + b'YouWillNotHaveTheDrink'
    hash = SHA3_256.new(toHash)
    digest = int.from_bytes(hash.digest(),byteorder ='big')
    K_KDFnext = digest #% n()

    return K_ENC, K_HMAC,K_KDFnext

#this function takes index and
# generate ith key for the key chain
def KDFatIndex(index:int,KDFkey):
    K_ENC, K_HMAC, K_KDFnext = KeyDerivation(KDFkey)
    for i in range(1,index):
        K_ENC, K_HMAC, K_KDFnext= KeyDerivation(K_KDFnext)

    return K_ENC, K_HMAC, K_KDFnext
KDFkey = 0

#Session key generated for both parties

#it is used as kdf and KENC KHMAC created.


#IDK how encryption will be done,
#KENC KHMAC used for message1, recreated for following messages.
def EncryptMessage(Message,K_ENC, K_HMAC, K_KDFnext):
    print("TODO: Encryption is done")
    #next chain of kdf. next encryption will be done accordingly.
    K_ENC, K_HMAC, K_KDFnext= KeyDerivation(K_KDFnext)
    """
    
    buradan aşağıda çalıştırınca göreceksin 4 mail geliyor onu düzeltmeyi deneyebilirsin
    
    """
print("MAILBOX")
#This function will decrypt the message that will send by the server
def Decryption(ciphertext_byte,nonce_byte, k_enc):
    cipher = AES.new(k_enc, AES.MODE_CTR, nonce = nonce_byte)
    decryptedtext_byte = cipher.decrypt(ciphertext_byte)
    decryptedtext = decryptedtext_byte.decode('utf-8')
    return decryptedtext


while True:
    signature = GenerateSignature(P(), stuID, privKey)
    h, s = signature

    select = input('mailbox[0], Send messages[1] , quit[2] :')
    if(select=="0"):
        messages = []
        counter = 0
        #FOR 5 MESSAGES, THIS RUNS
        print("reading mails")
        for i in range(6):
            signature = GenerateSignature(P(), stuID, privKey)
            h, s = signature
            try:
                #GET THE RESPONSE FROM SERVER. IF CANT, THE MAILBOX IS EMPTY
                IDB, OTKID, MSGID,MSG, EKx,EKy = ReqMsg(h,s)
            
            except:
                print("Empty Mailbox")
                break

            #Configuration
            #GENERATE SESSION KEY AND CHAIN KEYS ACCORDING TO MESSAGE ID.
            CurrentOTK = OTKarray[OTKID]
            CurrentEKpublic = Point(EKx, EKy,E)
            SessionKey = GenerateSessionKey(CurrentOTK,CurrentEKpublic)
            K_ENC, K_HMAC, K_KDFnext = KDFatIndex(MSGID,SessionKey)

            #Message is in form:
            # nonce (8 bytes) - msg - mac (32 bytes)
            MSG_bytes = MSG.to_bytes((MSG.bit_length() + 7) // 8, byteorder='big')
            #extracted hmac for verification
            MAC_bytes = MSG_bytes[len(MSG_bytes) - 32:]
            #extracted raw encrypted message for verification
            MSGraw_bytes = MSG_bytes[8:-32]

            #HMAC IS CALCULATED.
            K_HMAC_bytes = K_HMAC.to_bytes((K_HMAC.bit_length() + 7) // 8, byteorder='big')
            HMACnew_hash = HMAC.new(msg=MSGraw_bytes, digestmod=SHA256, key=K_HMAC_bytes)
            HMACnew_int = int.from_bytes(HMACnew_hash.digest(), byteorder='big') %n()
            HMACnew_bytes = HMACnew_int.to_bytes((HMACnew_int.bit_length() + 7) // 8, byteorder='big')

            #HMAC VERIFICATION
            if HMACnew_bytes == MAC_bytes:
                counter+=1
                print("VERIFIED")
                #IF VERIFIED DECRYPT THE MESSAGE
                # first 8 byte of the message.
                NONCE_bytes = MSG_bytes[0:8]
                # message without nonce to get the MAC of the message
                CIPHERTEXT_bytes = MSG_bytes[8:-32]
                # message in int format to decrypt it
                MSG_int = int.from_bytes(MSG_bytes[:len(MSG_bytes) - 32], byteorder='big')

                K_ENC_bytes = K_ENC.to_bytes((K_ENC.bit_length() + 7) // 8, byteorder='big')
                CIPHER = AES.new(K_ENC_bytes, AES.MODE_CTR, nonce=NONCE_bytes)
                PLAINTEXT_bytes = CIPHER.decrypt(CIPHERTEXT_bytes)

                messages.append(str(PLAINTEXT_bytes))
                decrypt_text = PLAINTEXT_bytes.decode('utf-8')
                #AFTER DECRYPTION SEND IT TO SERVER.
                Checker(stuID,IDB,MSGID,(decrypt_text))
            else:
                print("NOT VERIFIED")
                #SEND INVALID TO SERVER
                Checker(stuID, IDB, MSGID, "INVALIDHMAC")

        print("{} out of {} messages are verified\n\n".format(counter,5))
        print("Messages: ")
        for i in range(0,5):
            if len(messages)<i+1:break
            print(messages[i])
    elif (select=="1"):
        PseudoSendMsg(h,s)
        print("asking")
    else:
        sys.exit()
############################################################################