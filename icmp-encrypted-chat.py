'''
Created on 2012-12-14

@author: Patrick Mathieu (@PathetiQ)

@requires: https://www.dlitz.net/software/pycrypto/
@requires: http://www.secdev.org/projects/scapy/
'''

from scapy.all import sr,sr1,IP,ICMP,sniff
from Crypto.Cipher import AES
from Crypto import Random
import argparse
import threading

#blogal var to check if the last message has already been seen
lastMsg=""

#received a packet payload, decrypt and print it if not already seen
def decrypt(val,password):
    unpad = lambda s : s[0:-ord(s[-1])]
    global lastMsg
    

    enc = str(val[0][ICMP].load).decode("hex")

    iv = enc[:16]
    decryptor = AES.new(password,AES.MODE_CFB,iv)
    decrypted = str(unpad(decryptor.decrypt( enc[16:] )))
    
    #icmp can cause duplicate message 
    if lastMsg != decrypted:
        lastMsg = decrypted    
        print decrypted

#received data from user input, encrypt and return
def encrypt(data,password):
    BS = 32
    pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)  
    iv = Random.new().read( AES.block_size )
 
    cipher = AES.new(password,AES.MODE_CFB,iv)
    #data = "%s : %s" % str(nickname),str(data)
    raw = pad(data)
    crypted = str(iv + cipher.encrypt(raw)).encode("hex") #must be a multiple of 16 in lenght

    return crypted

def sniffing(ether,password,ip):
    sniff(iface=ether, filter="icmp and host "+str(ip), prn=lambda x: decrypt(x,password))
   
    
if __name__ == '__main__':
    
    parser = argparse.ArgumentParser()
    parser.add_argument('-ip', required=True, help='Enter IP to send the encrypted message')
    parser.add_argument('-p', required=True, help='Enter the password to encrypt message')
    parser.add_argument('-e', required=True, help='Enter network interface (EX: eth0)')
    parser.add_argument('-n', required=True, help='Enter your nickname')

    args = parser.parse_args()    
    
    ip = args.ip
    ether = args.e
    password = args.p
    nickname = args.n
    
    sniffThread = threading.Thread(target=sniffing, args=(ether,password,ip))
    sniffThread.start()
    
    #Quitting is pretty badly handle, need interupt(ctrl+c management in here)
    while(1):
        txt = raw_input()
        if txt == "quit()":
            break
        txt1 = "%s: %s" % (nickname, txt)
        data = encrypt(txt1,password)
        a = sr1(IP(dst=ip)/ICMP()/data)
    #sniffThread.join()
    quit()
    
    
    
    
    
    
    
    
    
    
    
    