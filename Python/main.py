from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
import base64

def verifySignature(filename, myECCKey, signaturefilename):
    finput = open(filename, "r")
    fsignature = open(filename + ".signature", "rb")
    inText = finput.read()
    finput.close()
    signature = fsignature.read()
    fsignature.close()
    hash = SHA256.new()
    hash.update(bytes(inText, 'ascii'))
    signer = DSS.new(myEccKey, 'fips-186-3')
    signer.verify(hash, signature)
    print("valid")



def sign(filename, myEccKey):
    finput = open(filename, "r")
    fsignature = open(filename + ".signature", "wb")
    inText = finput.read()
    finput.close()
    hash = SHA256.new()
    hash.update(bytes(inText, 'ascii'))
    signer = DSS.new(myEccKey, 'fips-186-3')
    signedData = signer.sign(hash)
    fsignature.write(signedData)
    fsignature.close()



def constructEccKeyFromPrivateKey(privateKey):
    privateKeyInt = int(privateKey, 16)
    myECCKey = ECC.construct(curve='P-256', d=privateKeyInt)
    return myECCKey


def constructEccKeyFromPublicKey(x, y):
    xInt = int(x, 16)
    yInt = int(y, 16)
    myEccKey = ECC.construct(curve='P-256', point_x=xInt, point_y=yInt)
    return myEccKey


def importEccPublicKeyFromCertificate(filename):
    certificateFile = open(filename,'rb')
    certificate = certificateFile.read()
    myEccKey = ECC.import_key(certificate)
    return myEccKey


def importEccPrivateKeyFromKeyFile(filename, password):
    keyFile = open(filename, 'rb')
    key = keyFile.read()
    myEccKey = ECC.import_key(key, passphrase=password)
    return myEccKey

if __name__ == '__main__':
#    myEccKey = constructEccKeyFromPrivateKey('AE176B08B19CC8AAF0B12BB290A651B804330B6800B6C3BA3174F81D9FCF70A7')
    myEccKey = importEccPrivateKeyFromKeyFile('MyPersonalECC.key', 'Pa$$w0rd')
    sign('MySecret.txt', myEccKey)
#    myEccKey = constructEccKeyFromPublicKey('EE26584F5E6755D70FA07833EE4036A2EFBB97D8BC22B3C97011730A266A31B9', '24CC48289CEDC6D5861B7339283FE6680E0B79D5F635BF7588D4166DBDD18EB9')
    myEccKey = importEccPublicKeyFromCertificate('MyPersonalECC.cer')
    verifySignature('MySecret.txt', myEccKey, 'MySecret.txt.signature')

