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
    myEccKey = constructEccKeyFromPrivateKey('D6BE6E5E2A2E6C1EDE640A5E6068D86A47E90247ABCEF9FE3926042DAE1B9B84')
#    myEccKey = importEccPrivateKeyFromKeyFile('MyPersonalECC.key', 'Pa$$w0rd')
    sign('MySecret.txt', myEccKey)
    myEccKey = constructEccKeyFromPublicKey('889AD76D433D4CA2DE1149FC8A6BE24AECDC5A9B139888246B42522B9A1A3EBD', 'EBDCC71372805673AC00EFEA95F06C6A45BA48F6C40D488B8BEF9B5B4DED1657')
#    myEccKey = importEccPublicKeyFromCertificate('MyPersonalECC.cer')
    verifySignature('MySecret.txt', myEccKey, 'MySecret.txt.signature')

