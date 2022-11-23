from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError
from cryptography.hazmat.primitives import hashes
from hashlib import sha256
import hashlib
from ecdsa.util import randrange_from_seed__trytryagain
import os
# 用一个私钥值派生一个私钥实例


def gen_public_key_and_private_key():
    seed = os.urandom(SECP256k1.baselen)
    secexp = randrange_from_seed__trytryagain(seed, SECP256k1.order)
    sk = SigningKey.from_secret_exponent(secexp, curve=SECP256k1)
    pk = sk.verifying_key.to_pem()
    sk = sk.to_pem()
    return pk, sk


def HASH160(pk):
    sha_256 = sha256()
    sha_256.update(pk)
    hash160 = hashlib.new('ripemd160')
    hash160.update(sha_256.digest())
    pk_hash = hash160.digest()
    return pk_hash


class InputScript:
    def __init__(self, Sigiture, PublicKey):
        # type P2PKH
        self.sigiture = Sigiture
        self.pk = PublicKey


class OutputScript:
    def __init__(self, PublicKeyHash):
        # type P2PKH
        self.PublicKeyHash = PublicKeyHash


def check_scripts(InputScript, OutputScript, msg):
    # 1 DUP
    pk_temp = InputScript.pk
    # 2 HASH160
    # 3 PUSHDATA(PUBLIC KEY)
    # 4 EQUALVERIFY
    if HASH160(pk_temp) == OutputScript.PublicKeyHash:
        # 5 CHECK SIG
        # 使用ECDSA签名算法验证InputScript.sigiture是不是和InputScript.pk匹配
        # 可以参考lab1里的ECDSA验证
        # 这部分需要你来完成
        verify_key = VerifyingKey.from_pem(pk_temp)
        try:
            if verify_key.verify(InputScript.sigiture, msg):
                return True
            else:
                return False
        except BadSignatureError:
            print("Bad Sig, verification failed")
            return False
        except:
            return False
    else:
        return False


if __name__ == '__main__':
    k = HASH160(b'2')
    pk,pr = gen_public_key_and_private_key() # bytes
    pr_obj = SigningKey.from_pem(pr)
    sig = pr_obj.sign(b"123")
    print(sig.hex())
    ips = InputScript(sig,pk)
    pk_hash = HASH160(pk)
    ops = OutputScript(pk_hash)
    print(check_scripts(ips,ops,b"123"))