import math
import os
import copy
from utils.help_func_xmss import *
from xmss_address import OtsAddress
from xmss.para_set import WotsPara


class WotspPK():
    def __init__(self, n, len):
        self.n = n
        self.len = len
        self.pk = [b'0'*self.n] * self.len

    def to_bytes(self) -> bytes:
        r = b"".join(self.pk)
        return r

    def from_bytes(self, pkb: bytes):
        assert len(pkb) == self.len * self.n
        for i in range(self.len):
            self.pk[i] = pkb[i * self.n:(i + 1) * self.n]

    def set(self, in_pk: list[bytes]):
        assert len(in_pk) == self.len
        for i in range(self.len):
            assert len(in_pk[i]) == self.n
        self.pk = copy.deepcopy(in_pk)

    def get(self) -> list[bytes]:
        return copy.deepcopy(self.pk)

    def compare(self, tmpPK:list[bytes]):
        try:
            for i in range(self.len):
                if not tmpPK[i] == self.pk[i]:
                    return False
            return True
        except Exception as e:
            return False


class WotspSK():
    def __init__ (self, n, len):
        self.n = n
        self.len = len
        self.sk = [b'0'*self.n] * self.len

    def to_bytes(self) -> bytes:
        r = b"".join(self.sk)
        return r

    def from_bytes(self, skb: bytes):
        assert len(skb) == self.len * self.n
        for i in range(self.len):
            self.sk[i] = skb[i*self.n:(i+1)*self.n]

    def set(self, in_sk: list[bytes]):
        assert len(in_sk) == self.len
        for i in range(self.len):
            assert len(in_sk[i]) == self.n
        self.sk = copy.deepcopy(in_sk)

    def get(self) -> list[bytes]:
        return copy.deepcopy(self.sk)

    def delete(self):
        self.sk = [b'0'*self.n] * self.len


class WOTSP():
    def __init__(self, wots_para:WotsPara, rng=os.urandom):
        # following parameters all can be set, make wots+ as a module for others
        self.para = wots_para
        self.rng = rng
        self.SEED = self.rng(self.para.n)
        # address is volatile
        self.addr = OtsAddress()
        # to indicate keys are generated on the fly
        self.skdf_flag = False
        self.skdf_secret = None

    def set_pseudo_kdf(self, secret:bytes):
        assert len(secret) == self.para.n
        self.skdf_secret = secret
        self.skdf_flag = True

    def set_seed(self, seed: bytes):
        '''This SEED is public'''
        assert (len(seed) == self.para.n)
        self.SEED = seed

    def set_address(self, address:OtsAddress):
        # this input is usually converted by other forms, no need to do deep copy
        self.addr = address

    def chain(self, x:bytes, start:int, step: int) -> bytes:
        if step == 0:
            return x
        if (start + step) > (self.para.w - 1):
            return None
        tmp0 = self.chain(x, start, step -1)

        self.addr.set_hash_address(start + step - 1)
        self.addr.set_keyAndMask(0)

        key = self.para.PRF(self.SEED, self.addr)
        self.addr.set_keyAndMask(1)
        BM = self.para.PRF(self.SEED, self.addr)
        tmp = self.para.F(key, bytewise_xor(tmp0, BM))

        return tmp

    def gen_sk(self) -> list[bytes]:
        sk = [None] * self.para.len
        if self.skdf_flag:
            for i in range(self.para.len):
                sk[i] = self.para.PRF(self.skdf_secret, int_2_bytes(i, 32))
        else:
            for i in range(self.para.len):
                sk[i] = self.rng(self.para.n)
        return sk

    def gen_pk_from_sk(self, sk:list[bytes]) -> list[bytes]:
        pk = [None] * self.para.len
        for i in range(self.para.len):
            self.addr.set_chain_address(i)
            pk[i] = self.chain(sk[i], 0, self.para.w -1)
        return pk

    def keygen(self):
        sk = self.gen_sk()
        pk = self.gen_pk_from_sk(sk)
        SK = WotspSK(self.para.n, self.para.len)
        PK = WotspPK(self.para.n, self.para.len)
        SK.set(sk)
        PK.set(pk)
        return SK, PK

    def sign(self, sk:list[bytes], m:bytes) -> list[bytes]:
        csum = 0
        msg = base_w(m, self.para.w, self.para.len1)

        for i in range(self.para.len1):
            csum += self.para.w - 1 - msg[i]

        csum = csum << (8 - ((self.para.len2 * lg(self.para.w))%8))
        len_2_bytes = math.ceil((self.para.len2 * lg(self.para.w))/8.0)
        msg = msg + base_w(int_2_bytes(csum, len_2_bytes), self.para.w, self.para.len2)

        sign = [None]* self.para.len
        for i in range(self.para.len):
            self.addr.set_chain_address(i)
            sign[i] = self.chain(sk[i], start=0, step=msg[i])
        return sign

    def pk_from_sig(self, m:bytes, sign:list[bytes]) -> list[bytes]:
        csum = 0
        msg = base_w(m, self.para.w, self.para.len1)

        for i in range(self.para.len1):
            csum += self.para.w - 1 - msg[i]

        csum = csum << (8 - ((self.para.len2 * lg(self.para.w)) % 8))
        len_2_bytes = math.ceil((self.para.len2 * lg(self.para.w)) / 8.0)
        msg = msg + base_w(int_2_bytes(csum, len_2_bytes), self.para.w, self.para.len2)

        tmpPK = [None] * self.para.len
        for i in range(self.para.len):
            self.addr.set_chain_address(i)
            tmpPK[i] = self.chain(sign[i], msg[i], self.para.w - 1 - msg[i])

        return tmpPK

    def verify(self, PK:WotspPK, m: bytes, sign: list[bytes]) -> bool:
        tmpPK = self.pk_from_sig(m, sign)
        return PK.compare(tmpPK)


if __name__ == "__main__":
    import utils.config
    with open(utils.config.wots_log,"w") as FIN:
        para = WotsPara()
        secrets = os.urandom(para.n)
        wots = WOTSP(wots_para = para)

        wots.set_pseudo_kdf(secrets)
        sk, pk = wots.keygen()

        mesg = bytes(bytearray([i+16 for i in range(16)]))*(wots.para.n//16)
        sign = wots.sign(sk.get(), mesg)
        ver = wots.pk_from_sig(mesg, sign)

        pretty_pf(FIN, "pk=:", pk.get())
        pretty_pf(FIN, "verify=", ver)
        pretty_pf(FIN, "sign=:", sign)

        test = wots.verify(pk, mesg, sign)
        print(f"verify result = {test}")
