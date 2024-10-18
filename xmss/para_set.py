import hashlib
import math
from utils.help_func_xmss import lg, int_2_bytes, choose_from_list
import ietf_parameters


hash_func_map = {"SHA2-256": ("sha256", 32),
                 "SHA2-512": ("sha512", 64),
                 "SHAKE128": ("shake_128", 32),
                 "SHAKE256": ("shake_256", 64)}


def hash_transfer(hashname: str, type: int, n: int):
    # assert (hashname in {'sha256', 'sha512', 'shake_128', 'shake_256'})
    def hash_f (*args):
        hashInst = eval(f"hashlib.new('{hashname}')")
        hashInst.update(int_2_bytes(type, n))
        res = None
        for a in args:
            if isinstance(a, bytes):
                hashInst.update(a)
            else:
                hashInst.update(a.to_bytes())
        if 'shake' in hashname:
            res = hashInst.digest(n)
        else:
            res = hashInst.digest()
        del (hashInst)
        return res

    return hash_f


def gen_4_hash_func(kw):
    assert kw in hash_func_map.keys()
    hash_name, nn = hash_func_map[kw]
    F = hash_transfer(hash_name, type=0, n=nn)
    H = hash_transfer(hash_name, type=1, n=nn)
    H_msg = hash_transfer(hash_name, type=2, n=nn)
    PRF = hash_transfer(hash_name, type=3, n=nn)
    return {"F": F, "H": H, "H_msg": H_msg, "PRF": PRF}


class WotsPara():
    wots_set_str = ietf_parameters.get_ietf_para_list("WOTSP")
    #     @:parameter h: height of Merkle Tree
    #     @:parameter n: typical message lenth
    #     @:parameter w: world length
    n = 32
    w = 16
    len1 = 64
    len2 = 3
    len = 67
    F, PRF, H, H_msg = None, None, None, None
    hsh = "SHA2-256"
    para_set_str = None

    def __init__ (self):
        self.from_str(self.wots_set_str[0])

    def from_str (self, sstr):
        assert sstr in self.wots_set_str
        str1 = sstr.split("-")
        str2 = str1[1].split("_")
        n = int(str2[1]) >> 3
        hash_name = None
        if str2[0] == "SHA2":
            hash_name = "-".join(str2)
        elif str2[0] == "SHAKE":
            str2[1] = str(n << 2)
            hash_name = "".join(str2)
        else:
            assert (False)
        hashs = gen_4_hash_func(hash_name)
        self.hsh = hash_name
        self.n = n
        self.len1 = math.ceil(8 * n / lg(self.w))
        self.len2 = math.floor(lg(self.len1 * (self.w - 1)) / lg(self.w)) + 1
        self.len = self.len1 + self.len2
        self.F = hashs["F"]
        self.PRF = hashs["PRF"]
        self.H = hashs["H"]
        self.H_msg = hashs["H_msg"]
        self.para_set_str = sstr

    def __str__ (self):
        s = [f"--- {self.para_set_str} ---",
             f"hash = {self.hsh}",
             f"n = {self.n}",
             f"w = {self.w}",
             f"len1 = {self.len1}",
             f"len = {self.len}"]
        s2 = "-" * len(s[1])
        s.append(s2)
        return "\n".join(s)

    def choose_para_set (self):
        self.from_str(choose_from_list(self.wots_set_str))
        print(self)


class XMSSPara(WotsPara):
    # A fake parameter set for fast test
    xmss_set_str = ["XMSS-SHA2_4_256"] + ietf_parameters.get_ietf_para_list("XMSS")
    # @:parameter h: merkle tree height
    h = 10

    def from_str(self, sstr):
        # assert sstr in self.xmss_set_str
        s1 = sstr.split("-")
        s2 = s1[1].split("_")
        self.h = int(s2.pop(1))
        wots_str = "WOTSP" + "-" + "_".join(s2)
        super().from_str(wots_str)
        self.para_set_str = sstr

    def __init__ (self):
        self.from_str(self.xmss_set_str[0])

    def choose_para_set (self):
        self.from_str(choose_from_list(self.xmss_set_str))
        print(self)

    def __str__ (self):
        s = super().__str__().split("\n")
        s1 = [f"h = {self.h}"]
        ss = s[:-1] + s1 + [s[-1]]
        return "\n".join(ss)


class XMSSMTPara(XMSSPara):
    # A fake parameter set for fast test
    xmss_mt_set_str = ["XMSSMT-SHA2_6/3_256"] + ietf_parameters.get_ietf_para_list("XMSS_MT")
    # @:parameter h: merkle tree height
    height = 4
    layer = 2

    def from_str (self, sstr):
        assert sstr in self.xmss_mt_set_str
        s1 = sstr.split("-")
        s2 = s1[1].split("_")
        s3 = s2[1].split("/")
        self.height = int(s3[0])
        self.layer = int(s3[1])
        self.h = self.height // self.layer
        xmss_str = f"XMSS-{s2[0]}_{self.h}_{s2[2]}"
        super().from_str(xmss_str)
        self.para_set_str = sstr

    def __init__ (self):
        self.from_str(self.xmss_mt_set_str[0])

    def choose_para_set (self):
        self.from_str(choose_from_list(self.xmss_mt_set_str))
        print(self)

    def __str__ (self):
        s = super().__str__().split("\n")
        s1 = [f"height/h = {self.height}", f"layer/d = {self.layer}"]
        ss = s[:-1] + s1 + [s[-1]]
        return "\n".join(ss)


if __name__ == "__main__":
    para = XMSSMTPara()
    print(para)
    para.choose_para_set()