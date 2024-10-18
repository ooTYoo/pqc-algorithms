import os
import copy

from para_set import *
from xmss_address import *
from wotsp import WOTSP
from Xmss import *
from utils.config import xmss_mt_pk_f, xmss_mt_sk_f, xmss_pk_f, xmss_sk_f


class XMSS_MT_PK():
    OID = b'XMSS_MT_PK'
    MT_root = None
    MT_SEED = 0


class XMSS_MT_SK():
    def __init__(self, para:XMSSMTPara, cache_flag = True):
        self.cflag = cache_flag
        self.para = para
        self.sk_size = self.para.len * self.para.n
        self.idx_MT = 0
        self.MT_root = None
        self.MT_SEED = None
        self.MT_SK_PRF = None
        # internal wots key pair
        self.main_secret = None
        # mod
        self.xmss_sk_mod = XMSS_SK(self.para, cache_flag=True)
        self.xmss_sk_mod.secure = False

    def set_main_secret(self, s:bytes):
        assert len(s) == self.para.n
        self.main_secret = s
        self.cflag = False
        self.xmss_sk_mod.cflag = False

    def set_seed(self, s:bytes):
        assert len(s) == self.para.n
        self.MT_SEED = s
        self.xmss_sk_mod.set_seed(s)

    def set_sprf(self, s:bytes):
        assert len(s) == self.para.n
        self.MT_SK_PRF = s
        self.xmss_sk_mod.set_sprf(s)

    def set_idx(self, idx):
        assert 0<= idx <= (1 << self.para.height)
        self.idx_MT = idx
        self.xmss_sk_mod.set_idx(idx & ((1 << self.para.h) -1))

    def get_idx(self):
        return self.idx_MT

    def increase_idx(self):
        self.set_idx(self.idx_MT + 1)

    # def get_wots_sk(self, idx):
    #     assert 0 <= idx < (1 << self.para.h)
    #     ans = self.xmss_sk_mod.get_wots_sk(idx)
    #     self.idx_MT = idx + 1
    #     return ans
    #
    # def get_wots_lpk(self, idx):
    #     assert 0 <= idx < (1 << self.para.h)
    #     return self.xmss_sk_mod.get_wots_lpk(idx)


class XMSS_MT():
    def __init__(self, para: XMSSMTPara, rng=os.urandom):
        self.para = para
        self.rng = rng
        self.addr = HashTreeAddress()
        self.xmss_mod = XMSS(self.para, rng=self.rng)
        self.sk_size = self.para.len * self.para.n

    def cache_xmss_keys(self, layer, tree):
        cnt = 0
        # leaf layer caller layer = 0
        for l in range(layer):
            cnt += 1 << (self.para.layer - 1 - l)
        cnt += tree
        with open(xmss_mt_sk_f, "rb") as fin:
            with open(xmss_sk_f, "wb") as fsink:
                fin.seek((self.sk_size << self.para.h)*cnt)
                tmp = fin.read(self.sk_size << self.para.h)
                assert len(tmp) == (self.sk_size << self.para.h)
                fsink.write(tmp)
        with open(xmss_mt_pk_f, "rb") as fin:
            with open(xmss_pk_f, "wb") as fsink:
                fin.seek((self.para.n << self.para.h)*cnt)
                tmp = fin.read(self.para.n << self.para.h)
                assert len(tmp) == (self.para.n << self.para.h)
                fsink.write(tmp)
        self.addr.set_layer_address(layer)
        self.addr.set_tree_address(tree)
        self.xmss_mod.set_tree_location(layer, tree)
        print(f"xmss tree at layer={layer}, #={tree} cached")

    def keygen(self, cflag=True):
        seed = self.rng(self.para.n)
        sprf = self.rng(self.para.n)
        SK = XMSS_MT_SK(self.para)

        # gen xmss wots keypairs for all xmss tree
        if cflag:
            with open(xmss_mt_sk_f, "wb+") as fskout:
                with open(xmss_mt_pk_f, "wb+") as fpkout:
                    # layer=0 is the leaf, layer=d is the root
                    for d in range(self.para.layer):
                        for tree in range(0, 1 << (self.para.layer - 1 - d)):
                            self.xmss_mod.set_tree_location(d, tree)
                            self.xmss_mod.keygen_reduced(seed, sprf, cache_f=True)

                            # copy from xmss cache file to mt cache file
                            with open(xmss_sk_f, "rb") as fin:
                                tmp = fin.read(self.sk_size << self.para.h)
                                assert len(tmp) == (self.sk_size << self.para.h)
                                fskout.write(tmp)
                            with open(xmss_pk_f, "rb") as fin:
                                tmp = fin.read(self.para.n << self.para.h)
                                assert len(tmp) == (self.para.n << self.para.h)
                                fpkout.write(tmp)
                            print(f"xmss tree at layer={d}, #={tree} created")
        else:
            main_s = self.rng(self.para.n)
            SK.set_main_secret(main_s)
            with open(xmss_mt_pk_f, "wb+") as fpkout:
                for d in range(self.para.layer):
                    layer_s = self.para.PRF(main_s, int_2_bytes(d, 32))
                    for tree in range(0, 1 << (self.para.layer - 1 - d)):
                        self.xmss_mod.set_tree_location(d, tree)
                        tmp = self.para.PRF(layer_s, int_2_bytes(tree, 32))
                        self.xmss_mod.set_main_secret(tmp)
                        self.xmss_mod.keygen_reduced(seed, sprf, cache_f=False)
                        with open(xmss_pk_f, "rb") as fin:
                            tmp = fin.read(self.para.n << self.para.h)
                            assert len(tmp) == (self.para.n << self.para.h)
                            fpkout.write(tmp)
        # calc root
        SK.set_seed(seed)
        SK.set_sprf(sprf)
        # no need to cache, since the root xmss tree already cached
        # self.cache_xmss_keys(self.para.layer-1, 0)
        if not cflag:
            s = self.para.PRF(SK.main_secret, int_2_bytes(self.para.layer-1, 32))
            s = self.para.PRF(s, int_2_bytes(0, 32))
            SK.xmss_sk_mod.set_main_secret(s)
        self.xmss_mod.set_tree_location(self.para.layer-1, 0)
        MT_root = self.xmss_mod.tree_hash(SK.xmss_sk_mod, 0, self.para.h)

        SK.MT_root = MT_root

        PK = XMSS_MT_PK()
        PK.MT_root = MT_root
        PK.MT_SEED = seed

        return SK, PK

    def sign(self,SK:XMSS_MT_SK, mesg:bytes) -> bytes:
        assert len(mesg) == self.para.n
        #init
        idx_tree = SK.get_idx()

        # message compression
        r = self.para.PRF(SK.MT_SK_PRF, int_2_bytes(idx_tree, self.para.n))
        M = self.para.H_msg(r, SK.MT_root, int_2_bytes(idx_tree, self.para.n), mesg)
        # sig_MT = [int_2_bytes(self.key_idx, self.para.height>>3)]
        # this rightshift may not work, since tree height is less than 64, we hardcode it as 8
        sig_MT = [int_2_bytes(idx_tree, 8)] + [r]

        root = M
        for j in range(0, self.para.layer):
            idx_leaf = idx_tree & ((1 << self.para.h)-1)
            idx_tree = idx_tree >> self.para.h

            self.cache_xmss_keys(j, idx_tree)
            self.addr.set_layer_address(j)
            self.addr.set_tree_address(idx_tree)
            self.xmss_mod.set_tree_location(j, idx_tree)
            if not SK.cflag:
                s = SK.para.PRF(SK.main_secret, int_2_bytes(j, 32))
                s = SK.para.PRF(s, int_2_bytes(idx_tree, 32))
                SK.xmss_sk_mod.set_main_secret(s)

            SK.xmss_sk_mod.set_idx(idx_leaf)
            sig_tmp = self.xmss_mod.tree_sign(SK.xmss_sk_mod, root)
            sig_MT += [sig_tmp]
            root = self.xmss_mod.tree_hash(SK.xmss_sk_mod,0, self.para.h)

        SK.increase_idx()
        return sig_MT

    def verify(self,PK:XMSS_MT_PK, mesg, sig) -> bool:
        idx = int_from_bytes(sig[0])
        r = sig[1]
        M = self.para.H_msg(r, PK.MT_root, int_2_bytes(idx, self.para.n), mesg)

        idx_tree = idx
        node = M
        for j in range(0, self.para.layer):
            idx_leaf = idx_tree & ((1 << self.para.h)-1)
            idx_tree = idx_tree >> self.para.h
            sig0 = sig[2 + j]
            # xmss_sig = [int_2_bytes(idx_leaf, self.para.h >> 3), 0] + sig0
            xmss_sig = [int_2_bytes(idx_leaf, 8), 0] + sig0
            self.addr.set_layer_address(j)
            self.addr.set_tree_address(idx_tree)
            self.xmss_mod.set_tree_location(j, idx_tree)
            node = self.xmss_mod.root_from_sign(PK.MT_SEED, xmss_sig, node) # to check
        return node == PK.MT_root


if __name__ == "__main__":
    para = XMSSMTPara()
    mt = XMSS_MT(para)
    SK,PK = mt.keygen(cflag=False)
    mt.key_idx = 3
    m = b"A"*para.n
    sign = mt.sign(SK, m)
    rslt = mt.verify(PK, m, sign)
    print(f"\nXMSS_MT signature verify {rslt}")























