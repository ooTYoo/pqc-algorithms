import os
import copy

from para_set import *
from xmss_address import *
from wotsp import *
from utils.config import xmss_pk_f, xmss_sk_f


class XMSS_SK():
    def __init__(self, para: XMSSPara, cache_flag = True):
        self.cflag = cache_flag
        self.para = para
        self.sk_size = self.para.len * self.para.n
        self.leaf_idx = 0
        self.SK_PRF = None
        self.SEED = None
        self.main_secret = None
        self.secure = True

    def set_seed(self, s:bytes):
        assert len(s) == self.para.n
        self.SEED = s

    def set_sprf(self, s:bytes):
        assert len(s) == self.para.n
        self.SK_PRF = s

    def set_main_secret(self, s: bytes):
        assert len(s) == self.para.n
        self.main_secret = s
        self.cflag = False

    def get_wots_sk(self, i) -> list[bytes]:
        assert self.leaf_idx <= i < (1 << self.para.h)
        sk = None
        if self.cflag:
            with open(xmss_sk_f, "rb") as fin:
                fin.seek(self.sk_size*i)
                tmp = fin.read(self.para.len * self.para.n)
                assert len(tmp) == self.para.len * self.para.n
                SK = WotspSK(self.para.n, self.para.len)
                SK.from_bytes(tmp)
                sk = SK.get()
        else:
            s_ots = self.para.PRF(self.main_secret, int_2_bytes(i,32))
            sk = [self.para.PRF(s_ots, int_2_bytes(j,32)) for j in range(self.para.len)]
        return sk

    def get_wots_lpk(self, i):
        assert (0 <= i < (1 << self.para.h))
        with open(xmss_pk_f, 'rb') as fin:
            fin.seek(self.para.n*i)
            lpk = fin.read(self.para.n)
        return lpk

    def set_idx(self, idx):
        '''for security reason, idx can only increase'''
        if self.secure:
            assert self.leaf_idx <= idx <= (1<<self.para.h)
        self.leaf_idx = idx

    def get_idx(self):
        return self.leaf_idx

    def increase_idx(self):
        self.leaf_idx += 1


class XMSS_PK():
    OID = b'XMSS_PK'
    root = None
    SEED = 0


class XMSS():
    def __init__(self, para:XMSSPara, rng=os.urandom):
        self.para = para
        self.PRF = para.PRF
        self.H = para.H
        self.H_msg = para.H_msg
        self.addr = HashTreeAddress()
        self.main_secret = None
        self.rng = rng
        self.wots_mod = WOTSP(self.para, rng=self.rng)

    def set_tree_location(self, layer, tree):
        self.addr = HashTreeAddress(layer, tree)

    def rand_hash(self,seed:bytes, left:bytes, right:bytes, addr:Address) -> bytes:
        assert (len(left) == self.para.n and len(right) == len(left))
        addr.set_keyAndMask(0)
        key = self.PRF(seed, addr)
        addr.set_keyAndMask(1)
        bm_0 = self.PRF(seed, addr)
        addr.set_keyAndMask(2)
        bm_1 = self.PRF(seed, addr)
        return self.H(key, bytewise_xor(left, bm_0) + bytewise_xor(right, bm_1))

    def ltree(self,seed:bytes, wots_pk:list[bytes], addr:LTreeAddress) -> bytes:
        """compress pubkeys of WOTS+ to merkle-tree leaf"""
        assert len(wots_pk) == self.para.len
        lenn = self.para.len
        addr.set_tree_height(0)

        while lenn > 1:
            for i in range(lenn//2):
                addr.set_tree_index(i)
                wots_pk[i] = self.rand_hash(seed, wots_pk[2*i], wots_pk[2*i+1], addr)
            if ( lenn & 0x1 ) == 1:
                wots_pk[lenn>>1] = wots_pk[lenn-1]
            lenn = (lenn + 1)>>2
            addr.set_tree_height(addr.get_tree_height()+1)
        return wots_pk[0]

    def tree_hash(self, SK:XMSS_SK, start:int, node_h:int) -> bytes:
        # this implementation is diff from IETF doc, where address is from all zero
        # here address using hashTreeAddr, makes calculation different for each tree
        # if only XMSS is used, this is equivalent to IETF doc
        assert start & ((1<< node_h)-1) == 0
        stack = []
        for i in range(1<<node_h):
            node = SK.get_wots_lpk(start + i)

            self.addr.set_type(2)
            self.addr.set_tree_height(0)
            self.addr.set_tree_index(i + start)

            while len(stack)>0 and stack[-1][0] == self.addr.get_tree_height():
                tree_index = (self.addr.get_tree_index() -1)>>1
                if tree_index < 0:
                    tree_index = 0
                self.addr.set_tree_index(tree_index)
                node = self.rand_hash(SK.SEED, stack.pop()[1], node, self.addr)
                self.addr.set_tree_height(self.addr.get_tree_height() + 1)
            stack.append([self.addr.get_tree_height(), node])
        return stack.pop()[1]

    def set_main_secret(self, s:bytes):
        assert len(s)== self.para.n
        self.main_secret = s

    def keygen_reduced(self, seed:bytes, sprf:bytes, cache_f = True):
        assert len(seed) == self.para.n
        assert len(sprf) == self.para.n
        self.wots_mod.set_seed(seed)
        addr = self.addr.to_wots_address()
        if cache_f:
            self.wots_mod.skdf_flag = False
            with open(xmss_sk_f, "wb+") as fsk:
                with open(xmss_pk_f, "wb+") as fpk:
                    for ots in range(1 << self.para.h):
                        addr.set_ots_address(ots)
                        self.wots_mod.set_address(addr)
                        sk = self.wots_mod.gen_sk()
                        pk = self.wots_mod.gen_pk_from_sk(sk)
                        fsk.write(b''.join(sk))
                        laddr = self.addr.to_ltree_addr()
                        laddr.set_ltree_address(ots)
                        node = self.ltree(seed, pk, laddr)
                        fpk.write(node)
        else:
            if self.main_secret is None:
                self.main_secret = self.rng(self.para.n)
            with open(xmss_pk_f, "wb+") as fpk:
                for ots in range(1 << self.para.h):
                    s_ots = self.para.PRF(self.main_secret, int_2_bytes(ots, 32))
                    self.wots_mod.set_pseudo_kdf(s_ots)
                    addr.set_ots_address(ots)
                    self.wots_mod.set_address(addr)
                    sk = self.wots_mod.gen_sk()
                    pk = self.wots_mod.gen_pk_from_sk(sk)
                    laddr = self.addr.to_ltree_addr()
                    laddr.set_ltree_address(ots)
                    node = self.ltree(seed, pk, laddr)
                    fpk.write(node)
        SK = XMSS_SK(self.para)
        SK.set_seed(seed)
        SK.set_sprf(sprf)
        if not cache_f:
            SK.set_main_secret(self.main_secret)
        root = self.tree_hash(SK, 0, self.para.h)
        SK.root = root
        PK = XMSS_PK()
        PK.SEED = seed
        PK.root = root
        return SK, PK

    def keygen(self, cache_f:bool):
        seed = self.rng(self.para.n)
        sprf = self.rng(self.para.n)
        return self.keygen_reduced(seed, sprf, cache_f)

    def build_auth(self, SK:XMSS_SK, i:int) -> list[bytes]:
        auth = [None] * self.para.h
        for j in range(self.para.h):
            k = (i>>j) ^ 1
            auth[j] = self.tree_hash(SK, k<<j, j)
        return auth

    def tree_sign(self, SK:XMSS_SK, mesg:bytes) -> bytes:
        index = SK.get_idx()
        auth = self.build_auth(SK, index)

        ots_addr = self.addr.to_wots_address()
        ots_addr.set_ots_address(index)
        self.wots_mod.set_address(ots_addr)

        sig_ots = self.wots_mod.sign(SK.get_wots_sk(index), mesg)
        return [sig_ots] + auth

    def sign(self, SK:XMSS_SK, mesg: bytes) -> bytes:
        assert len(mesg) == self.para.n
        index = SK.get_idx()

        r = self.PRF(SK.SK_PRF, int_2_bytes(index,32))
        mm = self.H_msg(r, SK.root, int_2_bytes(index, 32), mesg)
        sig = [int_2_bytes(index, 4), r] + self.tree_sign(SK, mm)

        SK.increase_idx()
        return sig

    def root_from_sign(self, seed:bytes, sig, mm) -> bytes:
        index = int_from_bytes(sig[0])
        addr = self.addr.to_wots_address()
        addr.set_ots_address(index)
        self.wots_mod.set_address(addr)
        self.wots_mod.set_seed(seed)
        pk_ots = self.wots_mod.pk_from_sig(mm, sig[2])

        addr = self.addr.to_ltree_addr()
        addr.set_ltree_address(index)
        node = [None]*2
        node[0] = self.ltree(seed, pk_ots, addr)

        self.addr.set_type(2)
        self.addr.set_tree_index(index)
        auth = sig[3:]
        for k in range(self.para.h):
            self.addr.set_tree_height(k)
            self.addr.set_tree_index(self.addr.get_tree_index() >> 2)
            if (index >> k) & 0x1 == 0:
                node[1] = self.rand_hash(seed, node[0], auth[k], self.addr)
            else:
                node[1] = self.rand_hash(seed, auth[k], node[0], self.addr)
            node[0] = node[1]
        return node[0]

    def verify(self, PK:XMSS_PK, mesg, sig) -> bool:
        index = int_from_bytes(sig[0])
        mm = self.H_msg(sig[1], PK.root, int_2_bytes(index, self.para.n), mesg)
        node = self.root_from_sign(PK.SEED, sig, mm)
        return node == PK.root


if __name__ == "__main__":
    para = XMSSPara()
    xmss = XMSS(para)
    xmss.set_tree_location(3,11)
    SK, PK = xmss.keygen(cache_f=True)
    SK.set_idx(3)
    m = b"A"*para.n
    sign = xmss.sign(SK, m)
    rslt = xmss.verify(PK, m, sign)
    print(f"XMSS signature verify {rslt}")
