import ctypes
import struct
from utils.help_func_xmss import *

'''
A 32Byte address is used to randomize each hash call
There are 3 addresses for different use cases
* for OTS schemes
* for hashes within Main Merkle tree construction
* for L-tree to compress OTS public key
'''
# class OtsAddress(ctypes.Structure):
#     _fields_ = [
#         ('layer_address', ctypes.c_uint32),
#         ('tree_address',  ctypes.c_uint64),
#         ('type',          ctypes.c_uint32),
#         ('ots_address',   ctypes.c_uint32),
#         ('chain_address', ctypes.c_uint32),
#         ('hash_address',  ctypes.c_uint32),
#         ('keyAndMask',    ctypes.c_uint32),
#     ]
#
# class LTreeAddress(ctypes.Structure):
#     _fields_ = [
#         ('layer_address',   ctypes.c_uint32),
#         ('tree_address',    ctypes.c_uint64),
#         ('type',            ctypes.c_uint32),
#         ('ltree_address',   ctypes.c_uint32),
#         ('tree_height',     ctypes.c_uint32),
#         ('tree_index',      ctypes.c_uint32),
#         ('keyAndMask',      ctypes.c_uint32),
#     ]
#
# class HashTreeAddress(ctypes.Structure):
#     _fields_ = [
#         ('layer_address',   ctypes.c_uint32),
#         ('tree_address',    ctypes.c_uint64),
#         ('type',            ctypes.c_uint32),
#         ('padding',         ctypes.c_uint32),
#         ('tree_height',     ctypes.c_uint32),
#         ('tree_index',      ctypes.c_uint32),
#         ('keyAndMask',      ctypes.c_uint32),
#     ]


class Address(ctypes.Structure):
    fields = [0] * 7
    field_name = ["layer_address",
                  "tree_address",
                  "type",
                  "field_3",
                  "field_4",
                  "field_5",
                  "keyAndMask"]

    def __init__(self):
        self.fields = [0] * 7

    def __init__(self, layer, tree, type):
        self.fields = [layer, tree, type] + ([0]*4)

    def get_field(self,i):
        return self.fields[i]

    def set_field(self,i, val):
        self.fields[i] = val
        for f in range(i+1,7):
            self.fields[f] = 0

    def get_layer_address(self):
        return self.get_field(0)

    def get_tree_address(self):
        return self.get_field(1)

    def get_type(self):
        return self.get_field(2)

    def get_keyAndMask(self):
        return self.get_field(6)

    def set_layer_address(self, layer):
        self.set_field(0, val = layer)

    def set_tree_address(self, tree):
        self.set_field(1, val = tree)

    def set_type(self, typev):
        self.set_field(2, val = typev)

    def set_keyAndMask(self, val):
        self.fields[6] = val

    def to_byte_list(self):
        r = [struct.pack('>I', self.fields[0]),
             struct.pack('>L', self.fields[1]),
             struct.pack('>I', self.fields[2]),
             struct.pack('>I', self.fields[3]),
             struct.pack('>I', self.fields[4]),
             struct.pack('>I', self.fields[5]),
             struct.pack('>I', self.fields[6])]
        return r

    def to_bytes(self):
        r = b""
        lyst = self.to_byte_list()
        for bb in lyst:
            r += bb
        return bb

    def to_str(self, lens = 24):
        s = ""
        r = self.to_byte_list()
        for i in range(7):
            s += str2fixlen(self.field_name[i], lens)
            s += r[i].hex()
            s += "\n"
        return s


class OtsAddress(Address):
    def __init__(self, layer=0, tree=0):
        self.field_name[3] = "ots_address"
        self.field_name[4] = "chain_address"
        self.field_name[5] = "hash_address"
        super(OtsAddress, self).__init__(layer, tree, 0)

    def __str__(self):
        return self.to_str()

    def get_ots_address(self):
        return self.get_field(3)

    def get_chain_address(self):
        return self.get_field(4)

    def get_hash_address(self):
        self.get_field(5)

    def set_ots_address(self, ots):
        self.set_field(3, ots)

    def set_chain_address(self,chain):
        self.set_field(4, chain)

    def set_hash_address(self, hashaddr):
        self.set_field(5, hashaddr)

    def to_ltree_addr(self):
        return LTreeAddress(self.get_layer_address(), self.get_tree_address())

    def to_hashtree_address(self):
        return HashTreeAddress(self.get_layer_address(), self.get_tree_address())


class LTreeAddress(Address):
    def __init__(self, layer=0, tree=0):
        self.field_name[3] = "ltree_address"
        self.field_name[4] = "tree_height"
        self.field_name[5] = "tree_index"
        super(LTreeAddress, self).__init__(layer, tree, 1)

    def __str__(self):
        return self.to_str()

    def get_ltree_address(self):
        return self.get_field(3)

    def get_tree_height(self):
        return self.get_field(4)

    def get_tree_index(self):
        return self.get_field(5)

    def set_ltree_address(self, ltree):
        self.set_field(3, ltree)

    def set_tree_height(self,h):
        self.set_field(4, h)

    def set_tree_index(self,index):
        self.set_field(5, index)

    def to_wots_address(self) -> OtsAddress:
        return OtsAddress(self.get_layer_address(), self.get_tree_address())

    def to_hashtree_address(self):
        return HashTreeAddress(self.get_layer_address(), self.get_tree_address())


class HashTreeAddress(Address):
    def __init__(self, layer=0, tree=0):
        self.field_name[3] = "padding"
        self.field_name[4] = "tree_height"
        self.field_name[5] = "tree_index"
        super(HashTreeAddress, self).__init__(layer, tree, 2)

    def __str__(self):
        return self.to_str()

    def get_tree_height(self):
        return self.get_field(4)

    def get_tree_index(self):
        return self.get_field(5)

    def set_tree_height(self, h):
        self.set_field(4, h)

    def set_tree_index(self,index):
        self.set_field(5, index)

    def to_wots_address (self) -> OtsAddress:
        return OtsAddress(self.get_layer_address(), self.get_tree_address())

    def to_ltree_addr(self) -> LTreeAddress:
        return LTreeAddress(self.get_layer_address(), self.get_tree_address())


if __name__ == "__main__":
    address = OtsAddress()
    print(address.get_layer_address())
    print(address.to_str())