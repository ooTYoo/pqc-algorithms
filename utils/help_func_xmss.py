import math


def bytewise_and(a: bytes, b:bytes) -> bytes:
    """bytewise AND, requires same input length"""
    assert len(a) == len(b)
    return bytes([a[i] & b[i] for i in range(len(a))])


def bytewise_xor(a: bytes, b:bytes) -> bytes:
    """bytewise XOR, requires same input length"""
    assert len(a) == len(b)
    return bytes([a[i] ^ b[i] for i in range(len(a))])


def int_2_bytes(v:int, y:int)->bytes:
    """ convert int to bytes, using big-endian"""
    assert v >=0 and y>=0
    return v.to_bytes(y,'big')


def int_from_bytes(x:bytes)->int:
    return int.from_bytes(x,'big')


def lg(a:int)->int:
    """calc log_2(a)"""
    return int(math.log(a,2))


def base_w(x:bytes, w:int, out_len:int)->list[int]:
    """
    @input: x is a len_x-byte strings
    @input: w is base, x in {4,16}
    @input: out_len <= 8*len_x / lg(w)
    """
    assert (w in {4,16})
    assert (out_len <= 8*len(x)/lg(w))
    basew = [-1] * out_len
    inn,total = 0,0
    bits = 0
    for i in range(out_len):
        if bits == 0:
            total = x[inn]
            inn += 1
            bits = 8
        bits -= lg(w)
        basew[i] = (total >> bits) & (w-1)
    return basew


def str2fixlen(s,l):
    "convert input string into fixed lenght l"
    return (s+' '*l)[:l]


def pretty_pf(fd, prefix:str, lyst:list[bytes]):
    fd.write(prefix + "[" + "\n")
    for a in lyst:
        fd.write("\t" + a.hex() + ",\n")
    fd.write("]\n")


def choose_from_list(lyst):
    for i, a in enumerate(lyst):
        print(f"({i})\t{a}")
    i = int(input("choose parameter set by number:\n"))
    assert i in list(range(len(lyst)))
    return lyst[i]


if __name__ == "__main__":
    x = bytes.fromhex("1234")
    print(base_w(x,16,4))
    print(base_w(x, 16, 3))
    print(int_2_bytes(255,32))
