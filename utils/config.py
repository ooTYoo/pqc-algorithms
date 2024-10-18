import os

p = os.path.dirname(__file__)
proj_dir = os.path.abspath(os.path.join(p,".."))

# xmss related files
wots_log = os.path.join(proj_dir, "data", "log.txt")
xmss_sk_f = os.path.join(proj_dir, "data", "xmss_cache.sk.bin")
xmss_pk_f = os.path.join(proj_dir, "data", "xmss_cache.pk.bin")
xmss_mt_sk_f = os.path.join(proj_dir, "data", "xmss_mt_cache.sk.bin")
xmss_mt_pk_f = os.path.join(proj_dir, "data", "xmss_mt_cache.pk.bin")


if __name__ == "__main__":
    print(p)
    print(proj_dir)

