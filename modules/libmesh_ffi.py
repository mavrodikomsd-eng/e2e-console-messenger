import ctypes
import os

_DLL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "libmesh")


class Libmesh(object):
    def __init__(self):
        self._lib = ctypes.CDLL(os.path.join(_DLL_DIR, "libmesh.dll"))

        self._lib.lm_derive_key.restype = ctypes.c_int
        self._lib.lm_derive_key.argtypes = [ctypes.c_char_p, ctypes.c_char_p,
                                            ctypes.POINTER(ctypes.c_ubyte)]

        self._lib.lm_gcm_encrypt_b64.restype = ctypes.c_int
        self._lib.lm_gcm_encrypt_b64.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_size_t, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_char_p)]

        self._lib.lm_gcm_decrypt_b64.restype = ctypes.c_int
        self._lib.lm_gcm_decrypt_b64.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte), ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,
            ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)),
            ctypes.POINTER(ctypes.c_size_t)]

        self._lib.lm_encrypt_to_peer.restype = ctypes.c_int
        self._lib.lm_encrypt_to_peer.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_char_p)]

        self._lib.lm_load_or_create_identity.restype = ctypes.c_int
        self._lib.lm_load_or_create_identity.argtypes = [
            ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p),
            ctypes.POINTER(ctypes.c_char_p)]

        self._lib.lm_free.restype = None
        self._lib.lm_free.argtypes = [ctypes.c_void_p]

    @staticmethod
    def _buf(data):
        return (ctypes.c_ubyte * len(data)).from_buffer_copy(data)

    def derive_key(self, seed_b64, peer_pub_b64):
        out = (ctypes.c_ubyte * 32)()
        seed = seed_b64.encode() if isinstance(seed_b64, str) else seed_b64
        pub = peer_pub_b64.encode() if isinstance(peer_pub_b64, str) else peer_pub_b64
        if self._lib.lm_derive_key(seed, pub, out) != 0:
            raise ValueError("derive_key failed")
        return bytes(out)

    def gcm_encrypt(self, key, plaintext, aad=b""):
        keyb = self._buf(key)
        pt = self._buf(plaintext)
        aadb = self._buf(aad) if aad else ctypes.POINTER(ctypes.c_ubyte)()
        out = ctypes.c_char_p()
        rc = self._lib.lm_gcm_encrypt_b64(keyb, pt, len(plaintext),
                                          aadb, len(aad), ctypes.byref(out))
        if rc != 0:
            raise ValueError("gcm_encrypt failed")
        return out.value.decode("ascii")

    def gcm_decrypt(self, key, encoded, aad=b""):
        keyb = self._buf(key)
        aadb = self._buf(aad) if aad else ctypes.POINTER(ctypes.c_ubyte)()
        out = ctypes.POINTER(ctypes.c_ubyte)()
        outlen = ctypes.c_size_t()
        rc = self._lib.lm_gcm_decrypt_b64(keyb, encoded.encode("ascii"),
                                          aadb, len(aad), ctypes.byref(out),
                                          ctypes.byref(outlen))
        if rc != 0:
            return None
        try:
            return bytes(out[:outlen.value]).decode("utf-8")
        finally:
            self._lib.lm_free(ctypes.cast(out, ctypes.c_void_p))

    def encrypt_to_peer(self, our_seed_b64, peer_pub_b64, self_pub_b64, plaintext):
        pt = self._buf(plaintext)
        out = ctypes.c_char_p()
        rc = self._lib.lm_encrypt_to_peer(
            our_seed_b64.encode(), peer_pub_b64.encode(), self_pub_b64.encode(),
            pt, len(plaintext), ctypes.byref(out))
        if rc != 0:
            raise ValueError("encrypt_to_peer failed")
        return out.value.decode("ascii")

    def load_or_create_identity(self, path):
        seed_p = ctypes.c_char_p()
        pub_p = ctypes.c_char_p()
        rc = self._lib.lm_load_or_create_identity(path.encode(),
                                                  ctypes.byref(seed_p),
                                                  ctypes.byref(pub_p))
        if rc != 0:
            raise ValueError("identity failed")
        return seed_p.value.decode(), pub_p.value.decode()


_libmesh = Libmesh()