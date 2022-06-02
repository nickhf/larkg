from frodokem import FrodoKEM
import numpy as np
import struct, bitstring
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def hkdf(ikm, info, length=64):
    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=length,
        salt=None,
        info=info,
        backend=default_backend(),
    )

    return hkdf.derive(ikm)

def hmac(key, data):
    hmac = HMAC(key, hashes.SHA512(), default_backend())
    hmac.update(data)
    return hmac.finalize()

class ARKG_KEM(FrodoKEM):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        #self.print_intermediate_values = True
        self.seedA = b' '*self.len_seedA_bytes
        self.A = self.gen(self.seedA)

    def keygen(self):
        """Generate a public key / secret key pair (FrodoKEM specification, 
        Algorithm 12)"""
        # 1. Choose uniformly random seeds s || seedSE || z
        s_seedSE_z = self.randombytes(self.len_s_bytes + self.len_seedSE_bytes + self.len_z_bytes)
        self.__print_intermediate_value("randomness", s_seedSE_z)
        s = bytes(s_seedSE_z[0:self.len_s_bytes])
        seedSE = bytes(s_seedSE_z[self.len_s_bytes : self.len_s_bytes + self.len_seedSE_bytes])
        z = bytes(s_seedSE_z[self.len_s_bytes + self.len_seedSE_bytes : self.len_s_bytes + self.len_seedSE_bytes + self.len_z_bytes])
        # 2. Generate pseudorandom seed seedA = SHAKE(z, len_seedA) (length in bits)
        #seedA = self.shake(z, self.len_seedA_bytes)
        #self.__print_intermediate_value("seedA", seedA)
        # 3. A = Frodo.Gen(seedA)
        #A = self.gen(seedA)
        # self.__print_intermediate_value("A", A)
        # 4. r = SHAKE(0x5F || seedSE, 2*n*nbar*len_chi) (length in bits), parsed as 2*n*nbar len_chi-bit integers in little-endian byte order
        rbytes = self.shake(bytes(b'\x5f') + seedSE, 2 * self.n * self.nbar * self.len_chi_bytes)
        r = [struct.unpack_from('<H', rbytes, 2*i)[0] for i in range(2 * self.n * self.nbar)]
        self.__print_intermediate_value("r", r)
        # 5. S^T = Frodo.SampleMatrix(r[0 .. n*nbar-1], nbar, n)
        Stransposed = self.sample_matrix(r[0 : self.n * self.nbar], self.nbar, self.n)
        self.__print_intermediate_value("S^T", Stransposed)
        S = self.__matrix_transpose(Stransposed)
        # 6. E = Frodo.SampleMatrix(r[n*nbar .. 2*n*nbar-1], n, nbar)
        E = self.sample_matrix(r[self.n * self.nbar : 2 * self.n * self.nbar], self.n, self.nbar)
        # self.__print_intermediate_value("E", E)
        # 7. B = A S + E
        #print'E',E)
        #print'Froebenius Norm of E', np.linalg.norm(E), np.linalg.norm(E, np.inf))
        B = self.__matrix_add(self.__matrix_mul(self.A,S), E)
        self.__print_intermediate_value("B", B)
        #print'B',B)
        ##print'A',A)
        # 8. b = Pack(B)
        b = self.pack(B)
        self.__print_intermediate_value("b", b)
        # 9. pkh = SHAKE(seedA || b, len_pkh) (length in bits)
        pkh = self.shake(self.seedA + b, self.len_pkh_bytes)
        self.__print_intermediate_value("pkh", pkh)
        # 10. pk = seedA || b, sk = (s || seedA || b, S^T, pkh)
        pk = self.seedA + b
        assert len(pk) == self.len_pk_bytes
        sk = bitstring.BitArray()
        sk.append(s + self.seedA + b)
        for i in range(self.nbar):
            for j in range(self.n):
                sk.append(bitstring.BitArray(intle = Stransposed[i][j], length = 16))
        sk.append(pkh)
        sk = sk.bytes
        assert len(sk) == self.len_sk_bytes
        return (pk, sk, S, B)


    def kem_keygen(self):
        """Generate a public key / secret key pair (FrodoKEM specification, 
        Algorithm 12)"""
        # 1. Choose uniformly random seeds s || seedSE || z
        s_seedSE_z = self.randombytes(self.len_s_bytes + self.len_seedSE_bytes + self.len_z_bytes)
        self.__print_intermediate_value("randomness", s_seedSE_z)
        s = bytes(s_seedSE_z[0:self.len_s_bytes])
        seedSE = bytes(s_seedSE_z[self.len_s_bytes : self.len_s_bytes + self.len_seedSE_bytes])
        #z = bytes(s_seedSE_z[self.len_s_bytes + self.len_seedSE_bytes : self.len_s_bytes + self.len_seedSE_bytes + self.len_z_bytes])
        # 2. Generate pseudorandom seed seedA = SHAKE(z, len_seedA) (length in bits)
        #seedA = self.shake(z, self.len_seedA_bytes)
        #self.__print_intermediate_value("seedA", seedA)
        # 3. A = Frodo.Gen(seedA)
        A = self.A
        # self.__print_intermediate_value("A", A)
        # 4. r = SHAKE(0x5F || seedSE, 2*n*nbar*len_chi) (length in bits), parsed as 2*n*nbar len_chi-bit integers in little-endian byte order
        rbytes = self.shake(bytes(b'\x5f') + seedSE, 2 * self.n * self.nbar * self.len_chi_bytes)
        r = [struct.unpack_from('<H', rbytes, 2*i)[0] for i in range(2 * self.n * self.nbar)]
        self.__print_intermediate_value("r", r)
        # 5. S^T = Frodo.SampleMatrix(r[0 .. n*nbar-1], nbar, n)
        Stransposed = self.sample_matrix(r[0 : self.n * self.nbar], self.nbar, self.n)
        self.__print_intermediate_value("S^T", Stransposed)
        S = self.__matrix_transpose(Stransposed)
        # 6. E = Frodo.SampleMatrix(r[n*nbar .. 2*n*nbar-1], n, nbar)
        E = self.sample_matrix(r[self.n * self.nbar : 2 * self.n * self.nbar], self.n, self.nbar)
        # self.__print_intermediate_value("E", E)
        # 7. B = A S + E
        #print'E',E)
        #print'Froebenius Norm of E', np.linalg.norm(E), np.linalg.norm(E, np.inf))
        B = self.__matrix_add(self.__matrix_mul(A,S), E)
        self.__print_intermediate_value("B", B)
        #print'B',B)
        #print'A',A)
        # 8. b = Pack(B)
        b = self.pack(B)
        self.__print_intermediate_value("b", b)
        # 9. pkh = SHAKE(seedA || b, len_pkh) (length in bits)
        pkh = self.shake(self.seedA + b, self.len_pkh_bytes)
        self.__print_intermediate_value("pkh", pkh)
        # 10. pk = seedA || b, sk = (s || seedA || b, S^T, pkh)
        pk = self.seedA + b
        assert len(pk) == self.len_pk_bytes
        sk = bitstring.BitArray()
        sk.append(s + self.seedA + b)
        for i in range(self.nbar):
            for j in range(self.n):
                sk.append(bitstring.BitArray(intle = Stransposed[i][j], length = 16))
        sk.append(pkh)
        sk = sk.bytes
        assert len(sk) == self.len_sk_bytes
        return (pk, sk, S, B)
        
    def kem_encaps(self, pk):
        """Encapsulate against a public key to create a ciphertext and shared secret 
        (FrodoKEM specification, Algorithm 13)"""
        # Parse pk = seedA || b
        assert len(pk) == self.len_seedA_bytes + self.D * self.n * self.nbar / 8, "Incorrect public key length"
        seedA = self.seedA #pk[0 : self.len_seedA_bytes]
        b = pk[self.len_seedA_bytes:]
        # 1. Choose a uniformly random key mu in {0,1}^len_mu (length in bits)
        mu = self.randombytes(self.len_mu_bytes)
        self.__print_intermediate_value("mu", mu)
        # 2. pkh = SHAKE(pk, len_pkh)
        pkh = self.shake(pk, self.len_pkh_bytes)
        self.__print_intermediate_value("pkh", pkh)
        # 3. seedSE || k = SHAKE(pkh || mu, len_seedSE + len_k) (length in bits)
        seedSE_k = self.shake(pkh + mu, self.len_seedSE_bytes + self.len_k_bytes)
        seedSE = seedSE_k[0:self.len_seedSE_bytes]
        self.__print_intermediate_value("seedSE", seedSE)
        k = seedSE_k[self.len_seedSE_bytes:self.len_seedSE_bytes + self.len_k_bytes]
        self.__print_intermediate_value("k", k)
        # 4. r = SHAKE(0x96 || seedSE, 2*mbar*n + mbar*nbar*len_chi) (length in bits)
        rbytes = self.shake(bytes(b'\x96') + seedSE, (2 * self.mbar * self.n + self.mbar * self.mbar) * self.len_chi_bytes)
        r = [struct.unpack_from('<H', rbytes, 2*i)[0] for i in range(2 * self.mbar * self.n + self.mbar * self.nbar)]
        self.__print_intermediate_value("r", r)
        # 5. S' = Frodo.SampleMatrix(r[0 .. mbar*n-1], mbar, n)
        Sprime = self.sample_matrix(r[0 : self.mbar * self.n], self.mbar, self.n)
        self.__print_intermediate_value("S'", Sprime)
        # 6. E' = Frodo.SampleMatrix(r[mbar*n .. 2*mbar*n-1], mbar, n)
        Eprime = self.sample_matrix(r[self.mbar * self.n : 2 * self.mbar * self.n], self.mbar, self.n)
        self.__print_intermediate_value("E'", Eprime)
        # 7. A = Frodo.Gen(seedA)
        A = self.A #self.gen(seedA)
        # 8. B' = S' A + E'
        Bprime = self.__matrix_add(self.__matrix_mul(Sprime, A), Eprime)
        self.__print_intermediate_value("B'", Bprime)
        # 9. c1 = Frodo.Pack(B')
        c1 = self.pack(Bprime)
        self.__print_intermediate_value("c1", c1)
        # 10. E'' = Frodo.SampleMatrix(r[2*mbar*n .. 2*mbar*n + mbar*nbar-1], mbar, n)
        Eprimeprime = self.sample_matrix(r[2 * self.mbar * self.n : 2 * self.mbar * self.n + self.mbar * self.nbar], self.mbar, self.nbar)
        self.__print_intermediate_value("E''", Eprimeprime)
        # 11. B = Frodo.Unpack(b, n, nbar)
        B = self.unpack(b, self.n, self.nbar)
        self.__print_intermediate_value("B", B)
        # 12. V = S' B + E''
        V = self.__matrix_add(self.__matrix_mul(Sprime, B), Eprimeprime)
        self.__print_intermediate_value("V", V)
        # 13. C = V + Frodo.Encode(mu)
        self.__print_intermediate_value("mu_encoded", self.encode(mu))
        C = self.__matrix_add(V, self.encode(mu))
        self.__print_intermediate_value("C", C)
        # 14. c2 = Frodo.Pack(C)
        c2 = self.pack(C)
        self.__print_intermediate_value("c2", c2)
        # 15. ss = SHAKE(c1 || c2 || k, len_ss)
        ss = self.shake(c1 + c2 + k, self.len_ss_bytes)
        ct = c1 + c2
        assert len(ct) == self.len_ct_bytes
        assert len(ss) == self.len_ss_bytes
        return (ct, ss)
    
    
    def kem_decaps(self, sk, ct):
        """Decapsulate a ciphertext using a secret key to obtain a shared secret 
        (FrodoKEM specification, Algorithm 14)"""
        # Parse ct = c1 || c2
        assert len(ct) == self.len_ct_bytes, "Incorrect ciphertext length"
        offset = 0; length = int(self.mbar * self.n * self.D / 8)
        c1 = ct[offset:offset+length]
        self.__print_intermediate_value("c1", c1)
        offset += length; length = int(self.mbar * self.nbar * self.D / 8)
        c2 = ct[offset:offset+length]
        self.__print_intermediate_value("c2", c2)
        # Parse sk = (s || seedA || b, S^T, pkh)
        assert len(sk) == self.len_sk_bytes
        offset = 0; length = self.len_s_bytes
        s = sk[offset:offset+length]
        self.__print_intermediate_value("s", s)
        offset += length; length = self.len_seedA_bytes
        seedA = self.seedA #sk[offset:offset+length]
        self.__print_intermediate_value("seedA", seedA)
        offset += length; length = int(self.D * self.n * self.nbar / 8)
        b = sk[offset:offset+length]
        self.__print_intermediate_value("b", b)
        offset += length; length = int(self.n * self.nbar * 16 / 8)
        Sbytes = bitstring.ConstBitStream(sk[offset:offset+length])
        Stransposed = [[0 for j in range(self.n)] for i in range(self.nbar)]
        for i in range(self.nbar):
            for j in range(self.n):
                Stransposed[i][j] = Sbytes.read('intle:16')
        self.__print_intermediate_value("S^T", Stransposed)
        S = self.__matrix_transpose(Stransposed)
        offset += length; length = self.len_pkh_bytes
        pkh = sk[offset:offset+length]
        self.__print_intermediate_value("pkh", pkh)
        # 1. B' = Frodo.Unpack(c1, mbar, n)
        Bprime = self.unpack(c1, self.mbar, self.n)
        self.__print_intermediate_value("B'", Bprime)
        # 2. C = Frodo.Unpack(c2, mbar, nbar)
        C = self.unpack(c2, self.mbar, self.nbar)
        self.__print_intermediate_value("C", C)
        # 3. M = C - B' S
        BprimeS = self.__matrix_mul(Bprime, S)
        self.__print_intermediate_value("B'S", BprimeS)
        M = self.__matrix_sub(C, BprimeS)
        self.__print_intermediate_value("M", M)
        # 4. mu' = Frodo.Decode(M)
        muprime = self.decode(M)
        self.__print_intermediate_value("mu'", muprime)
        # 5. Parse pk = seedA || b
        # (done above)
        # 6. seedSE' || k' = SHAKE(pkh || mu', len_seedSE + len_k) (length in bits)
        seedSEprime_kprime = self.shake(pkh + muprime, self.len_seedSE_bytes + self.len_k_bytes)
        seedSEprime = seedSEprime_kprime[0:self.len_seedSE_bytes]
        self.__print_intermediate_value("seedSE'", seedSEprime)
        kprime = seedSEprime_kprime[self.len_seedSE_bytes:self.len_seedSE_bytes + self.len_k_bytes]
        self.__print_intermediate_value("k'", kprime)
        # 7. r = SHAKE(0x96 || seedSE', 2*mbar*n + mbar*nbar*len_chi) (length in bits)
        rbytes = self.shake(bytes(b'\x96') + seedSEprime, (2 * self.mbar * self.n + self.mbar * self.mbar) * self.len_chi_bytes)
        r = [struct.unpack_from('<H', rbytes, 2*i)[0] for i in range(2 * self.mbar * self.n + self.mbar * self.nbar)]
        self.__print_intermediate_value("r", r)
        # 8. S' = Frodo.SampleMatrix(r[0 .. mbar*n-1], mbar, n)
        Sprime = self.sample_matrix(r[0 : self.mbar * self.n], self.mbar, self.n)
        self.__print_intermediate_value("S'", Sprime)
        # 9. E' = Frodo.SampleMatrix(r[mbar*n .. 2*mbar*n-1], mbar, n)
        Eprime = self.sample_matrix(r[self.mbar * self.n : 2 * self.mbar * self.n], self.mbar, self.n)
        self.__print_intermediate_value("E'", Eprime)
        # 10. A = Frodo.Gen(seedA)
        A = self.A #self.gen(seedA)
        # 11. B'' = S' A + E'
        Bprimeprime = self.__matrix_add(self.__matrix_mul(Sprime, A), Eprime)
        self.__print_intermediate_value("B''", Bprimeprime)
        # 12. E'' = Frodo.SampleMatrix(r[2*mbar*n .. 2*mbar*n + mbar*nbar-1], mbar, n)
        Eprimeprime = self.sample_matrix(r[2 * self.mbar * self.n : 2 * self.mbar * self.n + self.mbar * self.nbar], self.mbar, self.nbar)
        self.__print_intermediate_value("E''", Eprimeprime)
        # 13. B = Frodo.Unpack(b, n, nbar)
        B = self.unpack(b, self.n, self.nbar)
        self.__print_intermediate_value("B", B)
        # 14. V = S' B + E''
        V = self.__matrix_add(self.__matrix_mul(Sprime, B), Eprimeprime)
        self.__print_intermediate_value("V", V)
        # 15. C' = V + Frodo.Encode(muprime)
        Cprime = self.__matrix_add(V, self.encode(muprime))
        self.__print_intermediate_value("C'", Cprime)
        # 16. (in constant time) kbar = kprime if (B' || C == B'' || C') else kbar = s
        # Needs to avoid branching on secret data as per:
        #     Qian Guo, Thomas Johansson, Alexander Nilsson. A key-recovery timing attack on post-quantum 
        #     primitives using the Fujisaki-Okamoto transformation and its application on FrodoKEM. In CRYPTO 2020.
        use_kprime = self.__ctverify(Bprime + C, Bprimeprime + Cprime)
        kbar = self.__ctselect(kprime, s, use_kprime)
        # 17. ss = SHAKE(c1 || c2 || kbar, len_ss) (length in bits)
        ss = self.shake(c1 + c2 + kbar, self.len_ss_bytes)
        assert len(ss) == self.len_ss_bytes
        return ss


    def mat_add(self, A, B):
        return self._FrodoKEM__matrix_add(A, B)
    
    def __matrix_add(self, A, B):
        return self._FrodoKEM__matrix_add(A, B)
    
    def mat_mul(self, A, B):
        return self._FrodoKEM__matrix_mul(A, B)
    
    def __matrix_mul(self, A, B):
        return self._FrodoKEM__matrix_mul(A, B)
    
    def mat_mul(self, A, B):
        return self._FrodoKEM__matrix_mul(A, B)
        
    def __print_intermediate_value(self, name, value):
        return self._FrodoKEM__print_intermediate_value(name, value)
    
    def matrix_sub(self, a, b):
        return self._FrodoKEM__matrix_sub(a,b)
    
    def __matrix_sub(self, a, b):
        return self._FrodoKEM__matrix_sub(a,b)
    
    def __ctverify(self, a, b):
        return self._FrodoKEM__ctverify(a,b)
    
    def __ctselect(self, a, b, c):
        return self._FrodoKEM__ctselect(a,b,c)
    
    def __matrix_transpose(self, e):
        return self._FrodoKEM__matrix_transpose(e)
    
    def sample(self, r):
        """Sample from the error distribution using noise r (a two-byte array 
        encoding a 16-bit integer in little-endian byte order) (FrodoKEM 
        specification, Algorithm 5)"""
        # 1. t = sum_{i=1}^{len_x - 1} r_i * 2^{i-1}
        t = r >> 1
        # 2. e = 0
        e = 0
        # 3. for z = 0; z < s; z += 1
        for z in range(len(self.T_chi) - 1):
            # 4. if t > T_chi(z)
            if t > self.T_chi[z]:
                # 5. e = e + 1
                e += 1
        # 6. e = (-1)^{r_0} * e
        r0 = r % 2
        e = ((-1) ** r0) * e
        return e

    def sample_matrix(self, r, n1, n2):
        """Sample an n1 x n2 matrix from the error distribution using noise r 
        (FrodoKEM specification, Algorithm 6)"""
        E = [[None for j in range(n2)] for i in range(n1)]
        # 1. for i = 0; i < n1; i += 1
        for i in range(n1):
            # 2. for j = 0; j < n2; j += 1
            for j in range(n2):
                # 3. E[i][j] = Frodo.Sample(r^{i*n2+j}, T_chi)
                E[i][j] = self.sample(r[i * n2 + j])
        return E


def concat(in_array):
    out = []
    for i in range(0, len(in_array), 2):
        out.append(int.from_bytes(bytearray([in_array[i], in_array[i+1]]), 'little'))
    return out


def to_signed(input):
    for i in range(arkg_kem.n):
        for j in range(arkg_kem.nbar):
            if input[i][j] > np.abs(input[i][j] - 65536):
                input[i][j] = input[i][j] - 65536
    return input


def derive_pk(S,B):
    c, K = arkg_kem.kem_encaps(S)
    kmac = hkdf(K, b'1')
    kcred = concat([b for b in hkdf(K, b'2', length=arkg_kem.n*arkg_kem.nbar*2)])
    kcred = arkg_kem.sample_matrix(kcred,arkg_kem.n, arkg_kem.nbar)

    mu = hmac(kmac, c)
    P = arkg_kem.mat_add(arkg_kem.unpack(S, arkg_kem.n, arkg_kem.nbar), arkg_kem.mat_mul(arkg_kem.A, kcred))
    ppp = arkg_kem.mat_add(B,arkg_kem.mat_mul(arkg_kem.A,kcred))
    cred = c, mu

    return P, cred, ppp


def derive_sk(sk, sm, cred):
    c, mu = cred
    K = arkg_kem.kem_decaps(sk, c)

    kmac = hkdf(K, b'1')
    kcred = concat([b for b in hkdf(K, b'2', length=arkg_kem.n*arkg_kem.nbar*2)])   
    kcred = arkg_kem.sample_matrix(kcred,arkg_kem.n, arkg_kem.nbar)

    new_sm = to_signed(sm)
    p = arkg_kem.mat_add(new_sm, kcred)
    return p, kcred


def check(pkp,skp,P, B, kcred):
    Pprime = to_signed(arkg_kem.mat_mul(arkg_kem.A, skp))
    new_sm = to_signed(skp)
    a = to_signed(arkg_kem.matrix_sub(pkp, Pprime))
    return np.linalg.norm(a, np.inf) % arkg_kem.q < 256 and np.linalg.norm(new_sm) < 512


arkg_kem = ARKG_KEM("FrodoKEM-976-AES")
S, s, sm, B = arkg_kem.kem_keygen()
P, cred, p = derive_pk(S,B)
ppp = to_signed(p)
skp, kcred = derive_sk(s, sm, cred)
print(check(ppp, skp, P, B, kcred))

