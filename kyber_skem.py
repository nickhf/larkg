from kyber import Kyber, DEFAULT_PARAMETERS

class KyberSKEM(Kyber):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.keygen_dec = self.keygen

        # Fix public parameters rho and A.
        self.rho, _ = self._g(self.random_bytes(32))
        self.A = self._generate_matrix_from_seed(self.rho, is_ntt=True)
        self.At = self._generate_matrix_from_seed(self.rho, transpose=True,
                                                  is_ntt=True)


    ''' Kyber CPA PKE KeyGen with fixed A. '''
    def _cpapke_keygen(self):
        N, _, sigma = 0, *self._g(self.random_bytes(32))

        # Generate the error vector s ∈ R^k
        s, N = self._generate_error_vector(sigma, self.eta_1, N)
        s.to_ntt()

        # Generate the error vector e ∈ R^k
        e, N = self._generate_error_vector(sigma, self.eta_1, N)
        e.to_ntt()

        # Construct the public key
        t = (self.A @ s).to_montgomery() + e

        # Reduce vectors mod^+ q
        t.reduce_coefficents()
        s.reduce_coefficents()

        # Encode elements to bytes and return
        pk = t.encode(l=12) + self.rho
        sk = s.encode(l=12)
        return pk, sk


    ''' Returns encapsulation keypair. '''
    def keygen_enc(self):
        N, coins = 0, self.random_bytes(32)

        # Generate the error vector r ∈ R^k
        skp, N = self._generate_error_vector(coins, self.eta_1, N)
        skp.to_ntt()

        # Generate the error vector e1 ∈ R^k
        e1, N = self._generate_error_vector(coins, self.eta_2, N)

        # Module/Polynomial arithmatic
        u = (self.At @ skp).from_ntt() + e1

        u.reduce_coefficents()
        skp.reduce_coefficents()

        # Ciphertext to bytes
        pkp = u.encode(l=12)

        return pkp, skp


    ''' Encapsulate for pk using skp. '''
    def encaps(self, skp, pk):
        N, K = 0, self._h(self.random_bytes(32))
        tt = self.M.decode(pk, 1, self.k, l=12, is_ntt=True)

        # Encode message as polynomial
        m_poly = self.R.decode(K, l=1).decompress(1)

        coins = self.random_bytes(32)

        # Generate the error polynomial e2 ∈ R
        input_bytes = self._prf(coins,  bytes([N]), 64*self.eta_2)
        e2 = self.R.cbd(input_bytes, self.eta_2)

        # Module/Polynomial arithmatic 
        v = (tt @ skp)[0][0].from_ntt()
        v = v + e2 + m_poly

        # Ciphertext to bytes
        c = v.compress(self.dv).encode(l=self.dv)

        return c, K


    ''' Decapsulate ciphertext C with sk and pkp. '''
    def decaps(self, sk, c, pkp):
        u = self.M.decode(pkp, self.k, 1, l=12)
        u.to_ntt()

        v = self.R.decode(c, l=self.dv).decompress(self.dv)

        # s_transpose (already in NTT form)
        st = self.M.decode(sk, 1, self.k, l=12, is_ntt=True)

        # Recover message as polynomial
        m = (st @ u)[0][0].from_ntt()
        m = v - m

        # Return message as bytes
        m = m.compress(1).encode(l=1)
        return m


if __name__ == '__main__':
    skem = KyberSKEM(DEFAULT_PARAMETERS['kyber_1024'])
    pk, sk = skem.keygen_dec()
    pkp, skp = skem.keygen_enc()
    c, K = skem.encaps(skp, pk)
    kk = skem.decaps(sk, c, pkp)
    assert K == kk
