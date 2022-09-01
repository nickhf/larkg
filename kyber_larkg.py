from kyber_skem import KyberSKEM, Kyber, DEFAULT_PARAMETERS
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from polynomials import PolynomialRing
from collections import namedtuple
import timeit

PublicParams = namedtuple('PublicParams', 'skem k_length kdf')

def hkdf(msg):
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=None,
        backend=default_backend())
    return kdf.derive(msg)

def setup(sec_par=DEFAULT_PARAMETERS['kyber_1024']):
    skem = KyberSKEM(sec_par)
    k_length = (skem.n >> 2) * skem.eta_1
    return PublicParams(skem, k_length, hkdf)

def keygen(pp):
    return pp.skem.keygen_dec()

def derive_pk(pp, pk):
    E, e = pp.skem.keygen_enc()
    c, K = pp.skem.encaps(e, pk)
    mu = pp.kdf(K)

    pk_poly = pp.skem.M.decode(pk, pp.skem.k, 1, l=12, is_ntt=True)

    k_cred, _ = pp.skem._generate_error_vector(K, pp.skem.eta_1, 0)
    k_cred.to_ntt()

    D, _ = pp.skem._generate_error_vector(pp.skem.random_bytes(32),
                                          pp.skem.eta_1, 0)
    D.to_ntt()


    P = (pp.skem.A @ k_cred).to_montgomery() + D + pk_poly
    P.reduce_coefficents()
    P = P.encode(l=12)
    return P, (E, c, mu)

def derive_sk(pp, sk, cred):
    K = pp.skem.decaps(sk, cred[1], cred[0])
    k_cred, _ = pp.skem._generate_error_vector(K, pp.skem.eta_1, 0)
    k_cred.to_ntt()
    k_cred.reduce_coefficents()

    sk_poly = pp.skem.M.decode(sk, pp.skem.k, 1, l=12, is_ntt=True)

    mu = pp.kdf(K)
    if mu == cred[2]:
        skp = k_cred + sk_poly
        skp.reduce_coefficents()

    return skp

def test(pp, skp, pkp):
    skp = skp.encode(l=12)
    pkp = pkp + pp.skem.rho
    m = b' '*32
    c = pp.skem._cpapke_enc(pkp, m, pp.skem.random_bytes(32))
    mm = pp.skem._cpapke_dec(skp, c)
    return m == mm


if __name__ == '__main__':
    pp = setup(DEFAULT_PARAMETERS['kyber_1024'])
    pk, sk = keygen(pp)
    pkp, cred = derive_pk(pp, pk)
    skp = derive_sk(pp, sk, cred)
    assert test(pp, skp, pkp)
