# -*- coding: utf-8 -*-

import hashlib
import hmac
import random
from Crypto.Util.number import bytes_to_long, long_to_bytes

__all__ = [
	'newVerifier',
	'primeID',
	'primeID_size',
	'Client',
	'Server',
	'Error',
	'NotSupported',
	'ImproperKeyValue',
	'AuthFailure'
]


saltlen = 16    # bytes
ablen = 256     # bits


class Error(Exception):
	'Exception base class for this module.'
class NotSupported(Error):
	'Given parameter is not supported.'
class ImproperKeyValue(Error):
	'Exception indicates that the given key is improper.'
class AuthFailure(Error):
	'Exception indicates authentication failure.'

def HNxorg(N,g):
	hN = hashlib.sha512( N ).digest()
	hg = hashlib.sha512( g ).digest()
	return ''.join( chr( ord(hN[i]) ^ ord(hg[i]) ) for i in range(0,len(hN)) )

def newVerifier(user, passphrase, bits=1024):
	return SRP(bits).newVerifier(user, passphrase) + (bits,)

def primeID(bits=1024):
	return SRP(bits).primeID()

primeID_size = hashlib.sha512().digest_size


# 1024, 1536, 2048, 3072, 4096, 6144 and 8192 bit 'N' and its generator.
# This table was copied from "TLSLite v0.3.8".

pflist = {
	1024 : (2L, 0xEEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3),
	1536 : (2L, 0x9DEF3CAFB939277AB1F12A8617A47BBBDBA51DF499AC4C80BEEEA9614B19CC4D5F4F5F556E27CBDE51C6A94BE4607A291558903BA0D0F84380B655BB9A22E8DCDF028A7CEC67F0D08134B1C8B97989149B609E0BE3BAB63D47548381DBC5B1FC764E3F4B53DD9DA1158BFD3E2B9C8CF56EDF019539349627DB2FD53D24B7C48665772E437D6C7F8CE442734AF7CCB7AE837C264AE3A9BEB87F8A2FE9B8B5292E5A021FFF5E91479E8CE7A28C2442C6F315180F93499A234DCF76E3FED135F9BB),
	2048 : (2L, 0xAC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73),
	3072 : (5L, 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF),
	4096 : (5L, 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF),
	6144 : (5L, 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF),
	8192 : (5L, 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF)
}


# Calculate kid and k first.

class SRP:
	# N: Modulo; A large safe prime (N = 2q+1, where q is prime)
	# g: A generator for modulo N
	# k: H(N, g)

	def __init__(self, bits=1024):
		try:
			(self.g, self.N) = pflist[bits]
		except KeyError:
			raise NotSupported, '%d bits not available' % bits
		n = self.N
		self.scale = 0
		while n > 0:
			self.scale += 1
			n >>= 8
		self.kid_ = self.SHA(self.pad(self.N), self.pad(self.g))
		self.k = self.__b2n(self.kid_)

	def newVerifier(self, user, passphrase):
		salt = ''.join([chr(random.randrange(0, 256)) for x in range(saltlen)])
		return (salt, self.pow(self.g, SRP.makeX(salt, user, passphrase)))

	def primeID(self):
		return self.kid_

	def makeU(self, A, B):
		return SRP.__b2n(SRP.SHA(self.pad(A), self.pad(B)))

	def pow(self, a, b):
		return pow(a, b, self.N)

	def pad(self, n):
		s = []
		for x in range(self.scale):
			s.insert(0, chr(n & 255))
			n >>= 8
		return ''.join(s)

	def __n2b(n):
		s = []
		while n > 0:
			s.insert(0, chr(n & 255))
			n >>= 8
		return ''.join(s)
	__n2b = staticmethod(__n2b)

	def __b2n(s):
		r = 0L
		for c in s:
			r <<= 8
			r += ord(c)
		return r
	__b2n = staticmethod(__b2n)

	def HNxorg(N,g):
		hN = hashlib.sha512( __b2n(N) ).digest()
		hg = hashlib.sha512( __b2n(g) ).digest()
		return ''.join( chr( ord(hN[i]) ^ ord(hg[i]) ) for i in range(0,len(hN)) )
	HNxorg = staticmethod(HNxorg)

	def SHA(*args):
		m = hashlib.sha512()
		for s in args:
			if type(s) == long:
				s = SRP.__n2b(s)
			m.update(s)
		return m.digest()
	SHA = staticmethod(SHA)

	def hmacSHA(B, A, s, I, g, N, K):
		h = hashlib.sha512()
		h.update( HNxorg(long_to_bytes(N), long_to_bytes(g)) )
		h.update( hashlib.sha512( I ).digest() )
		h.update( s )
		h.update( long_to_bytes(A) )
		h.update( long_to_bytes(B) )
		h.update( K )
		return h.digest()
	hmacSHA = staticmethod(hmacSHA)

	def hmacSHA2(A, M, K):
		h = hashlib.sha512()
		h.update( long_to_bytes(A) )
		h.update( M )
		h.update( K )
		return h.digest()
	hmacSHA2 = staticmethod(hmacSHA2)

	def makeX(salt, user, passphrase):
		return SRP.__b2n(
	SRP.SHA(salt, SRP.SHA(user, ':', passphrase)))
	makeX = staticmethod(makeX)

class Server(SRP):
	def __init__(self, user, salt, verifier, bits=3072):
		'''bits: 1024, 1536, 2048, 3072, 4096, 6144 or 8192'''
		SRP.__init__(self, bits)
		self.user = user
		self.salt = salt
		self.v = verifier
		while 1:
			self.b = random.randrange(0, 1L << ablen)
			self.B = (self.pow(self.g, self.b) + self.k * verifier) % self.N
			if self.B != 0:
				break

	def seed(self):
		return self.B

	def proof(self, A, clientProof):
		if not 0 < A < self.N:
			raise ImproperKeyValue

		u = self.makeU(A, self.B)
		S = pow((A * pow(self.v, u, self.N)) % self.N, self.b, self.N)
		self.K = SRP.SHA(S)
		self.M = SRP.hmacSHA(self.B, A, self.salt, self.user, self.g, self.N, self.K)
		if clientProof != self.M:
			raise AuthFailure, 'Client not authenticated.'
		return SRP.hmacSHA2(A, self.M, self.K)

	def key(self):
		return self.K

