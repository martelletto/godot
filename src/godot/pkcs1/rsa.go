package pkcs1

import (
	"math/big"
)

// As per https://www.ietf.org/rfc/rfc3447.txt, A.1.2
type RSAPrivateKey struct {
	Version		*big.Int
	Modulus		*big.Int
	PublicExponent	*big.Int
	PrivateExponent	*big.Int
	Prime1		*big.Int
	Prime2		*big.Int
	Exponent1	*big.Int
	Exponent2	*big.Int
	Coefficient	*big.Int
}

// As per https://www.ietf.org/rfc/rfc3447.txt, A.1.1
type RSAPublicKey struct {
	Modulus		*big.Int
	PublicExponent	*big.Int
}
