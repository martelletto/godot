package secp256k1

// This is the order of the prime field over which secp256k1 is defined:
// 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1.
var FieldOrder = new(big.Int).SetBytes([]byte {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
})

// The order of the base point G.
var BaseOrder = new(big.Int).SetBytes([]byte {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
	0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
	0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
})

// createKey() returns a new private key d in [1, n-1] where n is the
// order of the base point G.
func createKey() *big.Int {
	for {
		d := rand.Int(baseOrder) // returns d in [0, baseOrder)
		if d.Cmp(big.NewInt(0)) == 1 {
			return d
		}
	}
}
