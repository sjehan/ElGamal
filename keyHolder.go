package elgamalcrypto

import (
	"math/big"
)

/******************************************************************************************************
 *
 * Functions providing the keys from a table of keys stored by the key holder
 *
 ******************************************************************************************************/

// GiveKeyPoint returns the value (r_i × s_j)⋅g which will allow the databuyer, when combined
// with the value given by another key holder, to reconstruct the decryption key specific
// to a cell of the table concerned. This is independent of the fact that the encryption was done
// by hashing or in the form of a point on the curve.
func (keys PartTableKey) GiveKeyPoint(c coord) (pt CPoint) {
	return baseMult(new(big.Int).Mul(keys.R[c.i], keys.PrivPart[c.j]))
}

// GiveKeyCalculation is used by the key holder to provide the decryption key corresponding
// to a calculation whose coefficients (integers) are given by coeffs.
func (keys PartTableKey) GiveKeyCalculation(coeffs map[coord]*big.Int) (pt CPoint) {
	var c, sum = new(big.Int), new(big.Int)
	for k, v := range coeffs {
		c.Mul(keys.R[k.i], keys.PrivPart[k.j])
		sum.Add(sum, new(big.Int).Mul(c, v))
	}
	pt = baseMult(sum)
	return
}
