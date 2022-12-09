package elgamalcrypto

import (
	"math/big"
)

/******************************************************************************************************
 *
 * Fonctions fournissant les clés à partir d'un tableau de clés stocké par le key holder
 *
 ******************************************************************************************************/

// GiveKeyPoint renvoie la valeur (r_i × s_j)⋅g qui permettra au databuyer, en la combinant
// avec la valeur donnée par un autre des key holders, de reconstituer la clé de décryption spécifique
// à une case de la table concernée. Ceci est indépendant du fait que le cryptage ait été réalisé
// par hachage ou sous forme de point de la courbe.
func (keys PartTableKey) GiveKeyPoint(c coord) (pt CPoint) {
	return baseMult(new(big.Int).Mul(keys.R[c.i], keys.PrivPart[c.j]))
}

// GiveKeyCalculation est utilisée en tant que key holder pour fournir la clé de décryptage correspondant
// à un calcul dont les coefficients (entiers) sont donnés par coeffs.
func (keys PartTableKey) GiveKeyCalculation(coeffs map[coord]*big.Int) (pt CPoint) {
	var c, sum = new(big.Int), new(big.Int)
	for k, v := range coeffs {
		c.Mul(keys.R[k.i], keys.PrivPart[k.j])
		sum.Add(sum, new(big.Int).Mul(c, v))
	}
	pt = baseMult(sum)
	return
}
