package elgamalcrypto

import (
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"
)

// Decrypt is a simple decryption function of a message in the form of a cypher,
// knowing the private key
func (priv *PrivateKey) Decrypt(cypher Cypher) (msg []byte) {
	DC := cypher.C.multB(priv[0])
	DCHash := sha512.Sum512(append(DC.x.Bytes(), DC.y.Bytes()...))

	msg = make([]byte, len(cypher.Data))
	for i, v := range cypher.Data {
		msg[i] = v ^ DCHash[i%BytesNumber]
	}
	return
}

// calculateDecryptionKey will calculate the key to decrypt a value encoded
// in any way from the keys sent by the key holders
func calculateDecryptionKey(keyParts map[int]CPoint) (s CPoint) {
	// The lambda variables are the interpolation constants used in the case
	// of a degree 1 polynomial given by two points on its curve

	lambda1 := big.NewInt(3)
	lambda2 := big.NewInt(-3)
	lambda3 := big.NewInt(1)

	c1, ok1 := keyParts[1]
	c2, ok2 := keyParts[2]
	c3, ok3 := keyParts[3]

	switch {
	case ok1 && ok2:
		s = addC(c1.mult(lambda1), c2.mult(lambda2))
	case ok2 && ok3:
		s = addC(c2.mult(lambda2), c3.mult(lambda3))
	case ok3 && ok1:
		s = addC(c3.mult(lambda3), c1.mult(lambda1))
	}
	return
}

/*
// sumPointsCol will sum the data representing points on the curve along a column
func sumPointsCol(db *sql.DB, tabName, colName string, coeffsCol map[uint]*big.Int) (sum CPoint) {
	sum = pointZero
	var temp []byte
	var coeff *big.Int
	var exist bool
	colRows, err := db.Query(fmt.Sprintf("SELECT %s FROM %s;", tabName, colName))
	for i := uint(0); colRows.Next(); i++ {
		coeff, exist = coeffsCol[i]
		if exist {
			err = colRows.Scan(&temp)
			checkErr(err)
			sum = addC(sum, PointFromShort(temp).mult(coeff))
		}
	}
	return
}
*/

/*
// sumPoints will sum the data representing points on the curve in a table
func sumPoints(db *sql.DB, ti TableInfo, coeffs map[coord]*big.Int) (sum CPoint) {
	coeffsCols := make([](map[interface{}]*big.Int), ti.nCol)
	for j := uint(0); j < ti.nCol; j++ {
		coeffsCols[j] = make(map[interface{}]*big.Int)
	}

	for c, v := range coeffs {
		coeffsCols[c.j][c.i] = v
	}

	sum = pointZero
	for j := uint(0); j < ti.nCol; j++ {
		if (len(coeffsCols[j]) > 0) && (ti.commands[j] == 2) {
			sum = addC(sum, sumPointsCol(db, ti.name, ti.colNames[j], coeffsCols[j]))
		}
	}
	return
}
*/

// decryptFromPoint will decrypt a data encoded as a point, knowing the key s
// corresponding to it, which is the result of the interpolation between the
// partial keys.

func decryptFromPoint(p, s CPoint, colType string) []byte {
	q := p.subC(s)
	bytesNumber := uint64(8)
	switch colType {
	case "INTEGER", "INT", "INT4", "SERIAL", "SERIAL4", "SMALLINT", "INT2", "REAL", "FLOAT4":
		bytesNumber = 4
	}
	return kangaroo(q, bytesNumber).Bytes()
}

// decryptFromPoint will decrypt a data encoded with a hash function
func decryptFromHash(d []byte, s CPoint) (m []byte) {
	m = make([]byte, len(d))
	sHash := sha512.Sum512(append(s.x.Bytes(), s.y.Bytes()...))
	for k, v := range d {
		m[k] = v ^ sHash[k%BytesNumber]
	}
	return
}

/**********************************************************************************************
 *
 * Fonctions resolving the discrete logarithm problem
 *
 **********************************************************************************************/

// rhoPollard resolves the equation pt = x⋅g where x belongs to Z/NZ
// It is therefore not suitable when we are able to restrict the interval
// on which x is present.

func rhoPollard(pt CPoint) (pow *big.Int, err error) {
	// whichSet is a function that serves to operate the partition into three
	// subsets of approximately equal size that the rho algorithm of Pollard requires.

	whichSet := func(p CPoint, modulo *big.Int) (set *big.Int) {
		return new(big.Int).Mod(p.x, modulo)
	}

	fgh := func(x *CPoint, a, b *big.Int) {
		switch whichSet(*x, Big3).Uint64() {
		case 0:
			(*x) = addC(*x, pt)
			b.Mod(new(big.Int).Add(b, Big1), P)
		case 1:
			(*x) = (*x).doubleC()
			a.Mod(new(big.Int).Mul(a, Big2), P)
			b.Mod(new(big.Int).Mul(b, Big2), P)
		default:
			(*x) = addC(*x, G)
			a.Mod(new(big.Int).Add(a, Big1), P)
		}
	}

	var Xi, X2i = pointZero, pointZero
	var Ai, A2i = Big0, Big0
	var Bi, B2i = Big0, Big0
	var r1, r2 *big.Int

	for true {
		fgh(&Xi, Ai, Bi)
		fgh(&X2i, A2i, B2i)
		fgh(&X2i, A2i, B2i)

		if Xi.equalC(X2i) {
			r1.Sub(Bi, B2i)
			if r1.Cmp(Big0) == 0 {
				return Big0, errors.New("r1 zero value failure")
			}
			r1.ModInverse(r1, P)
			r2.Sub(A2i, Ai)
			pow.Mul(r1, r2)
			return
		}
	}
	return
}

// kangaroo is the implementation of the lambda method of Pollard, also known
// as kangaroo because it can be seen as the story of two kangaroos,
// one tamed and the other wild, the first trying to catch the second.
// The function solves the equation pt = x⋅g where x belongs to [0;max] with max < N

func kangaroo(pt CPoint, bytesNumber uint64) *big.Int {
	nRoutines := uint64(4)
	// N describes the length of the second string we are building
	N := uint64(1 << (bytesNumber * 4))
	// Smaj is the smallest majorant of S (set of integers) not belonging to S
	Smaj := new(big.Int).SetUint64(bytesNumber * 8)
	// firstpoint is the starting point of the first tamed routine.
	// The starting points of the other routines will be multiples of it

	firstPoint := new(big.Int).SetUint64(N * N / nRoutines)
	// T is the array that stores the arrival points of each of the tamed kangaroos launched
	T := make([]CPoint, nRoutines)
	// dTPlis is an array that stores the distances traveled by each of the wild kangaroos
	// to which we have added their starting point

	dTPlus := make([]*big.Int, nRoutines)

	cFound := make(chan *big.Int)
	cLim := make(chan bool, nRoutines)

	fmt.Printf("début kangaroo, N = %d\n", N)

	/* Pseudo-random function f : C → S with S a set of integers */
	s := func(q CPoint) *big.Int {
		i := new(big.Int).Mod(q.x, Smaj)
		return new(big.Int).Exp(Big2, i, nil)
	}

	isInT := func(w CPoint) (bool, int) {
		for i := uint64(0); i < nRoutines; i++ {
			if w.equalC(T[i]) {
				return true, int(i)
			}
		}
		return false, 0
	}

	// runningTamed is the routine used for the travel of the tamed kangaroos
	runningTamed := func(num uint64) {
		var si *big.Int
		var siG CPoint
		var dTame = big.NewInt(0)
		basePointBig := new(big.Int).Mul(firstPoint, big.NewInt(int64(num)))
		Tame := baseMult(basePointBig)
		for i := uint64(0); i < N; i++ {
			si = s(Tame)
			dTame.Add(dTame, si)
			siG = baseMult(si)
			Tame = addC(Tame, siG) // T_i+1 = T_i + si⋅G
		}
		T[num] = Tame
		dTPlus[num] = new(big.Int).Add(basePointBig, dTame)
		cLim <- true
	}

	pursueWild := true

	// runningWild is the routine used for the travel of the wild kangaroos
	runningWild := func(k uint64) {
		offset := uint64(k)
		bigOffset := new(big.Int)
		var Wild, siG CPoint
		var dWPlus, si *big.Int
		var found bool
		var num int
		for pursueWild {
			bigOffset.SetUint64(offset)
			Wild = addC(pt, baseMult(bigOffset))
			found, num = isInT(Wild)
			if found {
				cFound <- new(big.Int).Sub(dTPlus[num], bigOffset)
				return
			}
			si = s(Wild)
			dWPlus = new(big.Int).Add(si, bigOffset)
			siG = baseMult(si)

			for i := uint64(0); i < N; i++ {
				Wild = addC(Wild, siG) // W_i+1 = W_i + si⋅G
				found, num = isInT(Wild)
				if found {
					cFound <- new(big.Int).Sub(dTPlus[num], dWPlus)
					return
				}
				// si est désormais en réalité s_i+1
				si = s(Wild)
				dWPlus.Add(dWPlus, si)
				siG = baseMult(si)
			}
			offset += nRoutines
			fmt.Println("Wild not caught")
		}
	}

	for k := uint64(0); k < nRoutines; k++ {
		go runningTamed(k)
	}
	for k := uint64(0); k < nRoutines; k++ {
		_ = <-cLim
	}

	fmt.Println("tamed finished")

	for k := uint64(0); k < nRoutines; k++ {
		go runningWild(k)
	}
	pow := <-cFound
	pursueWild = false
	return pow
}

// loadL2mpa will load in memory or create the hashmap used for the baby step giant step algorithm.
func loadhL2(m uint64) (hL2 map[ShortPoint]uint64) {
	hL2 = make(map[ShortPoint]uint64)
	pt := pointZero
	for i := uint64(0); i < m; i++ {
		//pt = baseMult(big.NewInt(int64(i)))
		hL2[GetShortOf(pt)] = i
		//fmt.Printf("added %s : %d\n", pt.String(), i)
		pt = addC(pt, G)
	}
	fmt.Println("Load finished")
	return
}

// babyStepGiantStep allows to compute the discrete logarithm with a guaranteed complexity in the square root
// of the maximum of the considered interval. To simplify things, rather than giving the maximum of the interval
// as a parameter, we send the number of bytes on which the value to find is encoded
func babyStepGiantStep(pt0 CPoint, bytesNumber uint64) uint64 {
	// ms is the square root of the maximum of the considered interval
	m := uint64(1 << (bytesNumber * 4))
	fmt.Printf("m = %d\n", m)
	// mg is the point m⋅g
	mg := baseMult(new(big.Int).SetUint64(m))
	// L2 is the list [0⋅g; 1⋅g; 2⋅g; ... ; (m-1)⋅g] and hL2 is the hashmap associated
	var hL2 = loadhL2(m)

	nRoutines := byte(MAX_ROUTINES)
	cPow := make(chan uint64)
	pursue := true

	findPow := func(k byte) {
		var j uint64
		var found bool
		rmg := mg.multB([]byte{nRoutines})
		pt1 := pt0.subC(mg.multB([]byte{k}))
		for i := uint64(k); (i < m) && pursue; i += uint64(nRoutines) {

			/*
			* The following line tests the presence of the point pt1 obtained in the base map.
			* It has to be changed if we want to keep the precalculated base in line.
			 */

			if j, found = hL2[GetShortOf(pt1)]; found {
				fmt.Printf("found %d\n", i*m+j)
				cPow <- i*m + j
			}
			pt1 = pt1.subC(rmg)
		}
	}

	for k := byte(0); k < nRoutines; k++ {
		go findPow(k)
	}

	pow := <-cPow
	pursue = false

	return pow
}
