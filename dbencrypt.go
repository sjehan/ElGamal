// The elgamalcrypto package contains all the functions needed to encrypt a database. It creates
// all the keys that will be sent to the two other key holders and contains decryption
// functions for testing and verification purposes.

package elgamalcrypto

import (
	"crypto/rand"
	"database/sql"
	"errors"
	"math/big"
)

/*
 * Functions used to encrypt a database
 *
 */

// EncryptDatabase will encrypt all the tables of a database
func EncryptDatabase(dbSource, dbDest *sql.DB, tableNames []string, commands map[string][]byte) (keysDB map[string]TableKeys) {
	keysDB = make(map[string]TableKeys)
	for _, name := range tableNames {
		keysDB[name] = EncryptTable(dbSource, dbDest, name, commands[name], rand.Reader)
	}
	return keysDB
}

// ExtractPart returns the partial key table used by one of the key holders
func (arr TableKeys) ExtractPart(num byte) (part PartTableKey, err error) {
	if (num != 1) && (num != 2) && (num != 3) {
		err = errors.New("Numéro de partie à extraire non valide.")
		return
	}

	part.keyHolder = num
	part.ti = arr.ti
	part.R = make(map[interface{}]*big.Int, len(arr.R))
	for k, v := range arr.R {
		part.R[k] = v
	}

	part.PrivPart = make(map[string]*big.Int)
	for k, v := range arr.Priv {
		part.PrivPart[k] = new(big.Int).SetBytes(v[num])
	}
	return
}

/*

// Find the data to send to the server
func SendDataToServer(indexData []byte) ([]byte) {
	return GetCypher2(indexData []byte)
}


// Function which calculates s1⋅c when a buyer ask for it
// with s1 being the dataseller part of the private key x
// and c being the first part of the cypher related to the data
func GiveBuyerKeyPart(indexData []byte) (C1x, C1y big.Int) {
	cx, cy := GetCypher1(indexData []byte)
	s1 := GetKeyPart(1, indexData []byte)
	C1x, C1y = (myCurve.Params()).ScalarMult(cx, cy, s1)
	return
}

*/
