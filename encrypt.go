package elgamalcrypto

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"database/sql"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"

	"github.com/codahale/sss"
)

/*
 * This file is at the heart of the ElGamal algorithm.
 * It will manage the operations that allow the encryption and decryption of messages.
 */

// rowToEncrypt is an internal type used by the library to parallelize the encryption of a row
// of the table

type rowToEncrypt struct {
	val []interface{}
	r   *big.Int
}

/**********************************************************************************************************
 *
 * Functions to generate keys on elliptic curve
 *
 *********************************************************************************************************/

// CreateKeys generates a key pair using the corresponding function of the elliptic library
func CreateKeys(random io.Reader) (pub PublicKey, priv0 []byte, err error) {
	var x, y *big.Int
	priv0, x, y, err = elliptic.GenerateKey(myCurve, random)
	if err != nil {
		return
	}

	pub = PublicKey{
		Curve: myCurve,
		Y:     CPoint{x, y},
	}
	return
}

// SetKeys generates a key pair used by the ElGamal algorithm
func SetKeys(random io.Reader) (pub PublicKey, priv PrivateKey, verifiers map[byte]CPoint) {

	pub, priv0, err := CreateKeys(random)
	checkErr(err)

	keyParts, err := sss.Split(3, 2, priv0)
	checkErr(err)
	priv = [4][]byte{priv0, keyParts[1], keyParts[2], keyParts[3]}

	verifiers = make(map[byte]CPoint)
	for i, si := range keyParts {
		verifiers[i] = baseMultB(si)
	}
	return
}

// SetTableKeys generates all the keys to encrypt a table of known dimensions
// The variable returned RforEnc is made especially to allow the encryption process which is simpler
// if the rows are indexed by their number rather than by their primary key.
func SetTableKeys(db *sql.DB, ti TableInfo, random io.Reader) (pubs map[string]PublicKey, keys TableKeys, RforEnc []*big.Int) {
	keys.ti = ti
	var r *big.Int
	var val interface{}
	var err error
	RforEnc = make([]*big.Int, ti.nRows)
	primColumn, err := db.Query(fmt.Sprintf("SELECT %s FROM %s;", ti.colNames[PRIM_COL_NUMBER], ti.name))
	checkErr(err)
	keys.R = make(map[interface{}]*big.Int)
	for i := uint64(0); i < ti.nRows; i++ {
		primColumn.Next()
		err = primColumn.Scan(&val)
		checkErr(err)

		r, err = rand.Int(random, N)
		checkErr(err)

		if r.Cmp(Big0) == 0 {
			r = Big2
		}
		RforEnc[i] = r
		keys.R[val] = r
	}

	pubs = make(map[string]PublicKey)
	keys.Priv = make(map[string]PrivateKey)
	var colN string
	for j := uint(0); j < ti.nCol; j++ {
		if ti.commands[j] != 0 {
			colN = ti.colNames[j]
			pubs[colN], keys.Priv[colN], _ = SetKeys(random)
		}
	}
	return
}

/*********************************************************************************************************
 *
 * Functions dedicated to the encryption of a data or a column
 *
 *********************************************************************************************************/

// Encrypt a simple message under the form of a byte array with a c created only for this message.
// The disadvantage is that, for messages longer than 512 bits, several different bytes will be
// encoded using an XOR with the same byte of the checksum obtained by the algorithm.
// It is therefore a basic function used to test one of the two types of encryption.
func (pub *PublicKey) basicEncryptHash(msg []byte, random io.Reader) (cypher Cypher) {
	r, err := rand.Int(random, N)
	checkErr(err)
	if r.Cmp(Big0) == 0 {
		r = Big2
	}
	C := baseMult(r) // C = rG
	s := pub.Y.mult(r)
	sHash := sha512.Sum512(append(s.x.Bytes(), s.y.Bytes()...))
	d := make([]byte, len(msg))
	for i, v := range msg {
		d[i] = v ^ sHash[i%BytesNumber]
	}
	cypher = Cypher{C, d}
	return
}

// EncryptPoint manages the encryption of a simple message under the form of a point on the curve
func (pub *PublicKey) basicEncryptPoint(msg []byte, random io.Reader) CypherPoint {

	r, err := rand.Int(random, N)
	checkErr(err)

	if r.Cmp(Big0) == 0 {
		r = Big2
	}
	C := baseMult(r) // C = rG
	s := pub.Y.mult(r)
	/* message encryption */
	d := addC(baseMultB(msg), s)
	return CypherPoint{C, GetShortOf(d)}
}

// encryptHash manages the encryption of the cells of a column in the case with hash function
func encryptHash(cE chan interface{}, cI chan string, nRows uint64, pubY CPoint, RforEnc []*big.Int) {
	var val interface{}
	var s CPoint
	var d, m []byte
	var sHash [sha512.Size]byte
	for i := uint64(0); i < nRows; i++ {
		s = pubY.mult(RforEnc[i])
		sHash = sha512.Sum512(append(s.x.Bytes(), s.y.Bytes()...))
		val = <-cE
		m = GetBytes(val)

		d = make([]byte, len(m))
		for k, v := range m {
			d[k] = v ^ sHash[k%BytesNumber]
		}
		cI <- fmt.Sprintf("decode('%x', 'hex')", d)
	}
}

// encryptPoint deals with the encryption of the cells of a column in the case with possible calculations
func encryptPoint(cE chan interface{}, cI chan string, nRows uint64, pubY CPoint, RforEnc []*big.Int) {
	/*
	 * s = r⋅Y = Xr⋅g
	 * d = m⋅g + r⋅Y = (m + Xr)⋅g
	 */
	var val interface{}
	var s CPoint
	var d ShortPoint
	var m []byte
	for i := uint64(0); i < nRows; i++ {
		s = pubY.mult(RforEnc[i])
		val = <-cE
		m = GetBytes(val)

		d = GetShortOf(addC(baseMultB(m), s))
		cI <- fmt.Sprintf("decode('%x', 'hex')", d)
	}
}

// transferBytea
func transferBytea(cE chan interface{}, cI chan string, nRows uint64) {
	var val interface{}
	var m []byte
	for i := uint64(0); i < nRows; i++ {
		val = <-cE
		m = GetBytes(val)
		cI <- fmt.Sprintf("decode('%x', 'hex')", m)
	}
	return
}

// transferInt64
func transferInt64(cE chan interface{}, cI chan string, nRows uint64) {
	var val interface{}
	for i := uint64(0); i < nRows; i++ {
		val = <-cE
		cI <- strconv.FormatInt(val.(int64), 10)
	}
	return
}

// transferInt32
func transferInt32(cE chan interface{}, cI chan string, nRows uint64) {
	var val interface{}
	for i := uint64(0); i < nRows; i++ {
		val = <-cE
		cI <- strconv.Itoa(val.(int))
	}
	return
}

// transferBool
func transferBool(cE chan interface{}, cI chan string, nRows uint64) {
	var val interface{}
	for i := uint64(0); i < nRows; i++ {
		val = <-cE
		cI <- strings.ToUpper(strconv.FormatBool(val.(bool)))
	}
	return
}

// transferFloat32
func transferFloat32(cE chan interface{}, cI chan string, nRows uint64) {
	var val interface{}
	for i := uint64(0); i < nRows; i++ {
		val = <-cE
		cI <- strconv.FormatFloat(val.(float64), 'f', -1, 32)
	}
	return
}

// transferFloat64
func transferFloat64(cE chan interface{}, cI chan string, nRows uint64) {
	var val interface{}
	for i := uint64(0); i < nRows; i++ {
		val = <-cE
		cI <- strconv.FormatFloat(val.(float64), 'f', -1, 64)
	}
	return
}

// transferJson
func transferJson(cE chan interface{}, cI chan string, nRows uint64) {
	var val interface{}
	for i := uint64(0); i < nRows; i++ {
		val = <-cE
		cI <- val.(string)
	}
	return
}

// transferString
func transferString(cE chan interface{}, cI chan string, nRows uint64) {
	var val interface{}
	for i := uint64(0); i < nRows; i++ {
		val = <-cE
		cI <- fmt.Sprintf("'%s'", val.(string))
	}
	return
}

func transferNumeric(cE chan interface{}, cI chan string, nRows uint64, numType string) {
	var val interface{}
	//paramStr := numType[8 : len(numType) - 1]
	for i := uint64(0); i < nRows; i++ {
		val = <-cE
		// TODO: improve to take into account the data on the precision
		cI <- strconv.FormatFloat(val.(float64), 'f', -1, 64)
	}
	return
}

/*********************************************************************************************************
 *
 * Intermediary functions for the encryption of a table
 *
 *********************************************************************************************************/

// rowInsertion is the routine that handles the insertion of a row into the new database
func rowInsertion(cIns []chan string, cEnd chan bool, nRows uint64, nColumns uint, db *sql.DB, newName string) {
	var buffer bytes.Buffer
	for i := uint64(0); i < nRows; i++ {
		buffer.Reset()
		for j := uint(0); j < nColumns; j++ {
			if j > 0 {
				buffer.WriteString(", ")
			}
			buffer.WriteString(<-cIns[j])
		}
		_, err := db.Exec(fmt.Sprintf("INSERT INTO %s VALUES (%s);", newName, buffer.String()))
		checkErr(err)
	}
	cEnd <- true
}

// EncryptTable deals with the encryption of the entire SQL table
// The variable commands contains the list of instructions for each column with:
// commands [j] == 0 -> we do not encrypt this column
// commands [j] == 1 -> we encrypt this column without possible calculation, i.e. with hash function
// commands [j] == 2 -> we encrypt this column with possible calculation, i.e. with d = m⋅g and use
//  	of the Pollard algorithm
func EncryptTable(dbInit, dbFinal *sql.DB, name string, commands []byte, random io.Reader) (keys TableKeys) {
	ti := tableInfoFromDB(dbInit, name, commands...)
	var err error

	/* We create the destination table */
	newName := fmt.Sprintf("%s_encrypted", name)
	// The line below ensures that the arrival table does not already exist, but is a bit dangerous
	_, err = dbFinal.Exec(fmt.Sprintf("DROP TABLE %s;", newName))
	checkErr(err)
	_, err = dbFinal.Exec(fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (%s);", newName, getColsString(ti)))
	checkErr(err)

	// We get the columns of the table
	columns := make([]*sql.Rows, ti.nCol)
	for j := uint(0); j < ti.nCol; j++ {
		columns[j], err = dbInit.Query(fmt.Sprintf("SELECT %s FROM %s;", ti.colNames[j], name))
		checkErr(err)
	}

	/* We create the table of keys used for the encryption */
	pubs, keys, RforEnc := SetTableKeys(dbInit, ti, random)

	/* We declare all the variables and launch the encryption and insertion routines */
	lTail := 2
	// cEnd is used to keep the main routine running until the last insertion is done
	cEnd := make(chan bool)
	// cEnc contains the channels that go from the main routine to the encryption routines
	cEnc := make([]chan interface{}, ti.nCol)
	// cIns contains the channels that go from the encryption routines to the insertion routine
	cIns := make([]chan string, ti.nCol)
	for j := uint(0); j < ti.nCol; j++ {
		cEnc[j] = make(chan interface{}, lTail)
		cIns[j] = make(chan string, lTail)
		checkErr(err)
		switch commands[j] {
		case 0:
			// If we don't encrypt the data then we try to determine its type to be able to
			// reinsert it in the new table
			switch ti.colTypes[j] {
			case "BIGINT", "INT8", "BIGSERIAL", "SERIAL8":
				go transferInt64(cEnc[j], cIns[j], ti.nRows)
			case "INTEGER", "INT", "INT4", "SERIAL", "SERIAL4", "SMALLINT", "INT2":
				go transferInt32(cEnc[j], cIns[j], ti.nRows)
			case "BYTEA", "VARBIT":
				go transferBytea(cEnc[j], cIns[j], ti.nRows)
			case "BOOLEAN", "BOOL":
				go transferBool(cEnc[j], cIns[j], ti.nRows)
			case "DOUBLE PRECISION", "FLOAT8":
				go transferFloat64(cEnc[j], cIns[j], ti.nRows)
			case "REAL", "FLOAT4":
				go transferFloat32(cEnc[j], cIns[j], ti.nRows)
			case "TEXT":
				go transferString(cEnc[j], cIns[j], ti.nRows)
			case "JSON":
				go transferJson(cEnc[j], cIns[j], ti.nRows)
			default:
				if strings.Contains(ti.colTypes[j], "CHAR") {
					go transferString(cEnc[j], cIns[j], ti.nRows)
				} else if strings.Contains(ti.colTypes[j], "NUMERIC") || strings.Contains(ti.colTypes[j], "DECIMAL") {
					go transferNumeric(cEnc[j], cIns[j], ti.nRows, ti.colTypes[j])
				} else {
					go transferBytea(cEnc[j], cIns[j], ti.nRows)
				}
			}
		case 1:
			go encryptHash(cEnc[j], cIns[j], ti.nRows, pubs[ti.colNames[j]].Y, RforEnc)
		case 2:
			go encryptPoint(cEnc[j], cIns[j], ti.nRows, pubs[ti.colNames[j]].Y, RforEnc)
		default:
			go encryptHash(cEnc[j], cIns[j], ti.nRows, pubs[ti.colNames[j]].Y, RforEnc)
		}
	}
	go rowInsertion(cIns, cEnd, ti.nRows, ti.nCol, dbFinal, newName)
	var val interface{}

	for i := uint64(0); i < ti.nRows; i++ {
		for j := uint(0); j < ti.nCol; j++ {
			columns[j].Next()
			err = columns[j].Scan(&val)
			checkErr(err)
			cEnc[j] <- val
		}
	}
	<-cEnd
	return
}
