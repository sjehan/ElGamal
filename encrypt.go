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
	/* We generate the El Gamal private and public keys */
	pub, priv0, err := CreateKeys(random)
	checkErr(err)

	/* We use the Shamir Secret Sharing split to get the three values to distribute */
	keyParts, err := sss.Split(3, 2, priv0)
	checkErr(err)
	priv = [4][]byte{priv0, keyParts[1], keyParts[2], keyParts[3]}

	/* We generate the verification data */
	verifiers = make(map[byte]CPoint)
	for i, si := range keyParts {
		verifiers[i] = baseMultB(si)
	}
	return
}

// SetTableKeys génère toutes les clés pour encrypter une table de dimensions connues
// La variabme retournée RforEnc est faite spécialement pour permettre le processus de cryptage qui est plus simple
// si les lignes sont indexées par leur numéro plutôt que par leur clé primaire.
func SetTableKeys(db *sql.DB, ti TableInfo, random io.Reader) (pubs map[string]PublicKey, keys TableKeys, RforEnc []*big.Int) {
	keys.ti = ti
	/* On génère les clés secondaires */
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
		/* Au cas où l'on tomberait sur r = 0 */
		if r.Cmp(Big0) == 0 {
			r = Big2
		}
		RforEnc[i] = r
		keys.R[val] = r
	}

	/* On génère les clés privées/publiques principales */
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
 * Fonctions dédiées au cryptage d'une donnée ou d'une colonne
 *
 *********************************************************************************************************/

// Encode un message simple sous forme de tableau de bytes avec un c créé uniquement pour ce message.
// L'inconvénient est que, pour les messages de plus de 512 bits, plusieurs bytes différents vont
// être encodés en utilisant un XOR avec le même byte de la checksum obtenue par l'algorithme.
// C'est donc une fonction basique utilisée pour tester un des deux types de cryptage.
func (pub *PublicKey) basicEncryptHash(msg []byte, random io.Reader) (cypher Cypher) {
	/* Données pour l'encodage */
	r, err := rand.Int(random, N)
	checkErr(err)
	/* Au cas où l'on tomberait sur r = 0 */
	if r.Cmp(Big0) == 0 {
		r = Big2
	}
	/* On crée les variables utiles */
	C := baseMult(r) // C = rG
	s := pub.Y.mult(r)
	sHash := sha512.Sum512(append(s.x.Bytes(), s.y.Bytes()...))
	/* On réalise le cryptage du message */
	d := make([]byte, len(msg))
	for i, v := range msg {
		d[i] = v ^ sHash[i%BytesNumber]
	}
	cypher = Cypher{C, d}
	return
}

// EncryptPoint fait de l'encodage simple sous forme de point de la courbe
func (pub *PublicKey) basicEncryptPoint(msg []byte, random io.Reader) CypherPoint {
	/* Données pour l'encodage */
	r, err := rand.Int(random, N)
	checkErr(err)
	/* Au cas où l'on tomberait sur r = 0 */
	if r.Cmp(Big0) == 0 {
		r = Big2
	}
	/* On crée les variables utiles */
	C := baseMult(r) // C = rG
	s := pub.Y.mult(r)
	/* On réalise le cryptage du message */
	d := addC(baseMultB(msg), s)
	return CypherPoint{C, GetShortOf(d)}
}

// encryptHash réalise l'encryption des cases d'une colonne dans le cas avec fonction de hachage
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

// encryptPoint réalise l'encryption des cases d'une colonne dans le cas avec calculs possibles
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
		// TODO : ligne suivante non correctes
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
		// TODO : améliorer pour tenir compte des données sur la précision
		cI <- strconv.FormatFloat(val.(float64), 'f', -1, 64)
	}
	return
}

/*********************************************************************************************************
 *
 * Fonctions intermédiaires pour le cryptage d'une table
 *
 *********************************************************************************************************/

// rowInsertion est la routine qui gère l'insertion d'une ligne dans la nouvelle base de donnée
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

// EncryptTable gère le cryptage de l'ensemble d'une table SQL
// La variable commands contient la liste des instructions pour chaque colonne avec :
// commands[j] == 0 -> on n'encrypte pas cette colonne
// commands[j] == 1 -> on crypte cette colonne sans calcul possible, i.e. avec fonction de hachage
// commands[j] == 2 -> on crypte cette colonne avec calcul possible, i.e. avec d = m⋅g et utilisation
//  	de l'algorithme de Pollard
func EncryptTable(dbInit, dbFinal *sql.DB, name string, commands []byte, random io.Reader) (keys TableKeys) {
	ti := tableInfoFromDB(dbInit, name, commands...)
	var err error

	/* On crée la table d'arrivée */
	newName := fmt.Sprintf("%s_encrypted", name)
	// La ligne suivante s'assure que la table d'arrivée n'existe pas déjà, mais est un peu dangereuse
	_, err = dbFinal.Exec(fmt.Sprintf("DROP TABLE %s;", newName))
	checkErr(err)
	_, err = dbFinal.Exec(fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (%s);", newName, getColsString(ti)))
	checkErr(err)

	// On obtient les colonnes de la table
	columns := make([]*sql.Rows, ti.nCol)
	for j := uint(0); j < ti.nCol; j++ {
		columns[j], err = dbInit.Query(fmt.Sprintf("SELECT %s FROM %s;", ti.colNames[j], name))
		checkErr(err)
	}

	/* On crée le tableau des clés utilisées pour le cryptage */
	pubs, keys, RforEnc := SetTableKeys(dbInit, ti, random)

	/* On déclare toutes les variables utiles et on lance les routines de cryptage et d'insertion */
	lTail := 2
	// cEnd sert à maintenir la routine principale en route le temps que la dernière insertion soit faite
	cEnd := make(chan bool)
	// cEnc contient les canaux qui vont de la routine principale aux routines de cryptage
	cEnc := make([]chan interface{}, ti.nCol)
	// cIns contient les canaux qui vont des routines de cryptage à la routine d'insertion
	cIns := make([]chan string, ti.nCol)
	for j := uint(0); j < ti.nCol; j++ {
		cEnc[j] = make(chan interface{}, lTail)
		cIns[j] = make(chan string, lTail)
		checkErr(err)
		switch commands[j] {
		case 0:
			// Si on ne crypte pas la donnée alors on essaie de déterminer son type pour pouvoir
			// la réinsérer à l'identique dans la nouvelle table
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

	/* On boucle sur les lignes pour toutes les crypter ou pas */
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
