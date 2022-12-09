package elgamalcrypto

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha512"
	"database/sql"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
)

/*
 *
 * Definition of the types used
 *
 */

// CPoint, for Curve Point, represents a point on an elliptic curve in (x,y) coordinates
type CPoint struct {
	x, y *big.Int
}

// shortPoint is the type of the representation of the curve points in short form
type ShortPoint [SHORT_POINT_LENGTH]byte

// Cypher is the type of cypher used for encryption on elliptic curves.
// It corresponds to a classical implementation of ElGamal but is only used here for
// testing purposes and not for encrypting tables.
type Cypher struct {
	C    CPoint
	Data []byte
}

// CypherPoint is the type of cypher in the case where the message is encoded as a point on the curve.
type CypherPoint struct {
	C    CPoint
	Data ShortPoint
}

// PublicKey is the type of public keys used for encryption on elliptic curves
type PublicKey struct {
	elliptic.Curve
	Y CPoint
}

// PrivateKey can be seen as a first degree polynomial whose four values are known.
// The first one, at zero, is the one used for encryption, and the three others
// at 1, 2 and 3 allow to retrieve the first one by interpolating two of them.
type PrivateKey [4][]byte

// TableInfo allows to keep all the useful information on a given SQL table
type TableInfo struct {
	name     string
	nRows    uint64
	nCol     uint
	colNames []string
	colTypes []string
	commands []byte
}

// ArrayKeys contains all the keys allowing the decryption of a table.
// The set of private keys is kept in a map since there is not necessarily a private key
// for each column, we do not encrypt all of them.
type TableKeys struct {
	ti   TableInfo
	R    map[interface{}]*big.Int
	Priv map[string]PrivateKey
}

// PartArrayKey describes the array of keys held by one of the key holders with respect
// to a database, i.e. with only a part of the private keys, given
// by Shamir's Secret Sharing. In practice, we keep here the elements
// s_i given by SSS in the form of big.Int. This facilitates the execution of calculations.
type PartTableKey struct {
	ti        TableInfo
	keyHolder byte
	R         map[interface{}]*big.Int
	PrivPart  map[string]*big.Int // les s_j,k
}

// coord is a type that corresponds to coordinates in a SQL table in their most convenient form.
// i corresponds to the primary key, which will identify the line, and j is the name of the column,
// which can be more convenient to manipulate than its number in the case of queries.
// This type is not very used in my code and I do not know if it will remain relevant.
type coord struct {
	i interface{}
	j string
}

/*********************************************************************************************
 *
 * Definition of the variables and constants (global to the package)
 *
 *********************************************************************************************/

const (
	DATAPROVIDER = 1
	APPOWNER     = 2
	ADMIN        = 3
)

// This value describes the length in bytes of the representation of a point of the curve in short form
// It must be changed if the curve is modified.
const SHORT_POINT_LENGTH = 29

// Indicates that the column that will serve as primary key is the first
const PRIM_COL_NUMBER = 0

// Maximum number of routines that we launch on the algorithms or the level of parallelization is variable
const MAX_ROUTINES = 4

// Number of bits of each encoded message (imposed by the hash algorithm)
const BytesNumber = sha512.Size // = 64

// Elliptic curve used
var myCurve = elliptic.P224()
var P = myCurve.Params().P
var N = myCurve.Params().N
var G = CPoint{myCurve.Params().Gx, myCurve.Params().Gy}
var pointZero = G.subC(G)
var Big0 = big.NewInt(0)
var Big1 = big.NewInt(1)
var Big2 = big.NewInt(2)
var Big3 = big.NewInt(3)

/*********************************************************************************************
 *
 * Functions for checking
 *
 *********************************************************************************************/

// checkErr is a function for error management,
// it panics if an error is detected
func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

// checkPoint checks the validity of a point of type CPoint
// and panics if it is not on the curve
func checkPoint(p CPoint) {
	if !(myCurve.Params()).IsOnCurve(p.x, p.y) {
		panic(errors.New("A point is not on the curve."))
	}
}

/*********************************************************************************************
 *
 * Operators on points of a curve
 *
 *********************************************************************************************/

func (pt CPoint) String() string {
	return fmt.Sprintf("(%x, %x)", pt.x, pt.y)
}

// baseMult is an intermediate to simplify the writing and avoid
// passing through ScalarBaseMult of elliptic, with a scalar in input
// in the form of * big.Int
func baseMult(a *big.Int) (r CPoint) {
	r.x, r.y = (myCurve.Params()).ScalarBaseMult(a.Bytes())
	return
}

// baseMult is an intermediate to simplify the writing and avoid
// passing through ScalarBaseMult of elliptic, with a scalar in input
// in the form of [] byte
func baseMultB(a []byte) (r CPoint) {
	r.x, r.y = (myCurve.Params()).ScalarBaseMult(a)
	return
}

// mult is an intermediate to simplify the writing and avoid
// passing through ScalarBaseMult of elliptic, with a scalar in input
// in the form of * big.Int
func (p CPoint) mult(a *big.Int) (r CPoint) {
	r.x, r.y = (myCurve.Params()).ScalarMult(p.x, p.y, a.Bytes())
	return
}

// mult is an intermediate to simplify the writing and avoid
// passing through ScalarBaseMult of elliptic, with a scalar in input
// in the form of [] byte
func (p CPoint) multB(a []byte) (r CPoint) {
	r.x, r.y = (myCurve.Params()).ScalarMult(p.x, p.y, a)
	return
}

// addC is an intermediate to simplify the writing and avoid
// passing through Add of elliptic
func addC(p, q CPoint) (r CPoint) {
	r.x, r.y = (myCurve.Params()).Add(p.x, p.y, q.x, q.y)
	return
}

// negC gives the opposite of a point on an elliptic curve
func (p CPoint) negC() (r CPoint) {
	r.x, r.y = p.x, new(big.Int).Neg(p.y)
	return
}

// sub is an intermediate to simplify the writing and avoid
// passing through Add of elliptic
func (p CPoint) subC(q CPoint) CPoint {
	return addC(p, q.negC())
}

// equal is a method on points of an elliptic curve to
// check their equality
func (this CPoint) equalC(p CPoint) bool {
	return (this.x.Cmp(p.x) == 0) && (this.y.Cmp(p.y) == 0)
}

// double is an intermediate to simplify the writing and avoid
// passing through Double of elliptic
func (p CPoint) doubleC() (r CPoint) {
	r.x, r.y = (myCurve.Params()).Double(p.x, p.y)
	return
}

/***********************************************************************************************
 *
 * Functions for the representation of points on the curve
 * the abscissa x and the sign of y are sufficient to know the point.
 *
 * The adopted form is the following concatenation:
 *  	short(p) = [f(y), x]
 * where f is a function of Z/pZ to {0,1} such that
 *		| 0 if y < p/2
 * f(y) = |
 *		| 1 if y >= p/2
 * Indeed, for a given x we find at most two points whose ordinates are
 * y and (p - y), because they have the same square modulo p.
 *
 *
 ***********************************************************************************************/

// GetShortOf returns the minimal representation of a point of an elliptic curve
func GetShortOf(p CPoint) (sp ShortPoint) {
	var middle = new(big.Int).Div(P, Big2)
	if p.y.Cmp(middle) >= 0 {
		sp[0] = 1
	} else {
		sp[0] = 0
	}
	temp := p.x.Bytes()
	lx := len(temp)
	for i := 1; i <= lx; i++ {
		sp[SHORT_POINT_LENGTH-i] = temp[lx-i]
	}
	return
}

// YFromX gives the positive ordinate of the point of the curve corresponding to the abscissa x
// It returns an error if this point does not exist.
// We recall that the curve formula is y^2 = x^3 - 3*x + b
// where b is specific to the curve used.
func YFromX(x *big.Int) (y *big.Int, err error) {
	x3 := new(big.Int).Exp(x, Big3, P)
	threeX := new(big.Int).Mul(x, Big3)

	y = new(big.Int).Sub(x3, threeX)
	y.Add(y, myCurve.Params().B)
	y.Mod(y, P)

	ok := y.ModSqrt(y, P)
	if ok == nil {
		err = errors.New("L'abscisse x ne correspond pas à un point de la courbe.")
	}
	return
}

// PonitFromShort returns the representation in coordinates of types (x,y) of a point
// from its reduced representation.
func PointFromShort(sp ShortPoint) (p CPoint) {
	var err error
	p.x = new(big.Int).SetBytes(sp[1:SHORT_POINT_LENGTH])
	p.y, err = YFromX(p.x)
	checkErr(err)
	var middle = new(big.Int).Div(P, Big2)
	if (p.y.Cmp(middle) < 0) && (sp[0] == 1) {
		p.y.Sub(P, p.y)
	} else if (p.y.Cmp(middle) >= 0) && (sp[0] == 0) {
		p.y.Sub(P, p.y)
	}
	return
}

// PointFromBytes is the equivalent of PointFromShort but taking bytes as input
func PointFromBytes(sp []byte) (p CPoint) {
	var err error
	p.x = new(big.Int).SetBytes(sp[1:SHORT_POINT_LENGTH])
	p.y, err = YFromX(p.x)
	checkErr(err)
	var middle = new(big.Int).Div(P, Big2)
	if (p.y.Cmp(middle) < 0) && (sp[0] == 1) {
		p.y.Sub(P, p.y)
	} else if (p.y.Cmp(middle) >= 0) && (sp[0] == 0) {
		p.y.Sub(P, p.y)
	}
	return
}

/*********************************************************************************************
 *
 * Functions for SQL tables
 *
 *********************************************************************************************/

func tableInfoFromDB(db *sql.DB, name string, comm ...byte) (ti TableInfo) {
	ti.name = name
	/* We get the dimensions of the table and the names of the columns */
	oneRow, err := db.Query(fmt.Sprintf("SELECT * FROM %s LIMIT 1;", name))
	checkErr(err)
	ti.colNames, _ = oneRow.Columns()
	ti.nCol = uint(len(ti.colNames))
	err = db.QueryRow(fmt.Sprintf("SELECT COUNT (*) FROM %s;", name)).Scan(&ti.nRows)
	checkErr(err)

	/* We get the data types in the columns */
	ti.colTypes = make([]string, ti.nCol)
	rowsColTypes, err := db.Query(fmt.Sprintf("SELECT data_type FROM information_schema.columns WHERE table_name = '%s';", name))
	checkErr(err)
	for j := 0; rowsColTypes.Next(); j++ {
		err = rowsColTypes.Scan(&ti.colTypes[j])
		ti.colTypes[j] = strings.ToUpper(ti.colTypes[j])
		checkErr(err)
	}

	if (ti.nCol > 0) && (uint(len(comm)) != ti.nCol) {
		ti.commands = make([]byte, ti.nCol)

		// If no instructions then we encrypt everything without calculation except the first column which
		// is supposed to be the primary key column

		ti.commands[0] = 0
		for j := uint(0); j < ti.nCol; j++ {
			ti.commands[j] = 1
		}
	} else {
		ti.commands = comm
	}
	return
}

// getCols returns the list of columns with names and types for the construction of the new table
func getColsString(ti TableInfo) string {
	// We use a buffer, which is more efficient for concatenating strings than the use of the + operator between string variables
	var buffer bytes.Buffer
	for j := uint(0); j < ti.nCol; j++ {
		if j > 0 {
			buffer.WriteString(", ")
		}
		buffer.WriteString(ti.colNames[j])
		buffer.WriteString(" ")
		if ti.commands[j] == 0 {
			buffer.WriteString(ti.colTypes[j])
		} else {
			buffer.WriteString("BYTEA DEFAULT NULL")
		}
	}
	return buffer.String()
}

/*********************************************************************************************
 *
 * Conversion functions
 *
 *********************************************************************************************/

func BytesFromFloat64(float float64) []byte {
	bits := math.Float64bits(float)
	bytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(bytes, bits)
	return bytes
}

func Float64frombytes(bytes []byte) float64 {
	bits := binary.LittleEndian.Uint64(bytes)
	float := math.Float64frombits(bits)
	return float
}

func BytesFromFloat32(float float32) []byte {
	bits := math.Float32bits(float)
	bytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(bytes, bits)
	return bytes
}

func Float32frombytes(bytes []byte) float32 {
	bits := binary.LittleEndian.Uint32(bytes)
	float := math.Float32frombits(bits)
	return float
}

func GetBytes(key interface{}) []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(key)
	checkErr(err)
	return buf.Bytes()
}
