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
 * Définitions des types utilisés
 *
 */

// CPoint, pour Curve Point, représente un point sur une courbe elliptique en coordonnées (x,y)
type CPoint struct {
	x, y *big.Int
}

// shortPoint est le type de la représentation des points de la courbe sous forme réduite
type ShortPoint [SHORT_POINT_LENGTH]byte

// Cypher est le type de cypher utilisé pour le cryptage sur courbe elliptique.
// Il correspond à une implémentation classique de ElGamal mais n'est utilisé ici qu'à
// des fins de test et pas pour le cryptage de tables.
type Cypher struct {
	C    CPoint
	Data []byte
}

// CypherPoint est le type de cypher dans le cas où le message est encodée sous forme
// de point de la courbe.
type CypherPoint struct {
	C    CPoint
	Data ShortPoint
}

// PublicKey est le type des clés publiques utilisées pour le cryptage sur les courbes elliptiques
type PublicKey struct {
	elliptic.Curve
	Y CPoint
}

// PrivateKey peut être vu comme un polynôme du premier degré dont on connait
// quatre valeurs. La première, en zéro, est celle qui est utilisée pour le
// cryptage, et les trois autres en 1, 2 et 3 permettent de retrouver la première
// en interpolant deux d'entre elles.
type PrivateKey [4][]byte

// TableInfo permet de garder toutes les informations utiles sur une table SQL donnée
type TableInfo struct {
	name     string
	nRows    uint64
	nCol     uint
	colNames []string
	colTypes []string
	commands []byte
}

// ArrayKeys contient toutes les clés permettant le déchiffrage d'une table.
// L'ensemble des clés privée est retenu sous forme de map puisqu'il n'existe pas
// forcément une clé privée par colonne, on ne les encrypte pas toutes.
type TableKeys struct {
	ti   TableInfo
	R    map[interface{}]*big.Int
	Priv map[string]PrivateKey
}

// PartArrayKey décrit le tableau des clés détenu par un des key holder relativement
// à une base de donnée, i.e. avec seulement une part des clés privées, donnée
// par Shamir's Secret Sharing. Concrètement au type clé privé on retient ici les éléments
// s_i donnés par SSS sous forme de big.Int. Cela facilite ensuite l'exécution de calculs.
type PartTableKey struct {
	ti        TableInfo
	keyHolder byte
	R         map[interface{}]*big.Int
	PrivPart  map[string]*big.Int // les s_j,k
}

// coord est un type qui correspond à des coordonnées dans un tableau SQL sous leur forme la plus
// pratique. i correspond à la clé primaire, qui va identifier la ligne, et j est le nom de la
// colonne, qui peut être plus pratique à manipuler que son numéro dans le cas de requêtes.
// Ce type n'est pas très utilisé actuellement dans mon code et je ne sais pas si il restera
// pertinent.
type coord struct {
	i interface{}
	j string
}

/*********************************************************************************************
 *
 * Définitions des variables et constantes (globales au package)
 *
 *********************************************************************************************/

const (
	DATASELLER = 1
	APPOWNER   = 2
	LEDGYS     = 3
)

// Cette valeur décrit la longueur en octets de la représentation d'un point de la courbe sous forme réduite
// Elle doit être changée si la courbe est modifiée.
const SHORT_POINT_LENGTH = 29

// Indique que la colonne qui va servir de clé primaire est la première
const PRIM_COL_NUMBER = 0

// Nombre maximum de routines que l'on lance sur les algorithmes ou le niveau de parallélisation est variable
const MAX_ROUTINES = 4

// Nombre de bits de chaque message encodé séparément (imposé par l'algorithme de hachage)
const BytesNumber = sha512.Size // = 64

// Tout ce qui a trait à la courbe utilisé
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
 * Fonctions de  vérification
 *
 *********************************************************************************************/

// checkErr est une fonction de gestion des erreurs,
// elle panique si une erreur est detectée
func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

// checkPoint vérifie la validité d'un point du type CPoint
// et panique si celui-ci n'est pas sur la courbe
func checkPoint(p CPoint) {
	if !(myCurve.Params()).IsOnCurve(p.x, p.y) {
		panic(errors.New("A point is not on the curve."))
	}
}

/*********************************************************************************************
 *
 * Opérateurs sur les points d'une courbe
 *
 *********************************************************************************************/

func (pt CPoint) String() string {
	return fmt.Sprintf("(%x, %x)", pt.x, pt.y)
}

// baseMult est un intermédiaire pour simplifier l'écriture et éviter
// de passer par ScalarBaseMult de elliptic, avec un scalaire en entrée
// sous forme de *big.Int
func baseMult(a *big.Int) (r CPoint) {
	r.x, r.y = (myCurve.Params()).ScalarBaseMult(a.Bytes())
	return
}

// baseMult est un intermédiaire pour simplifier l'écriture et éviter
// de passer par ScalarBaseMult de elliptic, avec un scalaire en entrée
// sous forme de []byte
func baseMultB(a []byte) (r CPoint) {
	r.x, r.y = (myCurve.Params()).ScalarBaseMult(a)
	return
}

// mult est un intermédiaire pour simplifier l'écriture et éviter
// de passer par ScalarBaseMult de elliptic, avec un scalaire en entrée
// sous forme de *big.Int
func (p CPoint) mult(a *big.Int) (r CPoint) {
	r.x, r.y = (myCurve.Params()).ScalarMult(p.x, p.y, a.Bytes())
	return
}

// mult est un intermédiaire pour simplifier l'écriture et éviter
// de passer par ScalarBaseMult de elliptic, avec un scalaire en entrée
// sous forme de []byte
func (p CPoint) multB(a []byte) (r CPoint) {
	r.x, r.y = (myCurve.Params()).ScalarMult(p.x, p.y, a)
	return
}

// addC est un intermédiaire pour simplifier l'écriture et éviter
// de passer par Add de elliptic
func addC(p, q CPoint) (r CPoint) {
	r.x, r.y = (myCurve.Params()).Add(p.x, p.y, q.x, q.y)
	return
}

// negC donne l'opposé d'un point sur une courbe elliptique
func (p CPoint) negC() (r CPoint) {
	r.x, r.y = p.x, new(big.Int).Neg(p.y)
	return
}

// sub est un intermédiaire pour simplifier l'écriture et éviter
// de passer par Add de elliptic
func (p CPoint) subC(q CPoint) CPoint {
	return addC(p, q.negC())
}

// equal est une méthode sur les points d'une courbe elliptique pour
// vérifier leur égalité
func (this CPoint) equalC(p CPoint) bool {
	return (this.x.Cmp(p.x) == 0) && (this.y.Cmp(p.y) == 0)
}

// double est un intermédiaire pour simplifier l'écriture et éviter
// de passer par Double de elliptic
func (p CPoint) doubleC() (r CPoint) {
	r.x, r.y = (myCurve.Params()).Double(p.x, p.y)
	return
}

/***********************************************************************************************
 *
 * Fonctions pour une représentation minimisée des points sur la courbe,
 * l'abscisse x et le signe de y suffisant à connaître le point.
 *
 * La forme adpoptée est la concaténation suivante :
 *  	short(p) = [f(y), x]
 * où f est une fonction de Z/pZ vers {0,1} telle que
 *		| 0 si y < p/2
 * f(y) = |
 *		| 1 si y >= p/2
 * En effet, pour un x donné on trouve au plus deux points dont les ordonnées sont
 * y et (p - y), car ils ont le même carré modulo p.
 * L'octet contenant f(y) sert donc à choisir le bon y au moment où l'on revient
 * ensuite en représentation classique.
 *
 ***********************************************************************************************/

// GetShortOf donne la représentation minimisée d'un point d'une courbe elliptique
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

// YFromX donne l'ordonnée positive du point de la courbe correspondant à l'abscisse x
// Il renvoie une erreur si ce point n'existe pas.
// On rappelle que la formule de la courbe est y^2 = x^3 - 3*x + b
// où b est spécifique à la courbe utilisée.
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

// PointFromShort retourne la représentation en coordonnées de types (x,y) d'un point
// à partir de sa représentation réduite.
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

// PointFromBytes est l'équivalent de PointFromShort mais en prenant des bytes en entrée
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
 * Fonctions utilitaires sur tables SQL
 *
 *********************************************************************************************/

func tableInfoFromDB(db *sql.DB, name string, comm ...byte) (ti TableInfo) {
	ti.name = name
	/* On obtient les dimensions de la table et les noms des colonnes */
	oneRow, err := db.Query(fmt.Sprintf("SELECT * FROM %s LIMIT 1;", name))
	checkErr(err)
	ti.colNames, _ = oneRow.Columns()
	ti.nCol = uint(len(ti.colNames))
	err = db.QueryRow(fmt.Sprintf("SELECT COUNT (*) FROM %s;", name)).Scan(&ti.nRows)
	checkErr(err)

	/* On obtient les types de données dans les colonnes */
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
		// Si pas d'instructions alors on crypte tout sans calcul possible sauf la première colonne qui
		// est supposée être celle des clés primaires
		ti.commands[0] = 0
		for j := uint(0); j < ti.nCol; j++ {
			ti.commands[j] = 1
		}
	} else {
		ti.commands = comm
	}
	return
}

// getCols renvoie la liste des colonnes avec noms et types pour la construction de la nouvelle table
func getColsString(ti TableInfo) string {
	// On utilise un buffer, qui est plus efficace pour la concaténation de chaînes de caractères
	// que l'utilisation de l'opérateur + entre variables string
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
 * Fonctions de conversion
 *
 *********************************************************************************************/

// BytesFromFloat64 convertit les float64 en bytes
func BytesFromFloat64(float float64) []byte {
	bits := math.Float64bits(float)
	bytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(bytes, bits)
	return bytes
}

// Float64frombytes convertit les []byte en float64
func Float64frombytes(bytes []byte) float64 {
	bits := binary.LittleEndian.Uint64(bytes)
	float := math.Float64frombits(bits)
	return float
}

// BytesFromFloat32 convertit les float64 en bytes
func BytesFromFloat32(float float32) []byte {
	bits := math.Float32bits(float)
	bytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(bytes, bits)
	return bytes
}

// Float32frombytes convertit les []byte en float64
func Float32frombytes(bytes []byte) float32 {
	bits := binary.LittleEndian.Uint32(bytes)
	float := math.Float32frombits(bits)
	return float
}

// GetBytes permet la conversion interface{} → []byte qui est utilisée plus haut
func GetBytes(key interface{}) []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(key)
	checkErr(err)
	return buf.Bytes()
}
