package elgamalcrypto

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"fmt"
	"math/big"
	mr "math/rand"
	"testing"

	"github.com/codahale/sss"
	_ "github.com/lib/pq"
)

const testText = "They met me in the day of success: and I have" +
	"learned by the perfectest report, they have more in " +
	"them than mortal knowledge. When I burned in desire" +
	"to question them further, they made themselves air," +
	"into which they vanished. Whiles I stood rapt in" +
	"the wonder of it, came missives from the king, who " +
	"all-hailed me ‘Thane of Cawdor;’ by which title, " +
	"before, these weird sisters saluted me, and referred" +
	"me to the coming on of time, with ‘Hail, king that" +
	"shalt be!’ This have I thought good to deliver" +
	"thee, my dearest partner of greatness, that thou" +
	"mightst not lose the dues of rejoicing, by being" +
	"gnorant of what greatness is promised thee. Lay it" +
	"to thy heart, and farewell."

const (
	DB_USER     = "postgres"
	DB_PASSWORD = "123456"
	DB_SSLMODE  = "disable"
)

// Check that the key creation algorithm is working properly
func TestCreateKeys(t *testing.T) {
	fmt.Println("\nStarting test 1")
	pub, priv0, errCreate := CreateKeys(rand.Reader)

	if errCreate != nil {
		t.Errorf("Creation error : %s", errCreate)
	}

	_, errP := fmt.Printf("p = %x\n", (pub.Params()).P)
	_, errN := fmt.Printf("n = %x\n", (pub.Params()).N)
	_, errG := fmt.Printf("g = (%x, %x)\n", (pub.Params()).Gx, (pub.Params()).Gy)
	_, errY := fmt.Printf("y = (%x, %x)\n", pub.Y.x, pub.Y.y)
	_, errX := fmt.Printf("x = % x\n", priv0)

	if errP != nil || errN != nil || errG != nil || errY != nil || errX != nil {
		t.Error("An error occured somewhere.")
	}
}

// Test of the encryption/decryption algorithm
func TestED1(t *testing.T) {
	testEncryptDecryptHash(t, 1, []byte("hello"))
}

// Test of the encryption/decryption algorithm with a long text
func TestED2(t *testing.T) {
	testEncryptDecryptHash(t, 2, []byte(testText))
}

// Test of the encryption/decryption algorithm with a big integer
func TestED3(t *testing.T) {
	messageint, _ := rand.Int(rand.Reader, new(big.Int).Exp(big.NewInt(2), big.NewInt(687), nil))
	testEncryptDecryptHash(t, 3, messageint.Bytes())
}

// We test the ability to encrypt and decrypt a message passed as a parameter
func testEncryptDecryptHash(t *testing.T, testNumber int, message []byte) {
	fmt.Printf("\nTest 2, start of subtest %d\n", testNumber)

	pub, priv, _ := SetKeys(rand.Reader)
	cypher := pub.basicEncryptHash(message, rand.Reader)

	result := priv.Decrypt(cypher)
	if !bytes.Equal(result, message) {
		t.Errorf("Decryption failed, got: '% x', want: '% x\n", result, message)
	} else {
		fmt.Printf("Decryption %d success\n", testNumber)
	}
}

// We test if the SSS part of the SetKeys function is working properly
func TestSetKeys(t *testing.T) {
	fmt.Println("\nStarting test 3")
	_, priv, _ := SetKeys(rand.Reader)
	shares := map[byte][]byte{
		1: priv[1],
		2: priv[2],
	}
	priv0found := sss.Combine(shares)

	if !bytes.Equal(priv[0], priv0found) {
		t.Errorf("Conversion failed, got %x, wanted %x", priv0found, priv[0])
	} else {
		fmt.Println("Conversion success")
	}
}

// TestShort will test the conversion and re-conversion of the curve points in shortened form
func TestShort(t *testing.T) {
	fmt.Println("\nStarting test 4")
	a, err := rand.Int(rand.Reader, N)
	checkErr(err)
	pt := baseMult(a)
	fmt.Printf("Donnée d'origine : x = (%x, %x)\n", pt.x, pt.y)

	s := GetShortOf(pt)
	fmt.Printf("Donnée raccourcie : s = %x\n", s)

	pt2 := PointFromShort(s)
	if pt.equalC(pt2) {
		fmt.Printf("Reconversion réussie\n")
	} else {
		t.Errorf("Reconversion failed, got (%x, %x)", pt2.x, pt2.y)
	}
}

// We test the encryption of a table
func muteTestEncryptTable(t *testing.T) {
	fmt.Println("\nStarting test 5")
	db1info := fmt.Sprintf("user=%s password=%s dbname=postgres sslmode=%s", DB_USER, DB_PASSWORD, DB_SSLMODE)
	db1, err := sql.Open("postgres", db1info)
	checkErr(err)
	defer db1.Close()

	commands := []byte{0, 0, 1, 1, 1, 1, 2}
	_ = EncryptTable(db1, db1, "user_details", commands, rand.Reader)
}

func TestZero(t *testing.T) {
	fmt.Printf("(%x,%x)\n", pointZero.x, pointZero.y)
	pt := baseMult(Big0)
	fmt.Printf("(%x,%x)", pt.x, pt.y)
}

func TestKangaroo(t *testing.T) {
	fmt.Println("\nStarting test 6 : kangaroo small integer")
	BigSmth := big.NewInt(4194967296) // < 2**(4*8)
	pt := baseMult(BigSmth)
	pow := kangaroo(pt, 4)
	if pow.Cmp(BigSmth) == 0 {
		fmt.Println("Pollard succed")
	} else {
		t.Errorf("Pollard failed")
	}
}

func TestBSGS(t *testing.T) {
	fmt.Println("\nStarting test 7 : BSGS 5 bytes")
	smth := uint64(1099511327776)
	BigSmth := new(big.Int).SetUint64(smth)
	pt := baseMult(BigSmth)
	pow := babyStepGiantStep(pt, 5)
	if pow == smth {
		fmt.Println("BSGS succed")
	} else {
		t.Errorf("BSGS failed")
	}
}

func muteTestDouble(t *testing.T) {
	fmt.Println("\nStarting test 7")
	a := mr.Float32() * 100
	fmt.Println(a)

	pub, priv, _ := SetKeys(rand.Reader)
	aBytes := BytesFromFloat32(a)
	fmt.Printf("float sous forme de bytes : % x\n", aBytes)
	cypher := pub.basicEncryptPoint(aBytes, rand.Reader)

	result := decryptFromPoint(PointFromShort(cypher.Data), cypher.C.multB(priv[0]), "REAL")
	a2 := Float32frombytes(result)
	if a2 != a {
		t.Errorf("Decryption failed")
	} else {
		fmt.Printf("Decryption success\n")
	}
}

func muteTestDoubleAddition(t *testing.T) {
	fmt.Println("\nStarting test 8")
	a := mr.Float32() * 100
	b := mr.Float32() * 100
	fmt.Printf("a = %f, b = %f", a, b)

	pubA, privA, _ := SetKeys(rand.Reader)
	pubB, privB, _ := SetKeys(rand.Reader)
	aBytes := BytesFromFloat32(a)
	bBytes := BytesFromFloat32(b)

	cyphA := pubA.basicEncryptPoint(aBytes, rand.Reader)
	cyphB := pubB.basicEncryptPoint(bBytes, rand.Reader)

	pt := addC(PointFromShort(cyphA.Data), PointFromShort(cyphB.Data))
	ptKey := addC(cyphA.C.multB(privA[0]), cyphB.C.multB(privB[0]))

	result := Float32frombytes(decryptFromPoint(pt, ptKey, "REAL"))
	if result != a+b {
		t.Errorf("Decryption failed")
	} else {
		fmt.Printf("Decryption success\n")
	}
}
