package elgamalcrypto

import (
	"encoding/json"
	"os"
)

/*
// Fonction pour stocker une clé privée dans un fichier
func (priv PrivateKey) StockPrivateKey (name string) (err error) {
	file, err := os.Create(name)
	defer file.Close()
	if err != nil {
		return
	}
	jsonTemp, _ := json.Marshal(priv.P)
	_, err = file.Write(jsonTemp)
	return
}

// Fonction pour obtenir une clé privée à partir d'un fichier
func RetrievePrivateKey (name string) (priv PrivateKey, err error) {
	file, err := os.Open(name)
	defer file.Close()
	if err != nil {
		return
	}
	b := make( []byte, 2*len(P.Bytes()) )
	nRead, err := file.Read(b)
	if err != nil {
		return
	}
	var P [4][]byte
	err = json.Unmarshal(b[0:nRead], P)
	priv = PrivateKey{ P }
	return
}

// Marshal a cypher as JSON
func (this *Cypher) MarshalJSON() ([]byte, error) {
	return json.Marshal(this.ToJSON())
}

// Unmarshal a JSON cypher
func (this *Cypher) UnmarshalJSON(bytes []byte) error {
	m := make(map[string]string)
	err := json.Unmarshal(bytes, &m)
	if err != nil {
		return err
	}
	this.FromJSON(m)
	return nil
}

// Fonction pour stocker un cypher classique
func (c Cypher) StockCypher (name string) (err error) {
	file, err := os.Create(name)
	defer file.Close()
	if err != nil {
		return
	}
	_, err = file.Write(Marshal(c))
	return
}
*/

// Fonction pour stocker un tableau de clés
func (array TableKeys) StockTableKeys(name string) (err error) {
	file, err := os.Create(name)
	defer file.Close()
	if err != nil {
		return
	}
	jsonTemp, _ := json.Marshal(array)
	_, err = file.Write(jsonTemp)
	return
}

func (array PartTableKey) StockSubKeyArray(name string) (err error) {
	return
}
