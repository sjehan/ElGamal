package elgamalcrypto

import (
	"database/sql"
)

// DecyptoOne Data allows the decryption of a single data encoded in a table
// We suppose that the row sent contains only the data
func DecryptOneData(row sql.Row, ti TableInfo, colNum int, keyParts map[int]CPoint) (result []byte) {
	sKey := calculateDecryptionKey(keyParts)
	var data []byte
	err := row.Scan(&data)
	checkErr(err)
	switch ti.commands[colNum] {
	case 1:
		result = decryptFromHash(data, sKey)
	case 2:
		result = decryptFromPoint(PointFromBytes(data), sKey, ti.colTypes[colNum])
	}
	return
}

// DecryptCalculatedDataColumn allows the data consumer to decrypt a data from a query
// We suppose that the rows sent contains couples of primary keys - data

func DecryptCalculatedDataColumn(rows sql.Rows, ti TableInfo, colNum int, keyParts map[int]CPoint) (result []byte) {
	// TODO
	return
}
