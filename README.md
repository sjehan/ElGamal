
# ixxo-elgamal
This package provides ElGamal encryption functionalities.
We use ElGamal on arrays, associated with Shamir's Secret Sharing and Baby Giant Step algorithm.


---
```go
// SETUP
go get github.com/codahale/sss
go get github.com/lib/pq
go build 
go test
```
---

We also find in this package 2 algoritms "lambda" and "Pollard rho", that are not used in the main program but whose usage could yet be implemented independently.
We use the Kangaroo algorithm to find the discrete logarithm of a number in a finite field.
https://arxiv.org/pdf/1501.07019.pdf


The ElGamal algorithm can be used in 2 distinct manners:
a) The first one uses a hash function and encodes the data by an XOR operation with the hash obtained from the key. The space taken by the encrypted data is then the same as that of the original, but no operation can be performed on it that does not pass through a preliminary decoding.
b) The second version considers the messages to be encrypted as integers, and then translates them into a point on the elliptic curve. To encrypt them, we then add another point on the curve determined by the corresponding keys. What is retained on the server is then a point on the curve in reduced format (29 bytes for the P224 curve). The encrypted messages are therefore necessarily voluminous but we can perform weighted sums of these values and decrypt only the result.


The source code uses the following packages:
- big : https://godoc.org/math/big
- elliptic : https://golang.org/pkg/crypto/elliptic/
- sql : https://golang.org/pkg/database/sql/
- pq (postgres) : https://godoc.org/github.com/lib/pq

Applications of the ElGamal algorithm are numerous, and we can cite the following examples:
1. A fully distributed voting system, being both private and verifiable.
https://members.loria.fr/VCortier/files/Papers/WPES2013.pdf

2. Verifiable dual encryption: we can verify that 2 different private keys have been used to encrypt the same message.
https://www.researchgate.net/publication/220100269_Verifiable_dual_encryption
https://www.cs.cornell.edu/fbs/publications/blindingRev.pdf

3. A digital currency with unlinkable transactions and privacy preserving regulation
https://publications.cispa.saarland/3823/1/platypus_ccs_final.pdf



## Description of the different files:
- dbdecrypt: contains the functions used specifically by the dataseller to encrypt tables in databases and to generate all the necessary keys.
- dbencrypt: contains the functions used specifically by the databuyer to decrypt the desired data.
- keyHolder: contains the functions used by the three key holders (Ledgys, the app owner and the data seller).
- decrypt: contains all the functions dedicated to the decryption of data, it is a kind of annex to the databuyer file which contains functions that are not accessible from the outside.
- encrypt: contains the functions dedicated to the encryption of data, which is in practice an annex to the dataseller file.
- utils: contains all the types of the package, constants and global variables as well as utility functions.
- localData: this file, still quite empty, was made to contain all the functions that will manage the storage of important data (keys ...) in the form of a file, so that they can be transmitted and / or preserved.


This package requires you to have an understanding of the concepts of ElGamal encryption, and elliptic curve. It is not a turn-key solution, but rather an infrastructure for you to build your own secured and privacy-preserving application.

To get technical support and the Enterprise version, contact us at: contact@ixxo.io

Enterprise version includes:
- Automatic export of files for CPoint, ShortPoint, TableKeys and PartTableKey.
- Support for NUMERIC (real numbers with known precision), the idea being to multiply them by the right power of 10 to then treat them as integers, then perform the inverse operation on the data consumer side after decoding. This is done according to the parameters that will be given by the datatype of the corresponding column in the SQL table.
- Improvement of the baby step giant step algorithm so that the first list (which is actually a map) that can be precomputed is stored locally 
- Web UI to test encryption and decryption of data and tables, secured computation on encrypoted data with online tables
- GraphQL API for easy integration in your application
- Support for multiple databases (Postgres, MySQL, MongoDB, Cassandra, Redis, Neo4j, ElasticSearch, etc.)
