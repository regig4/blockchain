package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
  "encoding/base64"
  "encoding/gob"
  "bytes"
)

type Blockchain[T hashable] struct {
	genesis    Block[T]
	chain      []Block[T]
	difficulty int
}

type Block[T hashable] struct {
	prevHash   string
	hash       string
	timestamp  time.Time
	merkleRoot *MerkleNode[T]
	nonce      int
}

type hashable interface {
	getHash() string
}

type MerkleNode[T hashable] struct {
	hash  string
	left  *MerkleNode[T]
	right *MerkleNode[T]
	data  []T
}

func (block Block[T]) computeHash() string {
	if block.merkleRoot == nil {
		return ""
	}

	hash := block.prevHash + block.timestamp.String() + fmt.Sprint(block.nonce)
	hash += block.merkleRoot.computeHash()
	tmpHash := sha256.Sum256([]byte(hash))
	tmpHash = sha256.Sum256(tmpHash[:])
	return toHex(tmpHash[:])
}

func (node MerkleNode[T]) computeHash() string {
	if node.left == nil {
		hashes := ""
		for _, v := range node.data {
			hashes += v.getHash()
			hash := sha256.Sum256([]byte(hashes))
			hash = sha256.Sum256(hash[:])
			return toHex(hash[:])
		}
	}

	leftHash := node.left.computeHash()
	rightHash := node.right.computeHash()

	hash := sha256.Sum224([]byte(leftHash + rightHash))
	hash = sha256.Sum224(hash[:])

	return toHex(hash[:])
}

type Transaction struct {
	data string
}

func (t Transaction) getHash() string {
	var hash = sha256.Sum256([]byte(t.data))
	hash = sha256.Sum256(hash[:])
	return toHex(hash[:])
}

func toHex(data []byte) string {
	return hex.EncodeToString(data)
}

func (b *Block[T]) mine(difficulty int) {
	b.merkleRoot.hash = b.merkleRoot.computeHash()
	for !strings.HasPrefix(b.hash, strings.Repeat("0", difficulty)) {
		b.nonce++
		b.hash = b.computeHash()
    fmt.Println(fmt.Sprint(b.nonce, ": ", b.hash))
	}
}

func (b *Blockchain[T]) addBlock(block Block[T]) {
  var stringDefaultValue string
  if block.hash == stringDefaultValue {
		block.mine(b.difficulty)
	}

	block.timestamp = time.Now()
  
  var defaultValue Block[T]

	if b.genesis == defaultValue {
		b.genesis = block
	}

	b.chain = append(b.chain, block)
	block.prevHash = b.chain[len(b.chain)-1].hash
}

// go binary encoder
func ToGOB64(blockchain Blockchain[Transaction]) string {
    b := bytes.Buffer{}
    e := gob.NewEncoder(&b)
    err := e.Encode(blockchain)
    if err != nil { fmt.Println(`failed gob Encode`, err) }
    return base64.StdEncoding.EncodeToString(b.Bytes())
}

// go binary decoder
func FromGOB64(str string) Blockchain[Transaction] {
    m := Blockchain[Transaction]{}
    by, err := base64.StdEncoding.DecodeString(str)
    if err != nil { fmt.Println(`failed base64 Decode`, err); }
    b := bytes.Buffer{}
    b.Write(by)
    d := gob.NewDecoder(&b)
    err = d.Decode(&m)
    if err != nil { fmt.Println(`failed gob Decode`, err); }
    return m
}

func main() {
	a := Transaction{"a"}
	b := Transaction{"b"}
	c := Transaction{"c"}
	d := Transaction{"d"}
	leftNode := MerkleNode[Transaction]{}
	leftNode.data = []Transaction{a, b}
	rightNode := MerkleNode[Transaction]{}
	rightNode.data = []Transaction{c, d}
	rootNode := MerkleNode[Transaction]{}
	rootNode.left = &leftNode
	rootNode.right = &rightNode
	block := new(Block[Transaction])
	block.merkleRoot = &rootNode
	blockchain := Blockchain[Transaction]{}
  blockchain.difficulty = 3
  blockchain.addBlock(*block)
  serialized := ToGOB64(blockchain)
  deserialized := FromGOB64(serialized)
  fmt.Println(deserialized.chain[len(blockchain.chain)-1].nonce)
}
