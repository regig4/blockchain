package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

type Blockchain[T hashable] struct {
	genesis Block[T]
	chain   []Block[T]
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

	hash := block.prevHash + block.timestamp.String() + string(block.nonce)
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
	for !strings.HasPrefix(b.merkleRoot.hash, strings.Repeat("0", difficulty)) {
		b.nonce++
		b.hash = b.computeHash()
	}
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
	fmt.Println(rootNode.computeHash())
}
