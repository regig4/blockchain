package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
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

func (block Block[T]) computeHash(ch chan string, difficulty int) {
	if block.merkleRoot == nil {
		return
	}

	hash := block.prevHash + block.timestamp.String() + fmt.Sprint(block.nonce)
	hash += block.merkleRoot.computeHash()
	tmpHash := sha256.Sum256([]byte(hash))
	tmpHash = sha256.Sum256(tmpHash[:])
	if strings.HasPrefix(toHex(tmpHash[:]), strings.Repeat("0", difficulty)) {
    fmt.Println(toHex(tmpHash[:]))
		ch <- toHex(tmpHash[:])
    close(ch)
	}
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
	from     string
	to       string
	value    int
	currency string
}

func (t Transaction) getHash() string {
	toJoin := []string{t.from, t.to, fmt.Sprint(t.value), t.currency}
	var hash = sha256.Sum256([]byte(strings.Join(toJoin, ",")))
	hash = sha256.Sum256(hash[:])
	return toHex(hash[:])
}

func toHex(data []byte) string {
	return hex.EncodeToString(data)
}

func (b *Block[T]) mine(difficulty int) {
	b.merkleRoot.hash = b.merkleRoot.computeHash()
	b.nonce = -1
	ch := make(chan string)
Loop:
	for {
		select {
		case <-ch:
			b.hash = <-ch
			break Loop
		default:
			b.nonce++
			go b.computeHash(ch, difficulty)
		}
	}

	fmt.Print(b.hash)

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
	if err != nil {
		fmt.Println(`failed gob Encode`, err)
	}
	return base64.StdEncoding.EncodeToString(b.Bytes())
}

// go binary decoder
func FromGOB64(str string) Blockchain[Transaction] {
	m := Blockchain[Transaction]{}
	by, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		fmt.Println(`failed base64 Decode`, err)
	}
	b := bytes.Buffer{}
	b.Write(by)
	d := gob.NewDecoder(&b)
	err = d.Decode(&m)
	if err != nil {
		fmt.Println(`failed gob Decode`, err)
	}
	return m
}

type MaxPaymentsHolder struct {
	maxPayments []int
}

func getMaxPayments(b Blockchain[Transaction], n int) []int {
	var maxPayments = []int{}
	result := MaxPaymentsHolder{maxPayments}
	for _, value := range b.chain {
		Dfs(*value.merkleRoot, &result, n)
	}
	return result.maxPayments
}

func Dfs(node MerkleNode[Transaction], maxPayments *MaxPaymentsHolder, n int) {
	if node.data == nil {
		Dfs(*node.left, maxPayments, n)
		Dfs(*node.right, maxPayments, n)
	} else {
		for _, tran := range node.data {
			if len(maxPayments.maxPayments) < n {
				maxPayments.maxPayments = append(maxPayments.maxPayments, tran.value)
				sort.Ints(maxPayments.maxPayments)
				for i, j := 0, len(maxPayments.maxPayments)-1; i < j; i, j = i+1, j-1 {
					maxPayments.maxPayments[i], maxPayments.maxPayments[j] = maxPayments.maxPayments[j], maxPayments.maxPayments[i]
				}
			} else {
				if maxPayments.maxPayments[len(maxPayments.maxPayments)-1] < tran.value {
					maxPayments.maxPayments = append(maxPayments.maxPayments, tran.value)
				}
				sort.Ints(maxPayments.maxPayments)
				for i, j := 0, len(maxPayments.maxPayments)-1; i < j; i, j = i+1, j-1 {
					maxPayments.maxPayments[i], maxPayments.maxPayments[j] = maxPayments.maxPayments[j], maxPayments.maxPayments[i]
				}
				maxPayments.maxPayments = maxPayments.maxPayments[:n]
			}
		}
	}
}

func main() {

	blockchain := CreateBlockchain()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleGetMaxPayments(w, r, blockchain)
	})
	http.ListenAndServe(":1000", nil)
}

func CreateBlockchain() Blockchain[Transaction] {
	a := Transaction{"a", "b", 10, "USD"}
	b := Transaction{"b", "a", 5, "USD"}
	c := Transaction{"a", "c", 15, "USD"}
	d := Transaction{"c", "b", 6, "USD"}
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
	return blockchain
}

func handleGetMaxPayments(w http.ResponseWriter, r *http.Request, b Blockchain[Transaction]) {
	json.NewEncoder(w).Encode(getMaxPayments(b, b.difficulty))
}
