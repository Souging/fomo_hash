package main

import (
    "encoding/binary"
    "encoding/json"
    "fmt"
    "io/ioutil"
    //"math/big"
    "net/http"
    "runtime"
    "sync"
    "sync/atomic"

    "golang.org/x/crypto/sha3"
)

type RequestData struct {
    CurrentHash []byte `json:"currentHash"`
    Sign        []byte `json:"sign"`
}

var inputPool = sync.Pool{
    New: func() interface{} {
        return make([]byte, 72)
    },
}

func calculateSHA3256(data []byte) []byte {
    hash := sha3.NewLegacyKeccak256()
    hash.Write(data)
    return hash.Sum(nil)
}

func main() {
    http.HandleFunc("/mine", handleMine)
    fmt.Println("Listening on :7070")
    http.ListenAndServe(":7070", nil)
}

func handleMine(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Access-Control-Allow-Origin", "https://suimine.xyz")
    w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

    if r.Method == http.MethodOptions {
        w.WriteHeader(http.StatusNoContent)
        return
    }

    if r.Method != http.MethodPost {
        http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
        return
    }

    body, err := ioutil.ReadAll(r.Body)
    if err != nil {
        http.Error(w, "Failed to read request body", http.StatusBadRequest)
        return
    }

    var data RequestData
    if err := json.Unmarshal(body, &data); err != nil {
        http.Error(w, "Failed to parse JSON", http.StatusBadRequest)
        return
    }
    nonce := findNonceParallel(data.CurrentHash, data.Sign)
	fmt.Println(data.CurrentHash,data.Sign,nonce)
    fmt.Fprintf(w, "%d", nonce)
}

func findNonceParallel(currentHash, signer []byte) uint64 {
    numCPU := runtime.NumCPU()*2
    runtime.GOMAXPROCS(numCPU)

    var found int64
    var resultNonce uint64
    var wg sync.WaitGroup

    for i := 0; i < numCPU; i++ {
        wg.Add(1)
        go func(id int) {
            defer wg.Done()
            input := inputPool.Get().([]byte)
            defer inputPool.Put(input)

            copy(input[:32], currentHash)
            copy(input[32:64], signer)

            for nonce := uint64(id); ; nonce += uint64(numCPU) {
                if atomic.LoadInt64(&found) != 0 {
                    return
                }

                binary.LittleEndian.PutUint64(input[64:], nonce)
                hash := calculateSHA3256(input)

                if checkHashIsValid(hash) {
                    if atomic.CompareAndSwapInt64(&found, 0, 1) {
                        resultNonce = nonce
                    }
                    return
                }

                if nonce+uint64(numCPU) < nonce { // Check for overflow
                    return
                }
            }
        }(i)
    }

    wg.Wait()
    return resultNonce
}

func checkHashIsValid(hash []byte) bool {
    return binary.LittleEndian.Uint32(hash)&0xFFFFFF == 0
}
