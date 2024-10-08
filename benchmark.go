package main

import (
	"encoding/binary"
	//"encoding/json"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
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

func benchmarkHashRate(currentHash, signer []byte, durationSeconds int) float64 {
        numCPU := runtime.NumCPU()*2
        runtime.GOMAXPROCS(numCPU)

        var totalHashes uint64
        var wg sync.WaitGroup
        done := make(chan struct{})

        for i := 0; i < numCPU; i++ {
                wg.Add(1)
                go func() {
                        defer wg.Done()
                        input := make([]byte, 72)
                        copy(input[:32], currentHash)
                        copy(input[32:64], signer)

                        var localHashes uint64
                        for {
                                select {
                                case <-done:
                                        atomic.AddUint64(&totalHashes, localHashes)
                                        return
                                default:
                                        binary.BigEndian.PutUint32(input[68:], uint32(localHashes))
                                        calculateSHA3256(input)
                                        localHashes++
                                }
                        }
                }()
        }

        time.Sleep(time.Duration(durationSeconds) * time.Second)
        close(done)
        wg.Wait()

        hashRate := float64(totalHashes) / float64(durationSeconds) / 1000000 // Convert to MH/s
        return hashRate
}


func calculateSHA3256(data []byte) []byte {
	hash := sha3.NewLegacyKeccak256()
	hash.Write(data)
	return hash.Sum(nil)
}

func findNonceParallel(currentHash, signer []byte) uint64 {
	numCPU := runtime.NumCPU()
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
						return
					}
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

func main() {
	// Replace with your actual data for benchmarking
	currentHash := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20}
	signer := []byte{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30}

	fmt.Println("Starting benchmark...")
	duration := 15
	hashRate := benchmarkHashRate(currentHash[:], signer[:], duration)
	fmt.Printf("hash：%.2f MH/s\n", hashRate)
	}
