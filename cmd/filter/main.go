package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/protocols/snap"
	"github.com/ethereum/go-ethereum/rlp"
)

func main() {
	// Parse the command line flags
	if len(os.Args) < 6 {
		fmt.Println("Usage: filter /path/to/snap.dump /path/to/snap.index hexdata /path/to/output.dump /path/to/output.index")
		return
	}
	dump, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer dump.Close()

	index, err := os.Open(os.Args[2])
	if err != nil {
		panic(err)
	}
	defer index.Close()

	h := common.HexToHash(os.Args[3])
	if h == (common.Hash{}) {
		panic("no hash")
	}

	outdump, err := os.Open(os.Args[4])
	if err != nil {
		panic(err)
	}
	defer outdump.Close()

	outindex, err := os.Open(os.Args[5])
	if err != nil {
		panic(err)
	}
	defer outindex.Close()

	matcher := makeMatcher(h)

	output := make(chan snap.Packet)
	go func() {
		for p := range output {
			writePacket(outdump, outindex, p)
		}
	}()
	filter(dump, index, matcher, output)
	close(output)
}

func makeMatcher(root common.Hash) func(snap.Packet) bool {
	var hasher = crypto.NewKeccakState()
	var hash = make([]byte, 32)

	matchFn := func(p snap.Packet) bool {
		switch packet := p.(type) {
		case *snap.AccountRangePacket:
			for _, x := range packet.Accounts {
				if x.Hash == root {
					return true
				}
				if bytes.Contains(x.Body, root[:]) {
					return true
				}

			}
		case *snap.StorageRangesPacket:
			for _, x := range packet.Slots {
				for _, data := range x {
					if data.Hash == root {
						return true
					}
				}
			}
		case *snap.ByteCodesPacket:
			for _, x := range packet.Codes {
				if bytes.Contains(x, root[:]) {
					return true
				}
			}
		case *snap.TrieNodesPacket:
			for _, x := range packet.Nodes {
				if bytes.Contains(x, root[:]) {
					return true
				}
				hasher.Reset()
				hasher.Write(x)
				hasher.Read(hash)
				if bytes.Equal(hash, root[:]) {
					return true
				}
			}
		}
		return false
	}
	return matchFn
}

func filter(dump, index *os.File, matchFn func(snap.Packet) bool, outCh chan snap.Packet) {

	var (
		pos  = int64(0)
		blob = make([]byte, 8)
	)
	for {
		_, err := index.ReadAt(blob, pos*17)
		if err != nil {
			break
		}
		//time := time.Unix(0, int64(binary.BigEndian.Uint64(blob)))

		index.ReadAt(blob, pos*17+8)
		offset := int64(binary.BigEndian.Uint64(blob))

		index.ReadAt(blob[:1], pos*17+16)
		kind := blob[0]
		// Read the data off disk
		dump.Seek(offset, io.SeekStart)
		var packet snap.Packet
		switch kind {
		case 0:
			packet = new(snap.AccountRangePacket)
		case 1:
			packet = new(snap.StorageRangesPacket)
		case 2:
			packet = new(snap.ByteCodesPacket)
		case 3:
			packet = new(snap.TrieNodesPacket)
		}
		if err := rlp.Decode(dump, packet); err != nil {
			panic(err)
		}
		if matchFn(packet) {
			outCh <- packet
		}
	}
}

var snapSize = uint64(0)

func writePacket(snapDump, snapIndex *os.File, packet snap.Packet) {
	blob, _ := rlp.EncodeToBytes(packet)
	if _, err := snapDump.Write(blob); err != nil {
		fmt.Printf("Failed to write packet into dump, err %v\n", err)
	}
	if err := binary.Write(snapIndex, binary.BigEndian, time.Now().UnixNano()); err != nil {
		fmt.Printf("Failed to write timestamp into index, err %v\n", err)
	}
	if err := binary.Write(snapIndex, binary.BigEndian, snapSize); err != nil {
		fmt.Printf("Failed to write offset into index, err %v\n", err)
	}
	snapSize += uint64(len(blob))

	var kind byte
	switch packet.(type) {
	case *snap.AccountRangePacket:
		kind = 0
	case *snap.StorageRangesPacket:
		kind = 1
	case *snap.ByteCodesPacket:
		kind = 2
	case *snap.TrieNodesPacket:
		kind = 3
	}
	if _, err := snapIndex.Write([]byte{kind}); err != nil {
		fmt.Printf("Failed to write type into index, err %v\n", err)
	}
}
