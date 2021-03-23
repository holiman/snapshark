package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/araddon/dateparse"
	"github.com/ethereum/go-ethereum/eth/protocols/snap"
	"github.com/ethereum/go-ethereum/rlp"
	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
)

func main() {
	// Parse the command line flags
	if len(os.Args) < 4 {
		fmt.Println("Usage: bisect /path/to/snap.dump /path/to/snap.index fuzzy-time")
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

	slot, err := dateparse.ParseLocal(os.Args[3])
	if err != nil {
		panic(err)
	}
	// Find the packet closest to the requested event
	indexstat, _ := index.Stat()

	var (
		start = int64(0)
		end   = (indexstat.Size() - 17) / 17
		blob  = make([]byte, 8)
	)
	for start < end-1 {
		mid := (start + end) / 2

		index.ReadAt(blob, mid*17)
		inst := time.Unix(0, int64(binary.BigEndian.Uint64(blob)))
		if inst.UnixNano() > slot.UnixNano() {
			end = mid
		} else {
			start = mid
		}
	}
	// Parse and print the package
	if err := ui.Init(); err != nil {
		log.Fatalf("failed to initialize termui: %v", err)
	}
	defer ui.Close()

	render := func() {
		grid := ui.NewGrid()
		termWidth, termHeight := ui.TerminalDimensions()
		grid.SetRect(0, 0, termWidth, termHeight)

		grid.Set(
			ui.NewRow(1.0/5, ui.NewCol(1.0, paragraph(dump, index, start-2, (indexstat.Size()-17)/17))),
			ui.NewRow(1.0/5, ui.NewCol(1.0, paragraph(dump, index, start-1, (indexstat.Size()-17)/17))),
			ui.NewRow(1.0/5, ui.NewCol(1.0, paragraph(dump, index, start, (indexstat.Size()-17)/17))),
			ui.NewRow(1.0/5, ui.NewCol(1.0, paragraph(dump, index, start+1, (indexstat.Size()-17)/17))),
			ui.NewRow(1.0/5, ui.NewCol(1.0, paragraph(dump, index, start+2, (indexstat.Size()-17)/17))),
		)
		ui.Render(grid)
	}
	render()

	for e := range ui.PollEvents() {
		if e.Type == ui.KeyboardEvent {
			switch e.ID {
			case "<Up>":
				if start > 0 {
					start--
				}
				render()
			case "<Down>":
				if start < (indexstat.Size()-17)/17-1 {
					start++
				}
				render()
			case "<Enter>":
				export(dump, index, start, (indexstat.Size()-17)/17)
			case "q", "<C-c>":
				return
			}
		}
	}
}

func paragraph(dump, index *os.File, pos, cap int64) *widgets.Paragraph {
	// Start constructing the paragraph
	p := widgets.NewParagraph()
	p.TitleStyle.Fg = ui.ColorGreen
	p.PaddingTop, p.PaddingLeft = 1, 1
	if pos < 0 {
		p.Text = "Reached start of dump..."
		return p
	} else if pos >= cap {
		p.Text = "Reached end of dump..."
		return p
	}
	// Read the metadata off disk
	blob := make([]byte, 8)

	index.ReadAt(blob, pos*17)
	time := time.Unix(0, int64(binary.BigEndian.Uint64(blob)))

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
	// Fill the paragraph
	p.Title = time.String()

	switch packet := packet.(type) {
	case *snap.AccountRangePacket:
		hashes, accounts, _ := packet.Unpack()
		p.Text = fmt.Sprintf("#%d) Account Range Packet  (req #%d):\n  - %d hashes\n  - %d accounts\n  - %d proofs", pos, packet.ID, len(hashes), len(accounts), len(packet.Proof))

	case *snap.StorageRangesPacket:
		hashset, slotset := packet.Unpack()
		p.Text = fmt.Sprintf("#%d) Storage Ranges Packet (req #%d):\n  - %d hashset\n  - %d slotset\n  - %d proofs", pos, packet.ID, len(hashset), len(slotset), len(packet.Proof))

	case *snap.ByteCodesPacket:
		p.Text = fmt.Sprintf("#%d) Byte Codes Packet     (req #%d):\n  - %d bytecodes", pos, packet.ID, len(packet.Codes))

	case *snap.TrieNodesPacket:
		p.Text = fmt.Sprintf("#%d) Trie Nodes Packet     (req #%d):\n  - %d trienodes", pos, packet.ID, len(packet.Nodes))
	}
	return p
}

func export(dump, index *os.File, pos, cap int64) {
	if pos < 0 || pos >= cap {
		return
	}
	// Read the metadata off disk
	blob := make([]byte, 8)

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
	// Export the data into some user consumable thing
	blob, err := json.MarshalIndent(packet, "", "  ")
	if err != nil {
		panic(err)
	}
	exp, _ := ioutil.TempFile("", "")
	exp.Write(blob)
	exp.Close()

	open(exp.Name())
}

func open(url string) {
	var err error

	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}
	if err != nil {
		log.Fatal(err)
	}
}
