// LDT — Local Data Transfer (Go edition)
// Same LDTv1 protocol as ldt.py — fully interoperable.
//
// Build:   go build -o ldt.exe .
// Usage:   ldt.exe Alice                  (interactive)
//
//	ldt.exe Alice receive
//	ldt.exe Bob send Alice file.mp4
//	ldt.exe Bob peers
package main

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv4"
)

// ─────────────────────────────────────────────────────────────────────────────
// PROTOCOL CONSTANTS
// ─────────────────────────────────────────────────────────────────────────────

var magic = [4]byte{'L', 'D', 'T', 0x01}

const (
	tHello      = 0x01
	tHelloAck   = 0x02
	tFileMeta   = 0x10
	tChunk      = 0x11
	tFileEnd    = 0x13
	tFileEndAck = 0x14
	tSessionEnd = 0x20
	tError      = 0xFF
	flagRaw     = 0x00
	flagZlib    = 0x01

	tcpPort      = 9900
	mcastGroup   = "239.255.42.42"
	mcastPort    = 9900
	discInterval = 5 * time.Second
	peerTTL      = 30 * time.Second
	chunkSize    = 2 * 1024 * 1024  // 2 MiB
	sockBuf      = 16 * 1024 * 1024 // 16 MiB
	compressGain = 0.05             // skip if ratio < 5%
	maxRetry     = 3
)

// ─────────────────────────────────────────────────────────────────────────────
// FRAME I/O
// ─────────────────────────────────────────────────────────────────────────────

func sendFrame(w io.Writer, msgType byte, payload []byte) error {
	hdr := make([]byte, 9)
	copy(hdr[:4], magic[:])
	hdr[4] = msgType
	binary.BigEndian.PutUint32(hdr[5:], uint32(len(payload)))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readFrame(r io.Reader) (byte, []byte, error) {
	hdr := make([]byte, 9)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return 0, nil, err
	}
	if hdr[0] != magic[0] || hdr[1] != magic[1] || hdr[2] != magic[2] || hdr[3] != magic[3] {
		return 0, nil, fmt.Errorf("bad magic: %x", hdr[:4])
	}
	msgType := hdr[4]
	plen := binary.BigEndian.Uint32(hdr[5:])
	payload := make([]byte, plen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return msgType, payload, nil
}

func tuneSock(conn *net.TCPConn) {
	conn.SetNoDelay(true)
	conn.SetReadBuffer(sockBuf)
	conn.SetWriteBuffer(sockBuf)
}

// ─────────────────────────────────────────────────────────────────────────────
// COMPRESSION & INTEGRITY
// ─────────────────────────────────────────────────────────────────────────────

func compressBytes(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := zlib.NewWriterLevel(&buf, 1) // level 1 = fastest
	if err != nil {
		return nil, err
	}
	if _, err = w.Write(data); err != nil {
		return nil, err
	}
	if err = w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decompressBytes(data []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("zlib open: %w", err)
	}
	defer r.Close()
	return io.ReadAll(r)
}

func sha256Bytes(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// ─────────────────────────────────────────────────────────────────────────────
// PEER DISCOVERY
// ─────────────────────────────────────────────────────────────────────────────

type Peer struct {
	ID   string
	Name string
	Host string
	Port int
	Seen time.Time
}

type Discovery struct {
	myName  string
	myID    string
	tcpPort int

	mu    sync.Mutex
	peers map[string]*Peer

	conn   *net.UDPConn
	stopCh chan struct{}
}

func newDiscovery(name string, port int) *Discovery {
	d := &Discovery{
		myName:  name,
		myID:    fmt.Sprintf("%d", time.Now().UnixNano()),
		tcpPort: port,
		peers:   make(map[string]*Peer),
		stopCh:  make(chan struct{}),
	}
	return d
}

func (d *Discovery) Start() error {
	addr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf(":%d", mcastPort))
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return err
	}
	d.conn = conn

	// Join multicast group
	iface, _ := d.bestInterface()
	pc := ipv4.NewPacketConn(conn)
	group := net.ParseIP(mcastGroup)
	if iface != nil {
		pc.JoinGroup(iface, &net.UDPAddr{IP: group})
	} else {
		ifaces, _ := net.Interfaces()
		for _, i := range ifaces {
			pc.JoinGroup(&i, &net.UDPAddr{IP: group})
		}
	}
	pc.SetMulticastTTL(4)

	go d.loop()
	return nil
}

func (d *Discovery) bestInterface() (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if _, ok := addr.(*net.IPNet); ok {
				return &iface, nil
			}
		}
	}
	return nil, nil
}

func (d *Discovery) Stop() {
	close(d.stopCh)
	d.send(map[string]interface{}{"t": "BY", "id": d.myID})
	d.conn.Close()
}

func (d *Discovery) Peers() []*Peer {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []*Peer
	now := time.Now()
	for _, p := range d.peers {
		if now.Sub(p.Seen) < peerTTL {
			out = append(out, p)
		}
	}
	return out
}

func (d *Discovery) Find(nameOrIP string) *Peer {
	for _, p := range d.Peers() {
		if p.Name == nameOrIP || p.Host == nameOrIP {
			return p
		}
	}
	return nil
}

func (d *Discovery) Query() {
	d.send(map[string]interface{}{
		"t": "QR", "id": d.myID,
		"name": d.myName, "port": d.tcpPort, "v": 1,
	})
}

func (d *Discovery) announce() {
	d.send(map[string]interface{}{
		"t": "AN", "id": d.myID,
		"name": d.myName, "port": d.tcpPort, "v": 1,
	})
}

func (d *Discovery) send(msg map[string]interface{}) {
	data, _ := json.Marshal(msg)
	dst := &net.UDPAddr{IP: net.ParseIP(mcastGroup), Port: mcastPort}
	d.conn.WriteTo(data, dst)
}

func (d *Discovery) loop() {
	ticker := time.NewTicker(discInterval)
	defer ticker.Stop()
	d.announce()
	buf := make([]byte, 2048)
	d.conn.SetReadDeadline(time.Time{})
	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			d.announce()
		default:
			d.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, src, err := d.conn.ReadFrom(buf)
			if err != nil {
				if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
					continue
				}
				return
			}
			srcIP := src.(*net.UDPAddr).IP.String()
			var msg map[string]interface{}
			if json.Unmarshal(buf[:n], &msg) == nil {
				d.handle(msg, srcIP)
			}
		}
	}
}

func (d *Discovery) handle(msg map[string]interface{}, srcIP string) {
	t, _ := msg["t"].(string)
	id, _ := msg["id"].(string)
	if id == d.myID {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if t == "BY" {
		delete(d.peers, id)
		return
	}
	if t == "AN" || t == "QR" {
		name, _ := msg["name"].(string)
		if name == "" {
			name = srcIP
		}
		port := tcpPort
		if p, ok := msg["port"].(float64); ok {
			port = int(p)
		}
		d.peers[id] = &Peer{ID: id, Name: name, Host: srcIP, Port: port, Seen: time.Now()}
		if t == "QR" {
			go d.announce()
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// FILE WALKER
// ─────────────────────────────────────────────────────────────────────────────

type FileEntry struct {
	AbsPath string
	RelPath string
	Size    int64
	Mtime   float64
	Chunks  int
}

func collectEntries(paths []string) ([]FileEntry, error) {
	var result []FileEntry
	for _, raw := range paths {
		abs, err := filepath.Abs(raw)
		if err != nil {
			return nil, err
		}
		info, err := os.Stat(abs)
		if err != nil {
			return nil, fmt.Errorf("not found: %s", raw)
		}
		if info.IsDir() {
			parent := filepath.Dir(abs)
			err = filepath.Walk(abs, func(path string, fi os.FileInfo, err error) error {
				if err != nil || fi.IsDir() {
					return err
				}
				rel, _ := filepath.Rel(parent, path)
				rel = filepath.ToSlash(rel)
				sz := fi.Size()
				n := int(math.Max(1, math.Ceil(float64(sz)/chunkSize)))
				if sz == 0 {
					n = 1
				}
				result = append(result, FileEntry{
					AbsPath: path, RelPath: rel, Size: sz,
					Mtime: float64(fi.ModTime().UnixNano()) / 1e9, Chunks: n,
				})
				return nil
			})
			if err != nil {
				return nil, err
			}
		} else {
			sz := info.Size()
			n := int(math.Max(1, math.Ceil(float64(sz)/chunkSize)))
			if sz == 0 {
				n = 1
			}
			result = append(result, FileEntry{
				AbsPath: abs, RelPath: info.Name(), Size: sz,
				Mtime: float64(info.ModTime().UnixNano()) / 1e9, Chunks: n,
			})
		}
	}
	return result, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// PROGRESS BAR
// ─────────────────────────────────────────────────────────────────────────────

type Progress struct {
	label string
	total int64
	done  atomic.Int64
	t0    time.Time
	last  time.Time
}

func newProgress(label string, total int64) *Progress {
	if len(label) > 20 {
		label = label[len(label)-20:]
	}
	return &Progress{label: label, total: max64(total, 1), t0: time.Now()}
}

func (p *Progress) Advance(n int64) {
	p.done.Add(n)
	if time.Since(p.last) >= 150*time.Millisecond || p.done.Load() >= p.total {
		p.last = time.Now()
		p.draw()
	}
}

func (p *Progress) Finish() {
	p.done.Store(p.total)
	p.draw()
	fmt.Fprintln(os.Stderr)
}

func (p *Progress) draw() {
	done := p.done.Load()
	pct := float64(done) / float64(p.total)
	width := 28
	filled := int(pct * float64(width))
	bar := strings.Repeat("#", filled) + strings.Repeat(".", width-filled)
	dt := time.Since(p.t0).Seconds()
	var speed float64
	if dt > 0 {
		speed = float64(done) / dt
	}
	var eta float64
	if speed > 0 {
		eta = float64(p.total-done) / speed
	}
	fmt.Fprintf(os.Stderr, "\r  %-20s [%s] %5.1f%%  %s/s  ETA %s",
		p.label, bar, pct*100, fmtSize(speed), fmtTime(eta))
}

func fmtSize(n float64) string {
	for _, u := range []string{"B", "KB", "MB", "GB"} {
		if n < 1024 {
			return fmt.Sprintf("%6.1f %s", n, u)
		}
		n /= 1024
	}
	return fmt.Sprintf("%6.1f TB", n)
}

func fmtTime(s float64) string {
	if s < 60 {
		return fmt.Sprintf("%.0fs", s)
	}
	return fmt.Sprintf("%.0fm%02ds", s/60, int(s)%60)
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// ─────────────────────────────────────────────────────────────────────────────
// SENDER
// ─────────────────────────────────────────────────────────────────────────────

func sendSession(conn *net.TCPConn, entries []FileEntry, myName string, quiet bool, gOffset, gTotal int) error {
	tuneSock(conn)
	bw := bufio.NewWriterSize(conn, sockBuf)

	totalLabel := gTotal
	if totalLabel == 0 {
		totalLabel = len(entries)
	}

	// HELLO
	hello, _ := json.Marshal(map[string]interface{}{"name": myName, "files": len(entries)})
	if err := sendFrame(bw, tHello, hello); err != nil {
		return err
	}
	if err := bw.Flush(); err != nil {
		return err
	}

	t, pl, err := readFrame(conn)
	if err != nil {
		return err
	}
	if t != tHelloAck {
		return fmt.Errorf("expected HELLO_ACK")
	}
	var ack map[string]interface{}
	json.Unmarshal(pl, &ack)
	if ok, _ := ack["ok"].(bool); !ok {
		reason, _ := ack["reason"].(string)
		return fmt.Errorf("rejected: %s", reason)
	}

	for idx, entry := range entries {
		fmt.Printf("  [%d/%d] %s  (%s)\n", gOffset+idx+1, totalLabel,
			entry.RelPath, strings.TrimSpace(fmtSize(float64(entry.Size))))
		if err := sendFile(conn, bw, idx, entry, quiet, 0); err != nil {
			return err
		}
	}
	return nil
}

func finishSession(conn *net.TCPConn, bw *bufio.Writer) error {
	if err := sendFrame(bw, tSessionEnd, nil); err != nil {
		return err
	}
	return bw.Flush()
}

func probeCompressible(path string, size int64) bool {
	if size == 0 {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return true
	}
	defer f.Close()
	probeLen := int64(chunkSize)
	if size < probeLen {
		probeLen = size
	}
	raw := make([]byte, probeLen)
	n, _ := io.ReadFull(f, raw)
	if n == 0 {
		return false
	}
	raw = raw[:n]
	comp, err := compressBytes(raw)
	if err != nil {
		return false
	}
	ratio := 1.0 - float64(len(comp))/float64(len(raw))
	return ratio >= compressGain
}

func sendFile(conn *net.TCPConn, bw *bufio.Writer, idx int, entry FileEntry, quiet bool, attempt int) error {
	useCompress := probeCompressible(entry.AbsPath, entry.Size)

	meta, _ := json.Marshal(map[string]interface{}{
		"i": idx, "p": entry.RelPath, "s": entry.Size,
		"c": entry.Chunks, "m": entry.Mtime,
		"retry": attempt, "nc": !useCompress,
	})
	if err := sendFrame(bw, tFileMeta, meta); err != nil {
		return err
	}

	var prog *Progress
	if !quiet && entry.Size > 0 {
		prog = newProgress(entry.RelPath, entry.Size)
	}

	f, err := os.Open(entry.AbsPath)
	if err != nil {
		return err
	}
	defer f.Close()

	fileHasher := sha256.New()
	buf := make([]byte, chunkSize)
	ci := 0

	if entry.Size == 0 {
		// empty file — send one empty chunk
		chunkHash := sha256.Sum256(nil)
		chunkHdr := make([]byte, 41) // 4+32+4+1
		binary.BigEndian.PutUint32(chunkHdr[0:], uint32(0))
		copy(chunkHdr[4:], chunkHash[:])
		binary.BigEndian.PutUint32(chunkHdr[36:], 0)
		chunkHdr[40] = flagRaw
		if err := sendFrame(bw, tChunk, chunkHdr); err != nil {
			return err
		}
	} else {
		for {
			n, err := f.Read(buf)
			if n == 0 {
				if err == io.EOF {
					break
				}
				return err
			}
			raw := buf[:n]
			fileHasher.Write(raw)
			chunkHash := sha256.Sum256(raw)

			var data []byte
			var flags byte
			if useCompress {
				comp, err := compressBytes(raw)
				if err != nil || len(comp) >= len(raw) {
					data = raw
					flags = flagRaw
				} else {
					data = comp
					flags = flagZlib
				}
			} else {
				data = raw
				flags = flagRaw
			}

			chunkHdr := make([]byte, 41)
			binary.BigEndian.PutUint32(chunkHdr[0:], uint32(ci))
			copy(chunkHdr[4:], chunkHash[:])
			binary.BigEndian.PutUint32(chunkHdr[36:], uint32(len(data)))
			chunkHdr[40] = flags
			payload := append(chunkHdr, data...)
			if err := sendFrame(bw, tChunk, payload); err != nil {
				return err
			}
			if prog != nil {
				prog.Advance(int64(n))
			}
			ci++
			if err == io.EOF {
				break
			}
		}
	}
	if err := bw.Flush(); err != nil {
		return err
	}
	if prog != nil {
		prog.Finish()
	}

	// FILE_END
	fileHash := fileHasher.Sum(nil)
	endPl := make([]byte, 36)
	binary.BigEndian.PutUint32(endPl[0:], uint32(idx))
	copy(endPl[4:], fileHash)
	if err := sendFrame(bw, tFileEnd, endPl); err != nil {
		return err
	}
	if err := bw.Flush(); err != nil {
		return err
	}

	// Wait FILE_END_ACK
	t, pl, err := readFrame(conn)
	if err != nil {
		return err
	}
	if t != tFileEndAck {
		return fmt.Errorf("expected FILE_END_ACK")
	}
	var ackMsg map[string]interface{}
	json.Unmarshal(pl, &ackMsg)
	if ok, _ := ackMsg["ok"].(bool); ok {
		return nil
	}
	reason, _ := ackMsg["reason"].(string)
	if attempt >= maxRetry {
		return fmt.Errorf("%s failed after %d retries: %s", entry.RelPath, maxRetry, reason)
	}
	fmt.Printf("  Retry %d/%d for %s (%s)\n", attempt+1, maxRetry, entry.RelPath, reason)
	return sendFile(conn, bw, idx, entry, quiet, attempt+1)
}

// ─────────────────────────────────────────────────────────────────────────────
// PARALLEL SEND
// ─────────────────────────────────────────────────────────────────────────────

func sendParallel(entries []FileEntry, host string, port int, myName string, workers int, quiet bool) error {
	if workers > len(entries) {
		workers = len(entries)
	}
	groups := make([][]FileEntry, workers)
	for i, e := range entries {
		groups[i%workers] = append(groups[i%workers], e)
	}
	gOffsets := make([]int, workers)
	off := 0
	for i := range workers {
		gOffsets[i] = off
		off += len(groups[i])
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error

	for i, group := range groups {
		if len(group) == 0 {
			continue
		}
		wg.Add(1)
		go func(grp []FileEntry, gOff int) {
			defer wg.Done()
			addr := fmt.Sprintf("%s:%d", host, port)
			c, err := net.DialTimeout("tcp", addr, 15*time.Second)
			if err != nil {
				mu.Lock()
				firstErr = err
				mu.Unlock()
				return
			}
			tc := c.(*net.TCPConn)
			bw := bufio.NewWriterSize(tc, sockBuf)
			err = sendSession(tc, grp, myName, quiet, gOff, len(entries))
			if err == nil {
				err = finishSession(tc, bw)
			}
			tc.Close()
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
			}
		}(group, gOffsets[i])
	}
	wg.Wait()
	return firstErr
}

// ─────────────────────────────────────────────────────────────────────────────
// RECEIVER
// ─────────────────────────────────────────────────────────────────────────────

func startServer(destDir string, port int) (*net.TCPListener, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}
	return ln.(*net.TCPListener), nil
}

func acceptLoop(ln *net.TCPListener, destDir string, stopCh <-chan struct{}) {
	for {
		ln.SetDeadline(time.Now().Add(time.Second))
		conn, err := ln.AcceptTCP()
		if err != nil {
			select {
			case <-stopCh:
				return
			default:
				continue
			}
		}
		go handleConn(conn, destDir)
	}
}

func handleConn(conn *net.TCPConn, destDir string) {
	defer conn.Close()
	tuneSock(conn)
	if err := recvSession(conn, destDir); err != nil && err != io.EOF {
		fmt.Fprintf(os.Stderr, "\n  !! Error from %s: %v\n", conn.RemoteAddr(), err)
	}
}

func recvSession(conn *net.TCPConn, destDir string) error {
	t, pl, err := readFrame(conn)
	if err != nil {
		return err
	}
	if t != tHello {
		return fmt.Errorf("expected HELLO")
	}
	var info map[string]interface{}
	json.Unmarshal(pl, &info)
	sender, _ := info["name"].(string)
	if sender == "" {
		sender = conn.RemoteAddr().String()
	}
	peerIP := strings.Split(conn.RemoteAddr().String(), ":")[0]

	ack, _ := json.Marshal(map[string]interface{}{"ok": true})
	if err := sendFrame(conn, tHelloAck, ack); err != nil {
		return err
	}
	fmt.Printf("\n  <- %s (%s)  %.0f file(s)\n", sender, peerIP, info["files"])

	for {
		t, pl, err := readFrame(conn)
		if err != nil {
			return err
		}
		switch t {
		case tSessionEnd:
			fmt.Printf("  OK Transfer from %s complete\n\n", sender)
			return nil
		case tFileMeta:
			var meta map[string]interface{}
			json.Unmarshal(pl, &meta)
			if err := recvFile(conn, meta, destDir); err != nil {
				return err
			}
		case tError:
			var errMsg map[string]interface{}
			json.Unmarshal(pl, &errMsg)
			fmt.Fprintf(os.Stderr, "  !! sender error: %v\n", errMsg["msg"])
			return nil
		}
	}
}

func recvFile(conn *net.TCPConn, meta map[string]interface{}, destDir string) error {
	relPath, _ := meta["p"].(string)
	totalF, _ := meta["s"].(float64)
	total := int64(totalF)
	nChunksF, _ := meta["c"].(float64)
	nChunks := int(nChunksF)
	mtimeF, _ := meta["m"].(float64)
	noComp, _ := meta["nc"].(bool)
	isRetry := false
	if r, ok := meta["retry"].(float64); ok && r > 0 {
		isRetry = true
	}

	// Security: block path traversal
	rel := filepath.FromSlash(relPath)
	if filepath.IsAbs(rel) || strings.Contains(rel, "..") {
		drain(conn, nChunks)
		readFrame(conn) // FILE_END
		nack, _ := json.Marshal(map[string]interface{}{"ok": false, "reason": "unsafe path"})
		sendFrame(conn, tFileEndAck, nack)
		return nil
	}

	dest := filepath.Join(destDir, rel)
	os.MkdirAll(filepath.Dir(dest), 0755)

	label := relPath
	if isRetry {
		label = "retry " + label
	}
	fmt.Printf("  >> %s  (%s)\n", label, strings.TrimSpace(fmtSize(float64(total))))

	prog := newProgress(relPath, max64(total, 1))

	// Async write queue
	type writeJob = []byte
	writeQ := make(chan writeJob, 4)
	var writeErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		f, err := os.Create(dest)
		if err != nil {
			writeErr = err
			for range writeQ {
			} // drain
			return
		}
		defer f.Close()
		for block := range writeQ {
			if block == nil {
				break
			}
			if _, err := f.Write(block); err != nil {
				writeErr = err
			}
		}
	}()

	fileHasher := sha256.New()
	var badChunks []int

	for range nChunks {
		t, pl, err := readFrame(conn)
		if err != nil {
			close(writeQ)
			wg.Wait()
			return err
		}
		if t == tError {
			close(writeQ)
			wg.Wait()
			return fmt.Errorf("sender error mid-transfer")
		}
		if t != tChunk || len(pl) < 41 {
			badChunks = append(badChunks, -1)
			continue
		}

		ci := binary.BigEndian.Uint32(pl[0:4])
		var expectedHash [32]byte
		copy(expectedHash[:], pl[4:36])
		dlen := binary.BigEndian.Uint32(pl[36:40])
		flags := pl[40]
		rawData := pl[41 : 41+dlen]

		var raw []byte
		if flags&flagZlib != 0 && !noComp {
			raw, err = decompressBytes(rawData)
			if err != nil {
				badChunks = append(badChunks, int(ci))
				writeQ <- make([]byte, chunkSize) // placeholder
				continue
			}
		} else {
			raw = rawData
		}

		gotHash := sha256.Sum256(raw)
		if gotHash != expectedHash {
			badChunks = append(badChunks, int(ci))
			writeQ <- raw // keep position
		} else {
			fileHasher.Write(raw)
			writeQ <- raw
		}
		prog.Advance(int64(len(raw)))
	}

	writeQ <- nil
	wg.Wait()

	if writeErr != nil {
		os.Remove(dest)
		readFrame(conn)
		nack, _ := json.Marshal(map[string]interface{}{"ok": false, "reason": writeErr.Error()})
		return sendFrame(conn, tFileEndAck, nack)
	}

	prog.Finish()

	// FILE_END
	t, pl, err := readFrame(conn)
	if err != nil {
		return err
	}
	if t != tFileEnd || len(pl) < 36 {
		nack, _ := json.Marshal(map[string]interface{}{"ok": false, "reason": "expected FILE_END"})
		return sendFrame(conn, tFileEndAck, nack)
	}

	var senderHash [32]byte
	copy(senderHash[:], pl[4:36])
	var actualHash [32]byte
	copy(actualHash[:], fileHasher.Sum(nil))

	if len(badChunks) > 0 || actualHash != senderHash {
		os.Remove(dest)
		nack, _ := json.Marshal(map[string]interface{}{
			"ok": false, "reason": "hash mismatch", "bad": badChunks,
		})
		fmt.Fprintf(os.Stderr, "  !! %s: hash mismatch -- will retry\n", relPath)
		return sendFrame(conn, tFileEndAck, nack)
	}

	if mtimeF > 0 {
		mt := time.Unix(int64(mtimeF), int64((mtimeF-math.Floor(mtimeF))*1e9))
		os.Chtimes(dest, mt, mt)
	}

	ackMsg, _ := json.Marshal(map[string]interface{}{"ok": true})
	sendFrame(conn, tFileEndAck, ackMsg)
	fmt.Printf("  OK saved -> %s\n", dest)
	return nil
}

func drain(conn *net.TCPConn, n int) {
	for range n {
		readFrame(conn)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// INTERACTIVE REPL
// ─────────────────────────────────────────────────────────────────────────────

const replHelp = `
Commands:
  peers                             List peers on the network
  send <target> <path> [<path>...]  Send files/folders to a peer
       --workers N                  Parallel connections (default 1)
  dir [PATH]                        Show/change receive directory
  help                              Show this message
  exit                              Quit
`

func doSend(disc *Discovery, args []string, myName string, port int, quiet bool) {
	workers := 1
	var clean []string
	for i := 0; i < len(args); i++ {
		if args[i] == "--workers" && i+1 < len(args) {
			if n, err := strconv.Atoi(args[i+1]); err == nil {
				workers = n
			}
			i++
		} else {
			clean = append(clean, args[i])
		}
	}
	if len(clean) < 2 {
		fmt.Println("  Usage: send <target> <path> [<path>...]")
		return
	}
	target, paths := clean[0], clean[1:]

	entries, err := collectEntries(paths)
	if err != nil {
		fmt.Printf("  Error: %v\n", err)
		return
	}
	if len(entries) == 0 {
		fmt.Println("  Nothing to send.")
		return
	}

	disc.Query()
	var peer *Peer
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if peer = disc.Find(target); peer != nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	var host string
	var rport int
	if peer != nil {
		host, rport = peer.Host, peer.Port
		fmt.Printf("  -> %s  [%s:%d]\n", peer.Name, host, rport)
	} else {
		host, rport = target, port
		fmt.Printf("  Peer '%s' not found — trying %s:%d directly\n", target, host, rport)
	}

	total := int64(0)
	for _, e := range entries {
		total += e.Size
	}
	if workers > len(entries) {
		workers = len(entries)
	}
	suffix := ""
	if workers > 1 {
		suffix = fmt.Sprintf("  [workers=%d]", workers)
	}
	fmt.Printf("  Sending %d file(s)  (%s)%s\n\n",
		len(entries), strings.TrimSpace(fmtSize(float64(total))), suffix)

	t0 := time.Now()
	if workers <= 1 {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, rport), 15*time.Second)
		if err != nil {
			fmt.Printf("  Cannot connect: %v\n", err)
			return
		}
		tc := c.(*net.TCPConn)
		bw := bufio.NewWriterSize(tc, sockBuf)
		err = sendSession(tc, entries, myName, quiet, 0, 0)
		if err == nil {
			err = finishSession(tc, bw)
		}
		tc.Close()
		if err != nil {
			fmt.Printf("  Transfer failed: %v\n", err)
			return
		}
	} else {
		if err := sendParallel(entries, host, rport, myName, workers, quiet); err != nil {
			fmt.Printf("  Transfer failed: %v\n", err)
			return
		}
	}
	dt := time.Since(t0).Seconds()
	speed := float64(total) / dt
	fmt.Printf("\n  Done  %s in %s  (%s/s)\n",
		strings.TrimSpace(fmtSize(float64(total))), fmtTime(dt), strings.TrimSpace(fmtSize(speed)))
}

func splitArgs(line string) []string {
	// simple shell-like split: respect "quoted strings"
	var parts []string
	var cur strings.Builder
	inQ := false
	for _, c := range line {
		switch {
		case c == '"':
			inQ = !inQ
		case c == ' ' && !inQ:
			if cur.Len() > 0 {
				parts = append(parts, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(c)
		}
	}
	if cur.Len() > 0 {
		parts = append(parts, cur.String())
	}
	return parts
}

func runInteractive(myName string, port int, recvDir string) {
	dir, _ := filepath.Abs(recvDir)
	os.MkdirAll(dir, 0755)

	disc := newDiscovery(myName, port)
	disc.Start()

	ln, err := startServer(dir, port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot bind port %d: %v\n", port, err)
		os.Exit(1)
	}
	stopCh := make(chan struct{})
	go acceptLoop(ln, dir, stopCh)

	fmt.Printf("LDT  |  %s  |  port %d  |  saving to %s\n", myName, port, dir)
	fmt.Println("Ready. Type 'help' for commands, Ctrl-C to exit.\n")

	quiet := false
	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Print("ldt> ")
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := splitArgs(line)
		cmd := strings.ToLower(parts[0])
		rest := parts[1:]

		switch cmd {
		case "exit", "quit", "q":
			goto done
		case "help", "h", "?":
			fmt.Println(replHelp)
		case "peers":
			disc.Query()
			time.Sleep(800 * time.Millisecond)
			found := disc.Peers()
			if len(found) == 0 {
				fmt.Println("  No peers found yet — peers announce every 5s")
			} else {
				fmt.Printf("\n  %-20s  %-16s  PORT\n", "NAME", "IP")
				fmt.Println("  " + strings.Repeat("-", 44))
				for _, p := range found {
					fmt.Printf("  %-20s  %-16s  %d\n", p.Name, p.Host, p.Port)
				}
				fmt.Println()
			}
		case "send":
			doSend(disc, rest, myName, port, quiet)
		case "dir":
			if len(rest) > 0 {
				newDir, _ := filepath.Abs(rest[0])
				os.MkdirAll(newDir, 0755)
				dir = newDir
				close(stopCh)
				ln.Close()
				ln, err = startServer(dir, port)
				if err != nil {
					fmt.Printf("  Cannot bind: %v\n", err)
					break
				}
				stopCh = make(chan struct{})
				go acceptLoop(ln, dir, stopCh)
				fmt.Printf("  Saving to: %s\n", dir)
			} else {
				fmt.Printf("  Saving to: %s\n", dir)
			}
		case "quiet":
			quiet = !quiet
			fmt.Printf("  Quiet mode: %v\n", quiet)
		default:
			fmt.Printf("  Unknown command: '%s'  (type 'help')\n", cmd)
		}
	}

done:
	close(stopCh)
	ln.Close()
	disc.Stop()
	fmt.Println("\nBye.")
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI / ENTRY POINT
// ─────────────────────────────────────────────────────────────────────────────

func usage() {
	fmt.Println(`LDT -- Local Data Transfer (Go edition)
Same protocol as ldt.py — fully interoperable.

Usage:
  ldt <name>                            Interactive mode (recommended)
  ldt <name> receive [--dir DIR]        Receive-only mode
  ldt <name> send <target> <path>...    Send one-shot
  ldt <name> peers [--wait N]           List peers

Options:
  --port N     UDP/TCP port (default 9900)
  --dir DIR    Save directory (default ./received)
  --workers N  Parallel TCP connections for send
  --wait N     Peer scan time in seconds (default 3)

Examples:
  ldt Alice
  ldt Bob send Alice video.mp4
  ldt Bob send Alice ./project --workers 4`)
}

func getFlag(args []string, name string, def string) (string, []string) {
	for i, a := range args {
		if a == name && i+1 < len(args) {
			return args[i+1], append(args[:i:i], args[i+2:]...)
		}
	}
	return def, args
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		usage()
		return
	}

	myName := args[0]
	args = args[1:]

	portStr, args := getFlag(args, "--port", strconv.Itoa(tcpPort))
	port, _ := strconv.Atoi(portStr)
	if port == 0 {
		port = tcpPort
	}

	if len(args) == 0 {
		dirStr, _ := getFlag(args, "--dir", "./received")
		runInteractive(myName, port, dirStr)
		return
	}

	cmd := strings.ToLower(args[0])
	args = args[1:]

	switch cmd {
	case "receive":
		dirStr, _ := getFlag(args, "--dir", "./received")
		dir, _ := filepath.Abs(dirStr)
		os.MkdirAll(dir, 0755)

		disc := newDiscovery(myName, port)
		disc.Start()
		ln, err := startServer(dir, port)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot bind port %d: %v\n", port, err)
			os.Exit(1)
		}
		stopCh := make(chan struct{})
		fmt.Printf("LDT  |  %s  |  port %d  |  saving to %s\n", myName, port, dir)
		fmt.Println("Waiting for transfers... (Ctrl-C to stop)\n")
		go acceptLoop(ln, dir, stopCh)
		// Wait forever
		select {}

	case "send":
		workersStr, args := getFlag(args, "--workers", "1")
		workers, _ := strconv.Atoi(workersStr)
		if workers < 1 {
			workers = 1
		}
		quiet := false
		for i, a := range args {
			if a == "--quiet" {
				quiet = true
				args = append(args[:i], args[i+1:]...)
				break
			}
		}
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: ldt <name> send <target> <path> [<path>...]")
			os.Exit(1)
		}
		target, paths := args[0], args[1:]

		entries, err := collectEntries(paths)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		disc := newDiscovery(myName, port)
		disc.Start()
		disc.Query()

		var peer *Peer
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if peer = disc.Find(target); peer != nil {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}

		var host string
		var rport int
		if peer != nil {
			host, rport = peer.Host, peer.Port
			fmt.Printf("Found %s at %s:%d\n", peer.Name, host, rport)
		} else {
			host, rport = target, port
			fmt.Printf("Peer '%s' not found — trying %s:%d\n", target, host, rport)
		}

		total := int64(0)
		for _, e := range entries {
			total += e.Size
		}
		if workers > len(entries) {
			workers = len(entries)
		}
		suffix := ""
		if workers > 1 {
			suffix = fmt.Sprintf("  [workers=%d]", workers)
		}
		fmt.Printf("Sending %d file(s)  (%s)  -> %s:%d%s\n\n",
			len(entries), strings.TrimSpace(fmtSize(float64(total))), host, rport, suffix)

		t0 := time.Now()
		var sendErr error
		if workers <= 1 {
			c, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, rport), 15*time.Second)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Cannot connect: %v\n", err)
				disc.Stop()
				os.Exit(1)
			}
			tc := c.(*net.TCPConn)
			bw := bufio.NewWriterSize(tc, sockBuf)
			sendErr = sendSession(tc, entries, myName, quiet, 0, 0)
			if sendErr == nil {
				sendErr = finishSession(tc, bw)
			}
			tc.Close()
		} else {
			sendErr = sendParallel(entries, host, rport, myName, workers, quiet)
		}

		disc.Stop()
		if sendErr != nil {
			fmt.Fprintf(os.Stderr, "\nTransfer failed: %v\n", sendErr)
			os.Exit(1)
		}
		dt := time.Since(t0).Seconds()
		speed := float64(total) / dt
		fmt.Printf("\nDone  %s in %s  (%s/s avg)\n",
			strings.TrimSpace(fmtSize(float64(total))), fmtTime(dt), strings.TrimSpace(fmtSize(speed)))

	case "peers":
		waitStr, _ := getFlag(args, "--wait", "3")
		waitSec, _ := strconv.ParseFloat(waitStr, 64)
		if waitSec < 1 {
			waitSec = 3
		}
		disc := newDiscovery(myName, port)
		disc.Start()
		disc.Query()
		fmt.Printf("Scanning for %.0fs ...\n", waitSec)
		time.Sleep(time.Duration(waitSec * float64(time.Second)))
		found := disc.Peers()
		disc.Stop()
		if len(found) == 0 {
			fmt.Println("No peers found.")
			return
		}
		fmt.Printf("\n  %-20s  %-16s  PORT\n", "NAME", "IP")
		fmt.Println("  " + strings.Repeat("-", 44))
		for _, p := range found {
			fmt.Printf("  %-20s  %-16s  %d\n", p.Name, p.Host, p.Port)
		}
		fmt.Println()

	default:
		// Unknown command — run interactive with this as first command?
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		usage()
		os.Exit(1)
	}

	_ = runtime.GOOS // suppress unused import
}
