/*
 * SPDX-FileCopyrightText: © Hypermode Inc. <hello@hypermode.com>
 * SPDX-License-Identifier: Apache-2.0
 */

package badger

import (
	"bufio"
	"bytes"
	"crypto/aes"
	cryptorand "crypto/rand"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/pkg/errors"

	"github.com/dgraph-io/badger/v4/pb"
	"github.com/dgraph-io/badger/v4/skl"
	"github.com/dgraph-io/badger/v4/y"
	"github.com/dgraph-io/ristretto/v2/z"
)

// memTable structure stores a skiplist and a corresponding WAL. Writes to memTable are written
// both to the WAL and the skiplist. On a crash, the WAL is replayed to bring the skiplist back to
// its pre-crash form.
type memTable struct {
	// TODO: Give skiplist z.Calloc'd []byte.
	sl         *skl.Skiplist
	wal        *logFile
	maxVersion uint64
	opt        Options
	buf        *bytes.Buffer
}
const memFileExt string = ".mem"

// UNDERSTOOD

func (db *DB) openMemTables(opt Options) error {
	// We don't need to open any tables in in-memory mode.
	if db.opt.InMemory {
		return nil
	}
	files, err := os.ReadDir(db.opt.Dir)
	if err != nil {
		return errFile(err, db.opt.Dir, "Unable to open mem dir.")
	}

	var fids []int
	// finds all the ids of the files are ending with .mem
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), memFileExt) {
			continue
		}
		fsz := len(file.Name())
		fid, err := strconv.ParseInt(file.Name()[:fsz-len(memFileExt)], 10, 64)
		if err != nil {
			return errFile(err, file.Name(), "Unable to parse log id.")
		}
		fids = append(fids, int(fid))
	}

	// Sort in ascending order.
	sort.Slice(fids, func(i, j int) bool {
		return fids[i] < fids[j]
	})
	for _, fid := range fids {
		flags := os.O_RDWR
		if db.opt.ReadOnly {
			flags = os.O_RDONLY
		}
		mt, err := db.openMemTable(fid, flags)
		if err != nil {
			return y.Wrapf(err, "while opening fid: %d", fid)
		}
		// If this memtable is empty we don't need to add it. This is a
		// memtable that was completely truncated.
		if mt.sl.Empty() {
			mt.DecrRef()
			continue
		}
		// These should no longer be written to. So, make them part of the imm.
		db.imm = append(db.imm, mt)
	}
	if len(fids) != 0 {
		db.nextMemFid = fids[len(fids)-1]
	}
	db.nextMemFid++
	return nil
}
// UNDERSTOOD

func (db *DB) openMemTable(fid, flags int) (*memTable, error) {
	filepath := db.mtFilePath(fid)
	// initializes the skiplist-> dont know what arena is , but i guess skiplist internals dont matter too much
	s := skl.NewSkiplist(arenaSize(db.opt))
	mt := &memTable{
		sl:  s,
		opt: db.opt,
		buf: &bytes.Buffer{},
	}

	// We don't need to create the wal for the skiplist in in-memory mode so return the mt.
	if db.opt.InMemory {
		return mt, z.NewFile
	}

	// intialize the logfile , we are passing in the keyRegistry for the logFile for encryption
	mt.wal = &logFile{
		fid:      uint32(fid),
		path:     filepath,
		registry: db.registry,
		writeAt:  vlogHeaderSize, // why are we passing in this??
		opt:      db.opt,
	}
	// WAL file is 2*MemTableSize->cuz we are logging both key and value?? Not sure
	lerr := mt.wal.open(filepath, flags, 2*db.opt.MemTableSize)
	if lerr != z.NewFile && lerr != nil {
		return nil, y.Wrapf(lerr, "While opening memtable: %s", filepath)
	}

	// Have a callback set to delete WAL when skiplist reference count goes down to zero. That is,
	// when it gets flushed to L0.
	s.OnClose = func() {
		if err := mt.wal.Delete(); err != nil {
			db.opt.Errorf("while deleting file: %s, err: %v", filepath, err)
		}
	}

	if lerr == z.NewFile {
		return mt, lerr
	}
	// initializes the skiplist
	err := mt.UpdateSkipList()
	return mt, y.Wrapf(err, "while updating skiplist")
}


// UNDERSTOOD

// Opens a newMenTable with the current nextMemFid and then increases the fid
// if any other error other than NewFile is returned from the openMemTable function, 
// then a call to this function has caused an error
func (db *DB) newMemTable() (*memTable, error) {
	mt, err := db.openMemTable(db.nextMemFid, os.O_CREATE|os.O_RDWR)
	if err == z.NewFile {
		db.nextMemFid++
		return mt, nil
	}

	if err != nil {
		db.opt.Errorf("Got error: %v for id: %d\n", err, db.nextMemFid)
		return nil, y.Wrapf(err, "newMemTable")
	}
	return nil, errors.Errorf("File %s already exists", mt.wal.Fd.Name())
}
// UNDERSTOOD

// just gives us back the filepath
func (db *DB) mtFilePath(fid int) string {
	return filepath.Join(db.opt.Dir, fmt.Sprintf("%05d%s", fid, memFileExt))
}
// UNDERSTOOD

// calls msync on the mmapped data , however on windows this doesnt have any implementation
func (mt *memTable) SyncWAL() error {
	return mt.wal.Sync()
}
// UNDERSTOOD

func (mt *memTable) isFull() bool {
	if mt.sl.MemSize() >= mt.opt.MemTableSize {
		return true
	}
	if mt.opt.InMemory {
		// InMemory mode doesn't have any WAL.
		return false
	}
	return int64(mt.wal.writeAt) >= mt.opt.MemTableSize
}

// Called by db.writeToLsm for insertion into the memtable 
// the value paramter is passed to us by the db so i will have to unerstand it from there
func (mt *memTable) Put(key []byte, value y.ValueStruct) error {  // UNDERSTOOD
	entry := &Entry{
		Key:       key,
		Value:     value.Value,
		UserMeta:  value.UserMeta,
		meta:      value.Meta,
		ExpiresAt: value.ExpiresAt,
	}

	// wal is nil only when badger in running in in-memory mode and we don't need the wal.
	if mt.wal != nil {
		// If WAL exceeds opt.ValueLogFileSize, we'll force flush the memTable. See logic in
		// ensureRoomForWrite.
		// inserts the entry into the WAL
		if err := mt.wal.writeEntry(mt.buf, entry, mt.opt); err != nil {
			return y.Wrapf(err, "cannot write entry to WAL file")
		}
	}
	// We insert the finish marker in the WAL but not in the memtable.
	// if the entry indicates the end of a transaction we do not have to 
	// insert it into the skiplist
	if entry.meta&bitFinTxn > 0 {
		return nil
	}

	// Write to skiplist and update maxVersion encountered.
	mt.sl.Put(key, value)
	if ts := y.ParseTs(entry.Key); ts > mt.maxVersion {
		// updates the maxVersion which is obtained from the key
		// why are we doing this ??
		mt.maxVersion = ts
	}
	y.NumBytesWrittenToL0Add(mt.opt.MetricsEnabled, entry.estimateSizeAndSetThreshold(mt.opt.ValueThreshold))
	return nil
}

// UNDERSTOOD

// Iterates over the logfile and updates the skiplist
// when we update over the logfile we will get to know till what offset contains 
// valid entries and we will return that offset and truncate the logfile till that offset
func (mt *memTable) UpdateSkipList() error {
	if mt.wal == nil || mt.sl == nil {
		return nil
	}
	endOff, err := mt.wal.iterate(true, 0, mt.replayFunction(mt.opt))
	if err != nil {
		return y.Wrapf(err, "while iterating wal: %s", mt.wal.Fd.Name())
	}
	if endOff < mt.wal.size.Load() && mt.opt.ReadOnly {
		return y.Wrapf(ErrTruncateNeeded, "end offset: %d < size: %d", endOff, mt.wal.size.Load())
	}
	return mt.wal.Truncate(int64(endOff))
}

// UNDERSTOOD

// IncrRef increases the refcount
func (mt *memTable) IncrRef() {
	mt.sl.IncrRef()
}

// UNDERSTOOD

// DecrRef decrements the refcount, deallocating the Skiplist when done using it
func (mt *memTable) DecrRef() {
	mt.sl.DecrRef()
}

func (mt *memTable) replayFunction(opt Options) func(Entry, valuePointer) error {
	first := true
	return func(e Entry, _ valuePointer) error { // Function for replaying.
		if first {
			opt.Debugf("First key=%q\n", e.Key)
		}
		first = false
		if ts := y.ParseTs(e.Key); ts > mt.maxVersion {
			mt.maxVersion = ts
		}
		v := y.ValueStruct{
			Value:     e.Value,
			Meta:      e.meta,
			UserMeta:  e.UserMeta,
			ExpiresAt: e.ExpiresAt,
		}
		// This is already encoded correctly. Value would be either a vptr, or a full value
		// depending upon how big the original value was. Skiplist makes a copy of the key and
		// value.
		mt.sl.Put(e.Key, v)
		return nil
	}
}

type logFile struct {
	*z.MmapFile
	path string
	// This is a lock on the log file. It guards the fd’s value, the file’s
	// existence and the file’s memory map.
	//
	// Use shared ownership when reading/writing the file or memory map, use
	// exclusive ownership to open/close the descriptor, unmap or remove the file.
	lock     sync.RWMutex
	fid      uint32
	size     atomic.Uint32
	dataKey  *pb.DataKey
	baseIV   []byte
	registry *KeyRegistry
	writeAt  uint32
	opt      Options
}

// truncates the mmap file
// Truncate would truncate the mmapped file to the given size. On Linux, we truncate
// the underlying file and then call mremap, but on other systems, we unmap first,
// then truncate, then re-map.
func (lf *logFile) Truncate(end int64) error { // UNDERSTOOD

	if fi, err := lf.Fd.Stat(); err != nil {
		return fmt.Errorf("while file.stat on file: %s, error: %v\n", lf.Fd.Name(), err)
	} else if fi.Size() == end {
		return nil
	}
	y.AssertTrue(!lf.opt.ReadOnly)
	lf.size.Store(uint32(end))
	return lf.MmapFile.Truncate(end)
}

// this is pretty complex
// encodeEntry will encode entry to the buf
// layout of entry
// +--------+-----+-------+-------+
// | header | key | value | crc32 |
// +--------+-----+-------+-------+
// Original Entry: [Header | Key | Value | CRC32(1234)]
// Corrupted Entry: [Header | Key | Altered Value | CRC32(5678)]
// Validation will fail because the CRC won't match
func (lf *logFile) encodeEntry(buf *bytes.Buffer, e *Entry, offset uint32) (int, error) { // UNDERSTOOD

	// header is 18 bytes
	h := header{
		klen:      uint32(len(e.Key)),
		vlen:      uint32(len(e.Value)),
		expiresAt: e.ExpiresAt,
		meta:      e.meta,
		userMeta:  e.UserMeta,
	}

	hash := crc32.New(y.CastagnoliCrcTable)
	writer := io.MultiWriter(buf, hash)

	// encode header.
	var headerEnc [maxHeaderSize]byte
	sz := h.Encode(headerEnc[:])

	// writes it into the hash as well as the buffer
	y.Check2(writer.Write(headerEnc[:sz]))
	// we'll encrypt only key and value.
	if lf.encryptionEnabled() {
		// 		Key Decryption Principles:
		// Use the EXACT same key (lf.dataKey.Data)
		// Regenerate the IV using the same offset
		// Use XORBlockStream in the same way as encryption
		// Symmetrical process - same method used for both encryption and decryption

		// TODO: no need to allocate the bytes. we can calculate the encrypted buf one by one
		// since we're using ctr mode of AES encryption. Ordering won't changed. Need some
		// refactoring in XORBlock which will work like stream cipher.
		eBuf := make([]byte, 0, len(e.Key)+len(e.Value))
		eBuf = append(eBuf, e.Key...)
		eBuf = append(eBuf, e.Value...)
		// currently eBuf contains the key and value without it being encrypted
		if err := y.XORBlockStream(
			// the offset being passed here is the previous lf.writeAt
			writer, eBuf, lf.dataKey.Data, lf.generateIV(offset)); err != nil {
			return 0, y.Wrapf(err, "Error while encoding entry for vlog.")
		}
	} else {
		// Encryption is disabled so writing directly to the buffer.
		y.Check2(writer.Write(e.Key))
		y.Check2(writer.Write(e.Value))
	}
	// write crc32 hash.
	var crcBuf [crc32.Size]byte
	binary.BigEndian.PutUint32(crcBuf[:], hash.Sum32())
	y.Check2(buf.Write(crcBuf[:]))
	// return encoded length.
	return len(headerEnc[:sz]) + len(e.Key) + len(e.Value) + len(crcBuf), nil
}

// writes the entry into the wal, called before we insert the entry in the memtable
// encodes the entry and then writes it into the wal
// since the wal file is memory mapped into a buffer we just need to copy it into the buffer
// we have a lf.writeAt which tells us till where the buffer is full and we increase the writeAt
// by how many bytes we have just written
func (lf *logFile) writeEntry(buf *bytes.Buffer, e *Entry, opt Options) error { // UNDERSTOOD

	buf.Reset()
	// encodes the entry
	plen, err := lf.encodeEntry(buf, e, lf.writeAt)
	if err != nil {
		return err
	}
	// copies it into the mmap buffer
	y.AssertTrue(plen == copy(lf.Data[lf.writeAt:], buf.Bytes()))
	lf.writeAt += uint32(plen)

	lf.zeroNextEntry()
	return nil
}


// the offset passed in here has to be the same as the offset where the write happened
// as that offset is used for encryption
func (lf *logFile) decodeEntry(buf []byte, offset uint32) (*Entry, error) { // UNDERSTOOD
	var h header
	// decodes the header initally
	hlen := h.Decode(buf)
	kv := buf[hlen:]
	if lf.encryptionEnabled() {
		var err error
		// No need to worry about mmap. because, XORBlock allocates a byte array to do the
		// xor. So, the given slice is not being mutated.
		// symmetric encryption and decryption so it can be handled
		// by calling the same encryption function
		if kv, err = lf.decryptKV(kv, offset); err != nil {
			return nil, err
		}
	}
	e := &Entry{
		meta:      h.meta,
		UserMeta:  h.userMeta,
		ExpiresAt: h.expiresAt,
		offset:    offset,
		Key:       kv[:h.klen],
		Value:     kv[h.klen : h.klen+h.vlen],
	}
	return e, nil
}


func (lf *logFile) decryptKV(buf []byte, offset uint32) ([]byte, error) { // UNDERSTOOD
	return y.XORBlockAllocate(buf, lf.dataKey.Data, lf.generateIV(offset))
}


// KeyID returns datakey's ID.
func (lf *logFile) keyID() uint64 { // UNDERSTOOD
	if lf.dataKey == nil {
		// If there is no datakey, then we'll return 0. Which means no encryption.
		return 0
	}
	return lf.dataKey.KeyId
}

func (lf *logFile) encryptionEnabled() bool { // UNDERSTOOD
	return lf.dataKey != nil
}

// Acquire lock on mmap/file if you are calling this
func (lf *logFile) read(p valuePointer) (buf []byte, err error) { // UNDERSTOOD
	offset := p.Offset
	// Do not convert size to uint32, because the lf.Data can be of size
	// 4GB, which overflows the uint32 during conversion to make the size 0,
	// causing the read to fail with ErrEOF. See issue #585.
	size := int64(len(lf.Data))
	valsz := p.Len
	lfsz := lf.size.Load()
	if int64(offset) >= size || int64(offset+valsz) > size ||
		// Ensure that the read is within the file's actual size. It might be possible that
		// the offset+valsz length is beyond the file's actual size. This could happen when
		// dropAll and iterations are running simultaneously.
		int64(offset+valsz) > int64(lfsz) {
		err = y.ErrEOF
	} else {
		buf = lf.Data[offset : offset+valsz]
	}
	return buf, err
}

// generateIV will generate IV by appending given offset with the base IV.
func (lf *logFile) generateIV(offset uint32) []byte { // UNDERSTOOD

	iv := make([]byte, aes.BlockSize)
	// baseIV is of 12 bytes.
	y.AssertTrue(12 == copy(iv[:12], lf.baseIV))
	// remaining 4 bytes is obtained from offset.
	binary.BigEndian.PutUint32(iv[12:], offset)
	return iv
}

// once we call this function it basically indicates we are done using this log file
// we sync the directory to which the logfile belongs if the SyncWrites option is true
// we also truncate the file to the offset specified
func (lf *logFile) doneWriting(offset uint32) error { // UNDERSTOOD
	if lf.opt.SyncWrites {
		if err := lf.Sync(); err != nil {
			return y.Wrapf(err, "Unable to sync value log: %q", lf.path)
		}
	}

	// Before we were acquiring a lock here on lf.lock, because we were invalidating the file
	// descriptor due to reopening it as read-only. Now, we don't invalidate the fd, but unmap it,
	// truncate it and remap it. That creates a window where we have segfaults because the mmap is
	// no longer valid, while someone might be reading it. Therefore, we need a lock here again.
	lf.lock.Lock()
	defer lf.lock.Unlock()

	// truncate the file to the offset specified
	if err := lf.Truncate(int64(offset)); err != nil {
		return y.Wrapf(err, "Unable to truncate file: %q", lf.path)
	}

	// Previously we used to close the file after it was written and reopen it in read-only mode.
	// We no longer open files in read-only mode. We keep all vlog files open in read-write mode.
	return nil
}

// iterate iterates over log file. It doesn't not allocate new memory for every kv pair.
// Therefore, the kv pair is only valid for the duration of fn call.
func (lf *logFile) iterate(readOnly bool, offset uint32, fn logEntry) (uint32, error) {
	if offset == 0 {
		// If offset is set to zero, let's advance past the encryption key header.
		offset = vlogHeaderSize
	}

	// For now, read directly from file, because it allows
	// lf.NewReader returns an mmapReader which just reads from the mmap Buffer
	reader := bufio.NewReader(lf.NewReader(int(offset)))
	read := &safeRead{
		k:            make([]byte, 10),
		v:            make([]byte, 10),
		recordOffset: offset,
		lf:           lf,
	}

	var lastCommit uint64
	var validEndOffset uint32 = offset

	var entries []*Entry
	var vptrs []valuePointer

loop:
	for {
		e, err := read.Entry(reader)
		switch {
		// We have not reached the end of the file but the entry we read is
		// zero. This happens because we have truncated the file and
		// zero'ed it out.
		case err == io.EOF:
			break loop
		case err == io.ErrUnexpectedEOF || err == errTruncate:
			break loop
		case err != nil:
			return 0, err
		case e == nil:
			continue
		case e.isZero():
			break loop
		}

		var vp valuePointer
		vp.Len = uint32(e.hlen + len(e.Key) + len(e.Value) + crc32.Size)
		read.recordOffset += vp.Len

		vp.Offset = e.offset
		vp.Fid = lf.fid

		switch {
		case e.meta&bitTxn > 0:
			txnTs := y.ParseTs(e.Key)
			if lastCommit == 0 {
				lastCommit = txnTs
			}
			if lastCommit != txnTs {
				break loop
			}
			entries = append(entries, e)
			vptrs = append(vptrs, vp)

		case e.meta&bitFinTxn > 0:
			txnTs, err := strconv.ParseUint(string(e.Value), 10, 64)
			if err != nil || lastCommit != txnTs {
				break loop
			}
			// Got the end of txn. Now we can store them.
			lastCommit = 0
			validEndOffset = read.recordOffset

			for i, e := range entries {
				vp := vptrs[i]
				if err := fn(*e, vp); err != nil {
					if err == errStop {
						break
					}
					return 0, errFile(err, lf.path, "Iteration function")
				}
			}
			entries = entries[:0]
			vptrs = vptrs[:0]

		default:
			if lastCommit != 0 {
				// This is most likely an entry which was moved as part of GC.
				// We shouldn't get this entry in the middle of a transaction.
				break loop
			}
			validEndOffset = read.recordOffset

			if err := fn(*e, vp); err != nil {
				if err == errStop {
					break
				}
				return 0, errFile(err, lf.path, "Iteration function")
			}
		}
	}
	return validEndOffset, nil
}

// UNDERSTOOD

// Zero out the next entry to deal with any crashes.
// ZeroOut zeroes out all the bytes in the range [start, end).
func (lf *logFile) zeroNextEntry() {
	z.ZeroOut(lf.Data, int(lf.writeAt), int(lf.writeAt+maxHeaderSize))
}

// UNDERSTOOD

// Used for both WAL logging are for vLogs
func (lf *logFile) open(path string, flags int, fsize int64) error {

	// going to be opening the file in READ_ONLY OR READ_WRITE MODE
	/*
	I'll explain the memory-mapped file (mmap) function in detail:
	This is a Windows-specific implementation of memory-mapped file functionality in Go. 
	Memory-mapped files allow you to treat a file as if it were loaded directly into memory, 
	which can provide significant performance benefits for large file operations.
	Let's break down the key aspects of this function:

	File Mapping Process
	
	Uses Windows-specific syscalls:
	CreateFileMapping() to create a file mapping object
	MapViewOfFile() to map the file view into memory
	CloseHandle() to close the mapping handle
	
	Memory Conversion
	Uses unsafe pointer manipulation to convert the memory mapping into a Go byte slice
	
	Common Use Cases for Memory-Mapped Files
	Large File Processing
	Efficiently read or write large files without loading entire contents into memory
	Useful for log files, databases, or large datasets
	
	Performance Optimization
	Reduces system call overhead
	Allows direct memory access to file contents
	Can be faster than traditional file I/O methods

	On a lower level we get a pointer to the file Address and the os 
	reserves part of the virtual address space, but doesnt load the file into that space
	until we actually need it for reading or writing
	When we first request it there will be a page fault and it will be fetched from disk and 
	the mapping will be added in the virtualPage->physicalPage mapping 
	it will also be added in the TLB which will accelerate future repeat accesses
	So we can sit back and let the os do a heavy lifting

    Each virtual page maps to a physical page which exists on disk
	In traditional files each write/read to a file would be a separate system call 
	requiring a context switch which is a little bit slow.
	In mmap we just need the initial system calls and then we map the whole file into
	separate addresses of memory, u just need to keep track of the offset 

	Problems
	1.Transactional Safety
	a)OS can flush dirty pages at any time
	b)We dont get any warning about this and cant prevent it from happening
	2.I/O Stalls
	a)You dont know which pages are in memory
	b) Reading any pafe can cause an I/O stall
	3.Error Handling
	4.Performance Issues
	*/
	mf, ferr := z.OpenMmapFile(path, flags, int(fsize))
	lf.MmapFile = mf

	if ferr == z.NewFile {
		if err := lf.bootstrap(); err != nil {
			os.Remove(path)
			return err
		}
		// increases the logFile size-> size is an atomic variable
		lf.size.Store(vlogHeaderSize)

	} else if ferr != nil {
		return y.Wrapf(ferr, "while opening file: %s", path)
	}
	// if the file is not new then it already has all the data and the file size can be easily initialized
	lf.size.Store(uint32(len(lf.Data)))

	if lf.size.Load() < vlogHeaderSize {
		// Every vlog file should have at least vlogHeaderSize. If it is less than vlogHeaderSize
		// then it must have been corrupted. But no need to handle here. log replayer will truncate
		// and bootstrap the logfile. So ignoring here.
		return nil
	}

	// The below code VALIDATES ALL THE ENCRYPTION KEYS AND THE HEADERS 

	// Copy over the encryption registry data.
	buf := make([]byte, vlogHeaderSize)

	y.AssertTruef(vlogHeaderSize == copy(buf, lf.Data),
		"Unable to copy from %s, size %d", path, lf.size.Load())
	keyID := binary.BigEndian.Uint64(buf[:8])
	// retrieve datakey.
	if dk, err := lf.registry.DataKey(keyID); err != nil {
		return y.Wrapf(err, "While opening vlog file %d", lf.fid)
	} else {
		lf.dataKey = dk
	}

	// sets the baseIv
	lf.baseIV = buf[8:]
	y.AssertTrue(len(lf.baseIV) == 12)

	// Preserved ferr so we can return if this was a new file.
	return ferr
}

// UNDERSTOOD

// bootstrap will initialize the log file with key id and baseIV.
// The below figure shows the layout of log file.
// +----------------+------------------+------------------+
// | keyID(8 bytes) |  baseIV(12 bytes)|	 entry...     |
// +----------------+------------------+------------------+
func (lf *logFile) bootstrap() error {
	var err error

	// generate data key for the log file.
	var dk *pb.DataKey
	// gets the latest encryption key
	if dk, err = lf.registry.LatestDataKey(); err != nil {
		return y.Wrapf(err, "Error while retrieving datakey in logFile.bootstarp")
	}
	lf.dataKey = dk

	// We'll always preserve vlogHeaderSize for key id and baseIV.
	buf := make([]byte, vlogHeaderSize)

	// write key id to the buf.
	// key id will be zero if the logfile is in plain text.
	binary.BigEndian.PutUint64(buf[:8], lf.keyID())
	// generate base IV. It'll be used with offset of the vptr to encrypt the entry.
	if _, err := cryptorand.Read(buf[8:]); err != nil {
		return y.Wrapf(err, "Error while creating base IV, while creating logfile")
	}

	// Initialize base IV.
	lf.baseIV = buf[8:]
	y.AssertTrue(len(lf.baseIV) == 12)

	// Copy over to the logFile.
	y.AssertTrue(vlogHeaderSize == copy(lf.Data[0:], buf))

	// Zero out the next entry.
	lf.zeroNextEntry()
	return nil
}
