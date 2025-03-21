/*
 * SPDX-FileCopyrightText: © Hypermode Inc. <hello@hypermode.com>
 * SPDX-License-Identifier: Apache-2.0
 */

package badger

import (
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/dgraph-io/badger/v4/options"
	"github.com/dgraph-io/badger/v4/table"
	"github.com/dgraph-io/badger/v4/y"
	"github.com/dgraph-io/ristretto/v2/z"
)

// Note: If you add a new option X make sure you also add a WithX method on Options.

// Options are params for creating DB object.
//
// This package provides DefaultOptions which contains options that should
// work for most applications. Consider using that as a starting point before
// customizing it for your own needs.
//
// Each option X is documented on the WithX method.
type Options struct {
	testOnlyOptions

	// Required options.

	Dir      string
	ValueDir string

	// Usually modified options.

	SyncWrites        bool
	NumVersionsToKeep int
	ReadOnly          bool
	Logger            Logger
	Compression       options.CompressionType
	InMemory          bool
	MetricsEnabled    bool
	// Sets the Stream.numGo field
	NumGoroutines int

	// Fine tuning options.

	MemTableSize        int64
	BaseTableSize       int64
	BaseLevelSize       int64
	LevelSizeMultiplier int
	TableSizeMultiplier int
	MaxLevels           int

	VLogPercentile float64
	ValueThreshold int64
	NumMemtables   int
	// Changing BlockSize across DB runs will not break badger. The block size is
	// read from the block index stored at the end of the table.
	BlockSize          int
	BloomFalsePositive float64
	BlockCacheSize     int64
	IndexCacheSize     int64

	NumLevelZeroTables      int
	NumLevelZeroTablesStall int

	ValueLogFileSize   int64
	ValueLogMaxEntries uint32

	NumCompactors        int
	CompactL0OnClose     bool
	LmaxCompaction       bool
	ZSTDCompressionLevel int

	// When set, checksum will be validated for each entry read from the value log file.
	VerifyValueChecksum bool

	// Encryption related options.
	EncryptionKey                 []byte        // encryption key
	EncryptionKeyRotationDuration time.Duration // key rotation duration

	// BypassLockGuard will bypass the lock guard on badger. Bypassing lock
	// guard can cause data corruption if multiple badger instances are using
	// the same directory. Use this options with caution.
	BypassLockGuard bool

	// ChecksumVerificationMode decides when db should verify checksums for SSTable blocks.
	ChecksumVerificationMode options.ChecksumVerificationMode

	// DetectConflicts determines whether the transactions would be checked for
	// conflicts. The transactions can be processed at a higher rate when
	// conflict detection is disabled.
	DetectConflicts bool

	// NamespaceOffset specifies the offset from where the next 8 bytes contains the namespace.
	NamespaceOffset int

	// Magic version used by the application using badger to ensure that it doesn't open the DB
	// with incompatible data format.
	ExternalMagicVersion uint16

	// Transaction start and commit timestamps are managed by end-user.
	// This is only useful for databases built on top of Badger (like Dgraph).
	// Not recommended for most users.
	managedTxns bool

	// 4. Flags for testing purposes
	// ------------------------------
	maxBatchCount int64 // max entries in batch
	maxBatchSize  int64 // max batch size in bytes

	maxValueThreshold float64
}

// DefaultOptions sets a list of recommended options for good performance.
// Feel free to modify these to suit your needs with the WithX methods.
func DefaultOptions(path string) Options {
	return Options{
		Dir:      path,
		ValueDir: path,

		MemTableSize:        64 << 20,
		BaseTableSize:       2 << 20,
		BaseLevelSize:       10 << 20,
		TableSizeMultiplier: 2,
		LevelSizeMultiplier: 10,
		MaxLevels:           7,
		NumGoroutines:       8,
		MetricsEnabled:      true,

		NumCompactors:           4, // Run at least 2 compactors. Zero-th compactor prioritizes L0.
		NumLevelZeroTables:      5,
		NumLevelZeroTablesStall: 15,
		NumMemtables:            5,
		BloomFalsePositive:      0.01,
		BlockSize:               4 * 1024,
		SyncWrites:              false,
		NumVersionsToKeep:       1,
		CompactL0OnClose:        false,
		VerifyValueChecksum:     false,
		Compression:             options.Snappy,
		BlockCacheSize:          256 << 20,
		IndexCacheSize:          0,

		// The following benchmarks were done on a 4 KB block size (default block size). The
		// compression is ratio supposed to increase with increasing compression level but since the
		// input for compression algorithm is small (4 KB), we don't get significant benefit at
		// level 3.
		// NOTE: The benchmarks are with DataDog ZSTD that requires CGO. Hence, no longer valid.
		// no_compression-16              10	 502848865 ns/op	 165.46 MB/s	-
		// zstd_compression/level_1-16     7	 739037966 ns/op	 112.58 MB/s	2.93
		// zstd_compression/level_3-16     7	 756950250 ns/op	 109.91 MB/s	2.72
		// zstd_compression/level_15-16    1	11135686219 ns/op	   7.47 MB/s	4.38
		// Benchmark code can be found in table/builder_test.go file
		ZSTDCompressionLevel: 1,

		// (2^30 - 1)*2 when mmapping < 2^31 - 1, max int32.
		// -1 so 2*ValueLogFileSize won't overflow on 32-bit systems.
		ValueLogFileSize: 1<<30 - 1,

		ValueLogMaxEntries: 1000000,

		VLogPercentile: 0.0,
		ValueThreshold: maxValueThreshold,

		Logger:                        defaultLogger(INFO),
		EncryptionKey:                 []byte{},
		EncryptionKeyRotationDuration: 10 * 24 * time.Hour, // Default 10 days.
		DetectConflicts:               true,
		NamespaceOffset:               -1,
	}
}

func buildTableOptions(db *DB) table.Options {
	opt := db.opt
	dk, err := db.registry.LatestDataKey()
	y.Check(err)
	return table.Options{
		ReadOnly:             opt.ReadOnly,
		MetricsEnabled:       db.opt.MetricsEnabled,
		TableSize:            uint64(opt.BaseTableSize),
		BlockSize:            opt.BlockSize,
		BloomFalsePositive:   opt.BloomFalsePositive,
		ChkMode:              opt.ChecksumVerificationMode,
		Compression:          opt.Compression,
		ZSTDCompressionLevel: opt.ZSTDCompressionLevel,
		BlockCache:           db.blockCache,
		IndexCache:           db.indexCache,
		AllocPool:            db.allocPool,
		DataKey:              dk,
	}
}

const (
	maxValueThreshold = (1 << 20) // 1 MB
)

// LSMOnlyOptions follows from DefaultOptions, but sets a higher ValueThreshold
// so values would be collocated with the LSM tree, with value log largely acting
// as a write-ahead log only. These options would reduce the disk usage of value
// log, and make Badger act more like a typical LSM tree.
func LSMOnlyOptions(path string) Options {
	// Let's not set any other options, because they can cause issues with the
	// size of key-value a user can pass to Badger. For e.g., if we set
	// ValueLogFileSize to 64MB, a user can't pass a value more than that.
	// Setting it to ValueLogMaxEntries to 1000, can generate too many files.
	// These options are better configured on a usage basis, than broadly here.
	// The ValueThreshold is the most important setting a user needs to do to
	// achieve a heavier usage of LSM tree.
	// NOTE: If a user does not want to set 64KB as the ValueThreshold because
	// of performance reasons, 1KB would be a good option too, allowing
	// values smaller than 1KB to be collocated with the keys in the LSM tree.
	return DefaultOptions(path).WithValueThreshold(maxValueThreshold /* 1 MB */)
}

// parseCompression returns badger.compressionType and compression level given compression string
// of format compression-type:compression-level
func parseCompression(cStr string) (options.CompressionType, int, error) {
	cStrSplit := strings.Split(cStr, ":")
	cType := cStrSplit[0]
	level := 3

	var err error
	if len(cStrSplit) == 2 {
		level, err = strconv.Atoi(cStrSplit[1])
		y.Check(err)
		if level <= 0 {
			return 0, 0,
				errors.Errorf("ERROR: compression level(%v) must be greater than zero", level)
		}
	} else if len(cStrSplit) > 2 {
		return 0, 0, errors.Errorf("ERROR: Invalid badger.compression argument")
	}
	switch cType {
	case "zstd":
		return options.ZSTD, level, nil
	case "snappy":
		return options.Snappy, 0, nil
	case "none":
		return options.None, 0, nil
	}
	return 0, 0, errors.Errorf("ERROR: compression type (%s) invalid", cType)
}

// generateSuperFlag generates an identical SuperFlag string from the provided Options.
func generateSuperFlag(options Options) string {
	superflag := ""
	v := reflect.ValueOf(&options).Elem()
	optionsStruct := v.Type()
	for i := 0; i < v.NumField(); i++ {
		if field := v.Field(i); field.CanInterface() {
			name := strings.ToLower(optionsStruct.Field(i).Name)
			kind := v.Field(i).Kind()
			switch kind {
			case reflect.Bool:
				superflag += name + "="
				superflag += fmt.Sprintf("%v; ", field.Bool())
			case reflect.Int, reflect.Int64:
				superflag += name + "="
				superflag += fmt.Sprintf("%v; ", field.Int())
			case reflect.Uint32, reflect.Uint64:
				superflag += name + "="
				superflag += fmt.Sprintf("%v; ", field.Uint())
			case reflect.Float64:
				superflag += name + "="
				superflag += fmt.Sprintf("%v; ", field.Float())
			case reflect.String:
				superflag += name + "="
				superflag += fmt.Sprintf("%v; ", field.String())
			default:
				continue
			}
		}
	}
	return superflag
}

// FromSuperFlag fills Options fields for each flag within the superflag. For
// example, replacing the default Options.NumGoroutines:
//
//	options := FromSuperFlag("numgoroutines=4", DefaultOptions(""))
//
// It's important to note that if you pass an empty Options struct, FromSuperFlag
// will not fill it with default values. FromSuperFlag only writes to the fields
// present within the superflag string (case insensitive).
//
// It specially handles compression subflag.
// Valid options are {none,snappy,zstd:<level>}
// Example: compression=zstd:3;
// Unsupported: Options.Logger, Options.EncryptionKey
func (opt Options) FromSuperFlag(superflag string) Options {
	// currentOptions act as a default value for the options superflag.
	currentOptions := generateSuperFlag(opt)
	currentOptions += "compression=;"

	flags := z.NewSuperFlag(superflag).MergeAndCheckDefault(currentOptions)
	v := reflect.ValueOf(&opt).Elem()
	optionsStruct := v.Type()
	for i := 0; i < v.NumField(); i++ {
		// only iterate over exported fields
		if field := v.Field(i); field.CanInterface() {
			// z.SuperFlag stores keys as lowercase, keep everything case
			// insensitive
			name := strings.ToLower(optionsStruct.Field(i).Name)
			if name == "compression" {
				// We will specially handle this later. Skip it here.
				continue
			}
			kind := v.Field(i).Kind()
			switch kind {
			case reflect.Bool:
				field.SetBool(flags.GetBool(name))
			case reflect.Int, reflect.Int64:
				field.SetInt(flags.GetInt64(name))
			case reflect.Uint32, reflect.Uint64:
				field.SetUint(flags.GetUint64(name))
			case reflect.Float64:
				field.SetFloat(flags.GetFloat64(name))
			case reflect.String:
				field.SetString(flags.GetString(name))
			}
		}
	}

	// Only update the options for special flags that were present in the input superflag.
	inputFlag := z.NewSuperFlag(superflag)
	if inputFlag.Has("compression") {
		ctype, clevel, err := parseCompression(flags.GetString("compression"))
		switch err {
		case nil:
			opt.Compression = ctype
			opt.ZSTDCompressionLevel = clevel
		default:
			ctype = options.CompressionType(flags.GetUint32("compression"))
			y.AssertTruef(ctype <= 2, "ERROR: Invalid format or compression type. Got: %s",
				flags.GetString("compression"))
			opt.Compression = ctype
		}
	}

	return opt
}

/*
Keys and values are written in separate directories in BadgerDb
the path where keys are written is given by opt.Dir and the path where
the vlues are written is given by opt.ValueDir
*/

// WithDir returns a new Options value with Dir set to the given value.
//
// Dir is the path of the directory where key data will be stored in.
// If it doesn't exist, Badger will try to create it for you.
// This is set automatically to be the path given to `DefaultOptions`.
func (opt Options) WithDir(val string) Options {
	opt.Dir = val
	return opt
}

// WithValueDir returns a new Options value with ValueDir set to the given value.
//
// ValueDir is the path of the directory where value data will be stored in.
// If it doesn't exist, Badger will try to create it for you.
// This is set automatically to be the path given to `DefaultOptions`.
func (opt Options) WithValueDir(val string) Options {
	opt.ValueDir = val
	return opt
}

// WithSyncWrites returns a new Options value with SyncWrites set to the given value.
//
// Badger does all writes via mmap. So, all writes can survive process crashes or k8s environments
// with SyncWrites set to false.
//
// When set to true, Badger would call an additional msync after writes to flush mmap buffer over to
// disk to survive hard reboots. Most users of Badger should not need to do this.
//
// The default value of SyncWrites is false.
func (opt Options) WithSyncWrites(val bool) Options {
	opt.SyncWrites = val
	return opt
}

// WithNumVersionsToKeep returns a new Options value with NumVersionsToKeep set to the given value.
//
// NumVersionsToKeep sets how many versions to keep per key at most.
//
// The default value of NumVersionsToKeep is 1.
func (opt Options) WithNumVersionsToKeep(val int) Options {
	opt.NumVersionsToKeep = val
	return opt
}

// WithNumGoroutines sets the number of goroutines to be used in Stream.
//
// The default value of NumGoroutines is 8.
func (opt Options) WithNumGoroutines(val int) Options {
	opt.NumGoroutines = val
	return opt
}

// WithReadOnly returns a new Options value with ReadOnly set to the given value.
//
// When ReadOnly is true the DB will be opened on read-only mode.
// Multiple processes can open the same Badger DB.
// Note: if the DB being opened had crashed before and has vlog data to be replayed,
// ReadOnly will cause Open to fail with an appropriate message.
//
// The default value of ReadOnly is false.
func (opt Options) WithReadOnly(val bool) Options {
	opt.ReadOnly = val
	return opt
}

// WithMetricsEnabled returns a new Options value with MetricsEnabled set to the given value.
//
// When MetricsEnabled is set to false, then the DB will be opened and no badger metrics
// will be logged. Metrics are defined in metric.go file.
//
// This flag is useful for use cases like in Dgraph where we open temporary badger instances to
// index data. In those cases we don't want badger metrics to be polluted with the noise from
// those temporary instances.
//
// Default value is set to true
func (opt Options) WithMetricsEnabled(val bool) Options {
	opt.MetricsEnabled = val
	return opt
}

// WithLogger returns a new Options value with Logger set to the given value.
//
// Logger provides a way to configure what logger each value of badger.DB uses.
//
// The default value of Logger writes to stderr using the log package from the Go standard library.
func (opt Options) WithLogger(val Logger) Options {
	opt.Logger = val
	return opt
}

// WithLoggingLevel returns a new Options value with logging level of the
// default logger set to the given value.
// LoggingLevel sets the level of logging. It should be one of DEBUG, INFO,
// WARNING or ERROR levels.
//
// The default value of LoggingLevel is INFO.
func (opt Options) WithLoggingLevel(val loggingLevel) Options {
	opt.Logger = defaultLogger(val)
	return opt
}

// WithBaseTableSize returns a new Options value with BaseTableSize set to the given value.
//
// BaseTableSize sets the maximum size in bytes for LSM table or file in the base level.
//
// The default value of BaseTableSize is 2MB.
func (opt Options) WithBaseTableSize(val int64) Options {
	opt.BaseTableSize = val
	return opt
}

// In leveling, each level may have at most one run, and every time a run in Level i − 1 (i ≥ 1) 
// is moved to Level i, it is greedily sort-merged with the run from Level i, if it exists.
// In the context of LSM trees, a "run" typically refers to a sorted segment of data on disk.
//  This is essentially an SSTable (Sorted String Table). 
//  So, when the statement says "each level may have at most one run," 
//  it means each level is designed to ideally contain a single, large, sorted SSTable.

// The LSM tree is a sequence of levels. Each level is one sorted run that can 
// be range partitioned into many files. Each level is many times larger than the 
// previous level. The size ratio of adjacent levels is sometimes called the fanout 
// and write amplification is minimized when the same fanout is used between all levels. 
// Compaction into level N (Ln) merges data from Ln-1 into Ln. 
// Compaction into Ln rewrites data that was previously merged into Ln

// WithLevelSizeMultiplier returns a new Options value with LevelSizeMultiplier set to the given
// value.
//
// LevelSizeMultiplier sets the ratio between the maximum sizes of contiguous levels in the LSM.
// Once a level grows to be larger than this ratio allowed, the compaction process will be
// triggered.
//
// The default value of LevelSizeMultiplier is 10.
func (opt Options) WithLevelSizeMultiplier(val int) Options {
	opt.LevelSizeMultiplier = val
	return opt
}

// WithMaxLevels returns a new Options value with MaxLevels set to the given value.
//
// Maximum number of levels of compaction allowed in the LSM.
//
// The default value of MaxLevels is 7.
func (opt Options) WithMaxLevels(val int) Options {
	opt.MaxLevels = val
	return opt
}

// WithValueThreshold returns a new Options value with ValueThreshold set to the given value.
//
// ValueThreshold sets the threshold used to decide whether a value is stored directly in the LSM
// tree or separately in the log value files.
//
// The default value of ValueThreshold is 1 MB, and LSMOnlyOptions sets it to maxValueThreshold
// which is set to 1 MB too.

// The Problem: Large Values in LSM Trees

// In a typical LSM tree, the SSTables store key-value pairs. 
// When a value is relatively small, storing it directly alongside the key within the SSTable 
// is efficient. However, if values can be very large (e.g., multi-megabyte documents or blobs), 
// storing them directly in the SSTables can lead to several potential issues:

// Increased SSTable Size: Large values can significantly inflate the size of SSTables. 
// This can make compaction operations more I/O intensive and time-consuming, as more
//  data needs to be read and written.
// Inefficient Reads for Small Values: Even when you're only interested in the key or
//  a small portion of the data, the system might need to read large chunks of the SSTable from 
// disk to access the associated value.
// Memory Usage During Compaction: When merging SSTables containing large values, 
// the system might require more memory to hold and process these values.
// The Solution: Value Log Files

// To address these issues, some LSM tree implementations employ a strategy of storing
//  large values separately in dedicated "log value files" (or similar). In this approach:

// In the SSTable: Instead of the entire large value, the SSTable stores only the key
// and a pointer or reference to the actual value's location within the log value files.
// Log Value Files: These are separate files (often append-only for efficiency) where the
// large values are stored sequentially.
// What is ValueThreshold?

// The ValueThreshold acts as a decision point for determining whether a value should
// be stored directly in the SSTable or separately in the log value files.

// If a value's size is less than or equal to the ValueThreshold: The entire value is
// stored directly within the SSTable alongside its key.
// If a value's size is greater than the ValueThreshold: Only a pointer or reference
// to the value's location in the log value files is stored in the SSTable. 
// The actual value is written to the log value files.
func (opt Options) WithValueThreshold(val int64) Options {
	opt.ValueThreshold = val
	return opt
}

// WithVLogPercentile returns a new Options value with ValLogPercentile set to given value.
//
// VLogPercentile with 0.0 means no dynamic thresholding is enabled.
// MinThreshold value will always act as the value threshold.
//
// VLogPercentile with value 0.99 means 99 percentile of value will be put in LSM tree
// and only 1 percent in vlog. The value threshold will be dynamically updated within the range of
// [ValueThreshold, Options.maxValueThreshold]
//
// # Say VLogPercentile with 1.0 means threshold will eventually set to Options.maxValueThreshold
//
// The default value of VLogPercentile is 0.0.
func (opt Options) WithVLogPercentile(t float64) Options {
	opt.VLogPercentile = t
	return opt
}

// WithNumMemtables returns a new Options value with NumMemtables set to the given value.
//
// NumMemtables sets the maximum number of tables to keep in memory before stalling.
//
// The default value of NumMemtables is 5.
func (opt Options) WithNumMemtables(val int) Options {
	opt.NumMemtables = val
	return opt
}

// WithMemTableSize returns a new Options value with MemTableSize set to the given value.
//
// MemTableSize sets the maximum size in bytes for memtable table.
//
// The default value of MemTableSize is 64MB.
func (opt Options) WithMemTableSize(val int64) Options {
	opt.MemTableSize = val
	return opt
}

// WithBloomFalsePositive returns a new Options value with BloomFalsePositive set
// to the given value.
//
// BloomFalsePositive sets the false positive probability of the bloom filter in any SSTable.
// Before reading a key from table, the bloom filter is checked for key existence.
// BloomFalsePositive might impact read performance of DB. Lower BloomFalsePositive value might
// consume more memory.
//
// The default value of BloomFalsePositive is 0.01.
//
// Setting this to 0 disables the bloom filter completely.
func (opt Options) WithBloomFalsePositive(val float64) Options {
	opt.BloomFalsePositive = val
	return opt
}

// WithBlockSize returns a new Options value with BlockSize set to the given value.
//
// BlockSize sets the size of any block in SSTable. SSTable is divided into multiple blocks
// internally. Each block is compressed using prefix diff encoding.
//
// The default value of BlockSize is 4KB.

// The comment mentions that "Each block is compressed using prefix diff encoding."
//  This is a common technique used to reduce the storage space occupied by the data within each block. 
// Here's how it typically works:

// Sorting: Within a block, the keys are already sorted.
// Prefix Sharing: Consecutive keys within the block often share
// a common prefix. Prefix diff encoding exploits this by storing only the differing 
// suffix of subsequent keys relative to the previous key. 
// For example, if you have keys "apple", "apricot", "banana" within a block, 
// the encoding might store "apple", then the difference "ricot" (after "ap"), and then "banana".
// Compression: After prefix diff encoding, the (often smaller) data within each 
// block is further compressed using a standard compression algorithm (like Snappy, zstd, etc.).
func (opt Options) WithBlockSize(val int) Options {
	opt.BlockSize = val
	return opt
}

// WithNumLevelZeroTables sets the maximum number of Level 0 tables before compaction starts.
//
// The default value of NumLevelZeroTables is 5.
func (opt Options) WithNumLevelZeroTables(val int) Options {
	opt.NumLevelZeroTables = val
	return opt
}

// WithNumLevelZeroTablesStall sets the number of Level 0 tables that once reached causes the DB to
// stall until compaction succeeds.
//
// The default value of NumLevelZeroTablesStall is 15.
func (opt Options) WithNumLevelZeroTablesStall(val int) Options {
	opt.NumLevelZeroTablesStall = val
	return opt
}

// WithBaseLevelSize sets the maximum size target for the base level.
//
// The default value is 10MB.
func (opt Options) WithBaseLevelSize(val int64) Options {
	opt.BaseLevelSize = val
	return opt
}

// WithValueLogFileSize sets the maximum size of a single value log file.
//
// The default value of ValueLogFileSize is 1GB.
func (opt Options) WithValueLogFileSize(val int64) Options {
	opt.ValueLogFileSize = val
	return opt
}

// WithValueLogMaxEntries sets the maximum number of entries a value log file
// can hold approximately.  A actual size limit of a value log file is the
// minimum of ValueLogFileSize and ValueLogMaxEntries.
//
// The default value of ValueLogMaxEntries is one million (1000000).
func (opt Options) WithValueLogMaxEntries(val uint32) Options {
	opt.ValueLogMaxEntries = val
	return opt
}

// WithNumCompactors sets the number of compaction workers to run concurrently.  Setting this to
// zero stops compactions, which could eventually cause writes to block forever.
//
// Level-based prioritization: The dedicated worker for L0-L1 compaction exists because these 
// levels are particularly important for write performance. L0 files often overlap in key ranges,
// which can slow down reads if they accumulate.
//
// Compactions use file-level locking to ensure multiple workers don't try to compact the same files
// A manifest or version set tracks all ongoing compactions
// Workers may use atomic operations for coordinating metadata updates
//
// The concurrent approach significantly improves throughput compared to single-threaded compaction, 
// especially on multi-core systems and when dealing with large datasets. 
// It allows the database to keep accepting writes while maintenance work happens in the background.
// The default value of NumCompactors is 4. One is dedicated just for L0 and L1.
func (opt Options) WithNumCompactors(val int) Options {
	opt.NumCompactors = val
	return opt
}

// WithCompactL0OnClose determines whether Level 0 should be compacted before closing the DB.  This
// ensures that both reads and writes are efficient when the DB is opened later.
//
// The default value of CompactL0OnClose is false.
func (opt Options) WithCompactL0OnClose(val bool) Options {
	opt.CompactL0OnClose = val
	return opt
}

// WithEncryptionKey is used to encrypt the data with AES. Type of AES is used based on the key
// size. For example 16 bytes will use AES-128. 24 bytes will use AES-192. 32 bytes will
// use AES-256.
func (opt Options) WithEncryptionKey(key []byte) Options {
	opt.EncryptionKey = key
	return opt
}

// WithEncryptionKeyRotationDuration returns new Options value with the duration set to
// the given value.
//
// Key Registry will use this duration to create new keys. If the previous generated
// key exceed the given duration. Then the key registry will create new key.

// The default value is set to 10 days.
func (opt Options) WithEncryptionKeyRotationDuration(d time.Duration) Options {
	opt.EncryptionKeyRotationDuration = d
	return opt
}

// WithCompression is used to enable or disable compression. When compression is enabled, every
// block will be compressed using the specified algorithm.  This option doesn't affect existing
// tables. Only the newly created tables will be compressed.
//
// The default compression algorithm used is snappy. Compression is enabled by default.
func (opt Options) WithCompression(cType options.CompressionType) Options {
	opt.Compression = cType
	return opt
}

// WithVerifyValueChecksum is used to set VerifyValueChecksum. When VerifyValueChecksum is set to
// true, checksum will be verified for every entry read from the value log. If the value is stored
// in SST (value size less than value threshold) then the checksum validation will not be done.
//
// The default value of VerifyValueChecksum is False.
func (opt Options) WithVerifyValueChecksum(val bool) Options {
	opt.VerifyValueChecksum = val
	return opt
}

// WithChecksumVerificationMode returns a new Options value with ChecksumVerificationMode set to
// the given value.
//
// ChecksumVerificationMode indicates when the db should verify checksums for SSTable blocks.
//
// The default value of VerifyValueChecksum is options.NoVerification.
func (opt Options) WithChecksumVerificationMode(cvMode options.ChecksumVerificationMode) Options {
	opt.ChecksumVerificationMode = cvMode
	return opt
}

// WithBlockCacheSize returns a new Options value with BlockCacheSize set to the given value.
//
// This value specifies how much data cache should hold in memory. A small size
// of cache means lower memory consumption and lookups/iterations would take
// longer. It is recommended to use a cache if you're using compression or encryption.
// If compression and encryption both are disabled, adding a cache will lead to
// unnecessary overhead which will affect the read performance. Setting size to
// zero disables the cache altogether.
//
// Default value of BlockCacheSize is 256 MB.
func (opt Options) WithBlockCacheSize(size int64) Options {
	opt.BlockCacheSize = size
	return opt
}

// WithInMemory returns a new Options value with Inmemory mode set to the given value.
//
// When badger is running in InMemory mode, everything is stored in memory. No value/sst files are
// created. In case of a crash all data will be lost.
func (opt Options) WithInMemory(b bool) Options {
	opt.InMemory = b
	return opt
}

// WithZSTDCompressionLevel returns a new Options value with ZSTDCompressionLevel set
// to the given value.
//
// The ZSTD compression algorithm supports 20 compression levels. The higher the compression
// level, the better is the compression ratio but lower is the performance. Lower levels
// have better performance and higher levels have better compression ratios.
// We recommend using level 1 ZSTD Compression Level. Any level higher than 1 seems to
// deteriorate badger's performance.
// The following benchmarks were done on a 4 KB block size (default block size). The compression is
// ratio supposed to increase with increasing compression level but since the input for compression
// algorithm is small (4 KB), we don't get significant benefit at level 3. It is advised to write
// your own benchmarks before choosing a compression algorithm or level.
//
// NOTE: The benchmarks are with DataDog ZSTD that requires CGO. Hence, no longer valid.
// no_compression-16              10	 502848865 ns/op	 165.46 MB/s	-
// zstd_compression/level_1-16     7	 739037966 ns/op	 112.58 MB/s	2.93
// zstd_compression/level_3-16     7	 756950250 ns/op	 109.91 MB/s	2.72
// zstd_compression/level_15-16    1	11135686219 ns/op	   7.47 MB/s	4.38
// Benchmark code can be found in table/builder_test.go file
func (opt Options) WithZSTDCompressionLevel(cLevel int) Options {
	opt.ZSTDCompressionLevel = cLevel
	return opt
}

// WithBypassLockGuard returns a new Options value with BypassLockGuard
// set to the given value.
//
// When BypassLockGuard option is set, badger will not acquire a lock on the
// directory. This could lead to data corruption if multiple badger instances
// write to the same data directory. Use this option with caution.
//
// The default value of BypassLockGuard is false.
func (opt Options) WithBypassLockGuard(b bool) Options {
	opt.BypassLockGuard = b
	return opt
}

// WithIndexCacheSize returns a new Options value with IndexCacheSize set to
// the given value.
//
// This value specifies how much memory should be used by table indices. These
// indices include the block offsets and the bloomfilters. Badger uses bloom
// filters to speed up lookups. Each table has its own bloom
// filter and each bloom filter is approximately of 5 MB.
//
// Zero value for IndexCacheSize means all the indices will be kept in
// memory and the cache is disabled.
//
// The default value of IndexCacheSize is 0 which means all indices are kept in
// memory.
func (opt Options) WithIndexCacheSize(size int64) Options {
	opt.IndexCacheSize = size
	return opt
}

// WithDetectConflicts returns a new Options value with DetectConflicts set to the given value.
//
// Detect conflicts options determines if the transactions would be checked for
// conflicts before committing them. When this option is set to false
// (detectConflicts=false) badger can process transactions at a higher rate.
// Setting this options to false might be useful when the user application
// deals with conflict detection and resolution.
//
// The default value of Detect conflicts is True.
func (opt Options) WithDetectConflicts(b bool) Options {
	opt.DetectConflicts = b
	return opt
}

// WithNamespaceOffset returns a new Options value with NamespaceOffset set to the given value. DB
// will expect the namespace in each key at the 8 bytes starting from NamespaceOffset. A negative
// value means that namespace is not stored in the key.
//
// Need to Understand this better
//
// The default value for NamespaceOffset is -1.
func (opt Options) WithNamespaceOffset(offset int) Options {
	opt.NamespaceOffset = offset
	return opt
}

// WithExternalMagic returns a new Options value with ExternalMagicVersion set to the given value.
// The DB would fail to start if either the internal or the external magic number fails validated.
func (opt Options) WithExternalMagic(magic uint16) Options {
	opt.ExternalMagicVersion = magic
	return opt
}

func (opt Options) getFileFlags() int {
	var flags int
	// opt.SyncWrites would be using msync to sync. All writes go through mmap.
	if opt.ReadOnly {
		flags |= os.O_RDONLY
	} else {
		flags |= os.O_RDWR
	}
	return flags
}
