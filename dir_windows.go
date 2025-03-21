//go:build windows
// +build windows

/*
 * SPDX-FileCopyrightText: © Hypermode Inc. <hello@hypermode.com>
 * SPDX-License-Identifier: Apache-2.0
 */

package badger

// OpenDir opens a directory in windows with write access for syncing.
import (
	"os"
	"path/filepath"
	"syscall"

	"github.com/dgraph-io/badger/v4/y"
)

// FILE_ATTRIBUTE_TEMPORARY - A file that is being used for temporary storage.
// FILE_FLAG_DELETE_ON_CLOSE - The file is to be deleted immediately after all of its handles are
// closed, which includes the specified handle and any other open or duplicated handles.
// See: https://docs.microsoft.com/en-us/windows/desktop/FileIO/file-attribute-constants
// NOTE: Added here to avoid importing golang.org/x/sys/windows
const (
	FILE_ATTRIBUTE_TEMPORARY  = 0x00000100
	FILE_FLAG_DELETE_ON_CLOSE = 0x04000000
)

func openDir(path string) (*os.File, error) {
	fd, err := openDirWin(path)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func openDirWin(path string) (fd syscall.Handle, err error) {
	if len(path) == 0 {
		return syscall.InvalidHandle, syscall.ERROR_FILE_NOT_FOUND
	}
	pathp, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return syscall.InvalidHandle, err
	}
	access := uint32(syscall.GENERIC_READ | syscall.GENERIC_WRITE)
	sharemode := uint32(syscall.FILE_SHARE_READ | syscall.FILE_SHARE_WRITE)
	createmode := uint32(syscall.OPEN_EXISTING)
	fl := uint32(syscall.FILE_FLAG_BACKUP_SEMANTICS)
	return syscall.CreateFile(pathp, access, sharemode, nil, createmode, fl, 0)
}

// DirectoryLockGuard holds a lock on the directory.
type directoryLockGuard struct {
	h    syscall.Handle
	path string
}

// AcquireDirectoryLock acquires exclusive access to a directory.
func acquireDirectoryLock(dirPath string, pidFileName string, readOnly bool) (*directoryLockGuard, error) {
	if readOnly {
		return nil, ErrWindowsNotSupported
	}

	// Convert to absolute path so that Release still works even if we do an unbalanced
	// chdir in the meantime.
	/*
	dirPath := "mydata" and pidFileName := "myprocess.pid": 
	We define a relative directory path mydata and a file name myprocess.pid.
	joinedPath := filepath.Join(dirPath, pidFileName): 
	The filepath.Join function takes these two parts and combines them into a single path string. 
	On most systems, this will result in "mydata/myprocess.pid". 
	On Windows, it would be "mydata\\myprocess.pid". The library handles this difference automatically, 
	making your code more portable.
	*/
	absLockFilePath, err := filepath.Abs(filepath.Join(dirPath, pidFileName))
	if err != nil {
		return nil, y.Wrap(err, "Cannot get absolute path for pid lock file")
	}

	// This call creates a file handler in memory that only one process can use at a time. When
	// that process ends, the file is deleted by the system.
	// FILE_ATTRIBUTE_TEMPORARY is used to tell Windows to try to create the handle in memory.
	// FILE_FLAG_DELETE_ON_CLOSE is not specified in syscall_windows.go but tells Windows to delete
	// the file when all processes holding the handler are closed.
	// XXX: this works but it's a bit klunky. i'd prefer to use LockFileEx but it needs unsafe pkg.

	// When a file is opened by a process using the CreateFile function, 
	// a file handle is associated with it until either the process terminates 
	// or the handle is closed using the CloseHandle function. 
	// The file handle is used to identify the file in many function calls.
	// Each file handle and file object is generally unique to each process that opens 
	// a file—the only exceptions to this are when a file handle held by a process is duplicated, 
	// or when a child process inherits the file handles of the parent process. 
	// In these situations, these file handles are unique, but see a single, shared file object.
	// See DuplicateHandle for more information on duplicating file handles held by processes.
	// Note that while the file handles are typically private to a process, 
	// the file data that the file handles point to is not. Therefore, 
	// processes and threads that share the same file must synchronize their access. 
	// For most operations on a file, a process identifies the file through its private pool of handles.
	h, err := syscall.CreateFile(
		syscall.StringToUTF16Ptr(absLockFilePath), 0, 0, nil,
		syscall.OPEN_ALWAYS,
		uint32(FILE_ATTRIBUTE_TEMPORARY|FILE_FLAG_DELETE_ON_CLOSE),
		0)
	if err != nil {
		return nil, y.Wrapf(err,
			"Cannot create lock file %q.  Another process is using this Badger database",
			absLockFilePath)
	}

	/*
	CloseHandle
The syscall.CloseHandle() function closes an open handle to a Windows operating system object. 
When you're done using a handle, you should always close it to release system resources.

File Handles
File handles are Windows-specific abstractions that represent references to system resources:
They're opaque values (often implemented as pointers) that Windows uses to track opened files,
pipes, events, etc.
File handles are used in Windows API functions
They're typically represented as HANDLE type in C/C++ or as syscall.Handle in Go's Windows implementation
Each process has its own handle table maintained by the OS
Unlike file descriptors, handles can refer to many kinds of objects beyond files 
(mutexes, events, processes, threads)
In Go Programming:
On Windows, Go's os.File wraps a handle
On UNIX-like systems, Go's os.File wraps a file descriptor
	*/
	return &directoryLockGuard{h: h, path: absLockFilePath}, nil
}

// Release removes the directory lock.
func (g *directoryLockGuard) release() error {
	g.path = ""
	return syscall.CloseHandle(g.h)
}

// Windows doesn't support syncing directories to the file system. See
// https://github.com/hypermodeinc/badger/issues/699#issuecomment-504133587 for more details.
func syncDir(dir string) error { return nil }
