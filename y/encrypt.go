/*
 * SPDX-FileCopyrightText: © Hypermode Inc. <hello@hypermode.com>
 * SPDX-License-Identifier: Apache-2.0
 */

package y

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

// XORBlock encrypts the given data with AES and XOR's with IV.
// Can be used for both encryption and decryption. IV is of
// AES block size.
func XORBlock(dst, src, key, iv []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(dst, src)
	return nil
}

/*
This function creates an AES encryption/decryption operation using CTR (Counter) mode. Let me break down what it does:

It takes three byte slices as input:

src: The source data to be encrypted/decrypted
key: The AES encryption key
iv: The initialization vector for the CTR mode


It creates a new AES cipher block using the provided key.
It initializes a CTR stream cipher with the AES block and the initialization vector.
It allocates a new byte slice dst with the same length as the source.
It performs the XOR operation between the source data and the key stream, storing the result in dst.
It returns the resulting encrypted/decrypted data and any error that might have occurred.

This is a symmetric encryption function - the same function can be used for 
both encryption and decryption with the same key and IV.
The CTR mode turns the block cipher into a stream cipher by XORing the plaintext 
with a key stream generated from the block cipher.
*/
/*
To decrypt data that was encrypted with these functions, you would use the exact same functions with the 
same key and IV. That's because AES in CTR mode is symmetric - 
the encryption and decryption operations are identical.
*/
func XORBlockAllocate(src, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, iv)
	dst := make([]byte, len(src))
	stream.XORKeyStream(dst, src)
	return dst, nil
}

// XORBlockStream, performs a similar encryption/decryption operation as the first function, but it uses a streaming approach:

// Like the first function, it creates an AES cipher block and initializes a CTR stream cipher.
// But instead of allocating a destination byte slice, it creates a StreamWriter that wraps:

// The CTR stream cipher (stream)
// An output writer (w)

// It then copies data from the source byte slice (converted to a Reader) to the StreamWriter.
// If an error occurs, it wraps the error with a message "XORBlockStream" using a custom Wrapf function.

// The key difference between these functions:

// XORBlockAllocate works in memory, allocating a new byte slice for the result
// XORBlockStream streams the encrypted/decrypted data directly to a writer (like a file or network connection)
func XORBlockStream(w io.Writer, src, key, iv []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	stream := cipher.NewCTR(block, iv)
	sw := cipher.StreamWriter{S: stream, W: w}
	_, err = io.Copy(sw, bytes.NewReader(src))
	return Wrapf(err, "XORBlockStream")
}

// GenerateIV generates IV.
// Calls the GenerateIV function (defined later) to generate a cryptographically secure Initialization Vector (IV).
//  An IV is crucial for secure encryption algorithms to ensure that the same plaintext encrypts to different ciphertexts.
func GenerateIV() ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	_, err := rand.Read(iv)
	return iv, err
}
