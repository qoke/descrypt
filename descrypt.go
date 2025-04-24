package descrypt

import (
	"errors"
	"strings"
)

// DESCryptHash computes the DES crypt(3) hash for a password and salt (2 chars) in pure Go
// Returns a 13-character string (2-char salt + 11-char hash)
func DESCryptHash(password, salt string) (string, error) {
	if len(salt) < 2 {
		return "", errors.New("salt must be 2 characters")
	}

	validChars := "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	for i := 0; i < 2; i++ {
		valid := false
		for _, c := range validChars {
			if salt[i] == uint8(c) {
				valid = true
				break
			}
		}
		if !valid {
			return "", errors.New("invalid character in salt")
		}
	}

	// --- Begin Go-native crypt(3) implementation ---
	// Tables and logic ported from crypt3.c

	// Permutation tables and S-boxes
	var (
		IP = [64]uint8{
			58, 50, 42, 34, 26, 18, 10, 2,
			60, 52, 44, 36, 28, 20, 12, 4,
			62, 54, 46, 38, 30, 22, 14, 6,
			64, 56, 48, 40, 32, 24, 16, 8,
			57, 49, 41, 33, 25, 17, 9, 1,
			59, 51, 43, 35, 27, 19, 11, 3,
			61, 53, 45, 37, 29, 21, 13, 5,
			63, 55, 47, 39, 31, 23, 15, 7,
		}
		FP = [64]uint8{
			40, 8, 48, 16, 56, 24, 64, 32,
			39, 7, 47, 15, 55, 23, 63, 31,
			38, 6, 46, 14, 54, 22, 62, 30,
			37, 5, 45, 13, 53, 21, 61, 29,
			36, 4, 44, 12, 52, 20, 60, 28,
			35, 3, 43, 11, 51, 19, 59, 27,
			34, 2, 42, 10, 50, 18, 58, 26,
			33, 1, 41, 9, 49, 17, 57, 25,
		}
		PC1_C = [28]uint8{
			57, 49, 41, 33, 25, 17, 9,
			1, 58, 50, 42, 34, 26, 18,
			10, 2, 59, 51, 43, 35, 27,
			19, 11, 3, 60, 52, 44, 36,
		}
		PC1_D = [28]uint8{
			63, 55, 47, 39, 31, 23, 15,
			7, 62, 54, 46, 38, 30, 22,
			14, 6, 61, 53, 45, 37, 29,
			21, 13, 5, 28, 20, 12, 4,
		}
		shifts = [16]uint8{1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1}
		PC2_C  = [24]uint8{
			14, 17, 11, 24, 1, 5,
			3, 28, 15, 6, 21, 10,
			23, 19, 12, 4, 26, 8,
			16, 7, 27, 20, 13, 2,
		}
		PC2_D = [24]uint8{
			41, 52, 31, 37, 47, 55,
			30, 40, 51, 45, 33, 48,
			44, 49, 39, 56, 34, 53,
			46, 42, 50, 36, 29, 32,
		}
		E = [48]uint8{
			32, 1, 2, 3, 4, 5,
			4, 5, 6, 7, 8, 9,
			8, 9, 10, 11, 12, 13,
			12, 13, 14, 15, 16, 17,
			16, 17, 18, 19, 20, 21,
			20, 21, 22, 23, 24, 25,
			24, 25, 26, 27, 28, 29,
			28, 29, 30, 31, 32, 1,
		}
		S = [8][64]uint8{
			{
				14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
				0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
				4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
				15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
			},
			{
				15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
				3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
				0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
				13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
			},
			{
				10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
				13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
				13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
				1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
			},
			{
				7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
				13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
				10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
				3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
			},
			{
				2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
				14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
				4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
				11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
			},
			{
				12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
				10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
				9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
				4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
			},
			{
				4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
				13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
				1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
				6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
			},
			{
				13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
				1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
				7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
				2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
			},
		}
		P = [32]uint8{
			16, 7, 20, 21,
			29, 12, 28, 17,
			1, 15, 23, 26,
			5, 18, 31, 10,
			2, 8, 24, 14,
			32, 27, 3, 9,
			19, 13, 30, 6,
			22, 11, 4, 25,
		}
	)

	// // Helper functions for bit operations
	// bit := func(b byte, n int) byte {
	// 	return (b >> uint(7-n)) & 1
	// }

	// Step 1: Break password into 64 bits (7 bits per char, 8 chars max)
	var key [64]byte
	for i := 0; i < 64; i++ {
		key[i] = 0
	}
	for i := 0; i < len(password) && i < 8; i++ {
		c := password[i]
		for j := 0; j < 7; j++ {
			key[i*8+j] = (c >> uint(6-j)) & 1
		}
	}

	// Step 2: Set up C and D from key using PC1
	var C, D [28]byte
	for i := 0; i < 28; i++ {
		C[i] = key[PC1_C[i]-1]
		D[i] = key[PC1_D[i]-1]
	}

	// Step 3: Generate key schedule KS[16][48]
	var KS [16][48]byte
	for i := 0; i < 16; i++ {
		// Rotate C and D
		for k := 0; k < int(shifts[i]); k++ {
			c0, d0 := C[0], D[0]
			copy(C[0:], C[1:])
			C[27] = c0
			copy(D[0:], D[1:])
			D[27] = d0
		}
		for j := 0; j < 24; j++ {
			KS[i][j] = C[PC2_C[j]-1]
			KS[i][j+24] = D[PC2_D[j]-28-1]
		}
	}

	// Step 4: Prepare E bit selection table (will be mutated by salt)
	var Ebits [48]uint8
	copy(Ebits[:], E[:])

	// Step 5: Apply salt to Ebits
	for i := 0; i < 2; i++ {
		c := salt[i]
		if c > 'Z' {
			c -= 6
		}
		if c > '9' {
			c -= 7
		}
		c -= '.'
		for j := 0; j < 6; j++ {
			if ((c >> uint(j)) & 1) != 0 {
				t := Ebits[6*i+j]
				Ebits[6*i+j] = Ebits[6*i+j+24]
				Ebits[6*i+j+24] = t
			}
		}
	}

	// Step 6: Initial data block is all zero bits
	var block [66]byte
	for i := 0; i < 66; i++ {
		block[i] = 0
	}

	// Step 7: 25 rounds of DES encryption
	desEncrypt := func(block *[66]byte) {
		var left, right [32]byte
		for j := 0; j < 32; j++ {
			left[j] = block[IP[j]-1]
		}
		for j := 32; j < 64; j++ {
			right[j-32] = block[IP[j]-1]
		}
		for ii := 0; ii < 16; ii++ {
			i := ii
			var oldRight [32]byte
			copy(oldRight[:], right[:])
			// Expand right to 48 bits and xor with key
			var preS [48]byte
			for j := 0; j < 48; j++ {
				preS[j] = right[Ebits[j]-1] ^ KS[i][j]
			}
			// S-boxes
			var f [32]byte
			for j := 0; j < 8; j++ {
				temp := 6 * j
				idx := (preS[temp+0] << 5) | (preS[temp+1] << 3) | (preS[temp+2] << 2) | (preS[temp+3] << 1) | (preS[temp+4] << 0) | (preS[temp+5] << 4)
				k := S[j][idx]
				temp2 := 4 * j
				f[temp2+0] = (k >> 3) & 1
				f[temp2+1] = (k >> 2) & 1
				f[temp2+2] = (k >> 1) & 1
				f[temp2+3] = (k >> 0) & 1
			}
			// Permute f with P and xor with left
			var newRight [32]byte
			for j := 0; j < 32; j++ {
				newRight[j] = left[j] ^ f[P[j]-1]
			}
			left = oldRight
			right = newRight
		}
		// Swap left and right
		for j := 0; j < 32; j++ {
			left[j], right[j] = right[j], left[j]
		}
		// Final permutation
		for j := 0; j < 64; j++ {
			if FP[j] < 33 {
				block[j] = left[FP[j]-1]
			} else {
				block[j] = right[FP[j]-33]
			}
		}
	}
	for i := 0; i < 25; i++ {
		desEncrypt(&block)
	}

	// Step 8: Format output (2-char salt + 11-char hash)
	var out [13]byte
	out[0] = salt[0]
	out[1] = salt[1]
	for i := 0; i < 11; i++ {
		c := byte(0)
		for j := 0; j < 6; j++ {
			c <<= 1
			c |= block[6*i+j]
		}
		c += '.'
		if c > '9' {
			c += 7
		}
		if c > 'Z' {
			c += 6
		}
		out[i+2] = c
	}
	return string(out[:]), nil
}

// DESPasswordVerify verifies a password against a traditional DES crypt hash (13 chars) using Go-native implementation
// Returns nil if the password matches, or an error if not
func DESPasswordVerify(inputPassword string, storedHash string) error {
	if strings.HasPrefix(storedHash, "{CRYPT}") {
		storedHash = storedHash[7:]
	}
	if len(storedHash) != 13 {
		return errors.New("invalid DES crypt hash length (expected 13 chars)")
	}
	salt := storedHash[:2]
	computed, err := DESCryptHash(inputPassword, salt)
	if err != nil {
		return err
	}
	if computed != storedHash {
		return errors.New("password does not match hash")
	}
	return nil
}
