package descryptcheck

// #cgo LDFLAGS: -lcrypt
// #define _GNU_SOURCE
// #include <stdlib.h>
// #include <string.h>
// #include <unistd.h>
// #include <crypt.h>
// char* des_crypt(const char* password, const char* salt) {
//     return crypt(password, salt);
// }
import "C"
import (
	"errors"
	"strings"
	"unsafe"
)

// desCryptHash computes the DES crypt(3) hash for a password and salt (2 chars)
// Returns a 13-character string (2-char salt + 11-char hash)
func CdesCryptHash(password, salt string) (string, error) {
	if len(salt) < 2 {
		return "", errors.New("salt must be 2 characters")
	}

	// Validate salt characters are in the crypt table
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

	// Convert Go strings to C strings
	cPassword := C.CString(password)
	defer C.free(unsafe.Pointer(cPassword))

	cSalt := C.CString(salt)
	defer C.free(unsafe.Pointer(cSalt))

	// Call the C crypt function
	cResult := C.des_crypt(cPassword, cSalt)
	if cResult == nil {
		return "", errors.New("crypt function failed")
	}

	// Convert the C string result back to a Go string
	result := C.GoString(cResult)
	if len(result) != 13 {
		return "", errors.New("invalid crypt result length")
	}

	return result, nil
}

// DESPasswordVerify verifies a password against a traditional DES crypt hash (13 chars)
// Returns nil if the password matches, or an error if not
func CDESPasswordVerify(inputPassword string, storedHash string) error {
	if strings.HasPrefix(storedHash, "{CRYPT}") {
		storedHash = storedHash[7:]
	}

	if len(storedHash) != 13 {
		return errors.New("invalid DES crypt hash length (expected 13 chars)")
	}

	salt := storedHash[:2]
	computed, err := CdesCryptHash(inputPassword, salt)
	if err != nil {
		return err
	}

	if computed != storedHash {
		return errors.New("password does not match hash")
	}
	return nil
}
