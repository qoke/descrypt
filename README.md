# descrypt
Native DES Crypt Library for Go (No C required)

**NB: DES is not secure - Only use for legacy backwards compatibility!**

## Installation

```
go get github.com/qoke/descrypt
```

## Usage

```go
package main

import (
    "fmt"
    "github.com/qoke/descrypt"
)

func main() {
    password := "SecretPassword123"
    salt := "rq" // 2 characters

    // Generate DES crypt hash
    hash, err := descrypt.DESCryptHash(password, salt)
    if err != nil {
        panic(err)
    }
    fmt.Println("Hash:", hash) // e.g. "rq/N3gSWdwWeA"

    // Verify password
    err = descrypt.DESPasswordVerify(password, hash)
    if err != nil {
        fmt.Println("Password does not match!")
    } else {
        fmt.Println("Password verified!")
    }
}
```

## API

- `DESCryptHash(password, salt string) (string, error)`
  - Computes the DES crypt(3) hash for a password and 2-character salt. Returns a 13-character string (2-char salt + 11-char hash).
- `DESPasswordVerify(inputPassword, storedHash string) error`
  - Verifies a password against a traditional DES crypt hash (13 chars). Returns nil if the password matches, or an error if not.

## Security Warning

**DES is considered cryptographically broken and unsuitable for further use.**
This library is provided only for legacy compatibility. Do not use for new applications or to protect sensitive data.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
