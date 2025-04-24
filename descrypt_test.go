package descrypt

import (
	"testing"
)

func TestDESPasswordVerify(t *testing.T) {
	testCases := []struct {
		name          string
		inputPassword string
		salt          string
		expectedHash  string
		wrongPassword string
		malformed     bool
		empty         bool
	}{
		{
			name:          "Correct password (SecretPassword123)",
			inputPassword: "SecretPassword123",
			salt:          "rq",
			expectedHash:  "rq/N3gSWdwWeA",
			wrongPassword: "WrongPassword",
		},
		{
			name:          "Correct password (TestPassword123)",
			inputPassword: "TestPassword123",
			salt:          "pn",
			expectedHash:  "pnA3klLBJ.CRU",
			wrongPassword: "WrongPassword",
		},
		{
			name:          "Malformed hash (too short)",
			inputPassword: "password",
			salt:          "ab",
			expectedHash:  "ab1xQWzQ9Qf",
			malformed:     true,
		},
		{
			name:          "Empty password",
			inputPassword: "",
			salt:          "xy",
			expectedHash:  "xy1xQWzQ9Qf8w",
			empty:         true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name+" (Go-native)", func(t *testing.T) {
			if tc.malformed {
				err := DESPasswordVerify(tc.inputPassword, tc.expectedHash)
				if err == nil {
					t.Errorf("DESPasswordVerify() should fail with malformed hash")
				}

				err = DESPasswordVerify(tc.inputPassword, tc.expectedHash+"X")
				if err == nil {
					t.Errorf("DESPasswordVerify() should fail with malformed hash")
				}
				return
			}

			if tc.empty {
				err := DESPasswordVerify("", tc.expectedHash)
				if err == nil {
					t.Errorf("DESPasswordVerify() should fail with empty password")
				}

				err = DESPasswordVerify(tc.inputPassword, "")
				if err == nil {
					t.Errorf("DESPasswordVerify() should fail with empty hash")
				}
				return
			}

			hash, err := DESCryptHash(tc.inputPassword, tc.salt)
			if err != nil {
				t.Fatalf("DESCryptHash() error = %v", err)
			}

			err = DESPasswordVerify(tc.inputPassword, hash)
			if err != nil {
				t.Errorf("DESPasswordVerify() failed for correct password: %v", err)
			}

			err = DESPasswordVerify(tc.wrongPassword, hash)
			if err == nil {
				t.Errorf("DESPasswordVerify() should fail for wrong password")
			}
		})
	}
}

func TestDESPasswordVerify_Generated(t *testing.T) {
	passwords := []string{"abc123", "", "!@#$$%^&*()", "longerpassword", "short"}
	salts := []string{"ab", "xy", "zz", "AA", "12"}

	for _, pw := range passwords {
		for _, salt := range salts {
			hashGo, errGo := DESCryptHash(pw, salt)
			if errGo != nil {
				t.Errorf("DESCryptHash() error = %v for password '%s' salt '%s'", errGo, pw, salt)
				continue
			}

			err := DESPasswordVerify(pw, hashGo)
			if err != nil {
				t.Errorf("DESPasswordVerify() failed for generated hash: password='%s', salt='%s', hash='%s', err=%v", pw, salt, hashGo, err)
			}

			// Negative test: wrong password
			wrong := ""
			if len(pw) > 0 {
				if pw[0] == 'A' {
					wrong = "B" + pw[1:]
				} else {
					wrong = "A" + pw[1:]
				}
			} else {
				wrong = "x"
			}

			wrongHashGo, _ := DESCryptHash(wrong, salt)
			if wrongHashGo == hashGo {
				t.Errorf("DESCryptHash() should generate different hashes for different passwords: password='%s', wrong='%s', hash='%s'", pw, wrong, hashGo)
			}

			err = DESPasswordVerify(wrong, hashGo)
			if err == nil {
				t.Errorf("DESPasswordVerify() should have failed for wrong password: got nil error for password='%s', hash='%s'", wrong, hashGo)
			}
		}
	}
}

func TestDESCryptAgainstStandardImplementation(t *testing.T) {
	testCases := []struct {
		password string
		salt     string
		expected string
	}{
		{"SecretPassword123", "rq", "rq/N3gSWdwWeA"},
		{"TestPassword123", "pn", "pnA3klLBJ.CRU"},
		{"WrongPassword", "rq", "rqnO5.MEhjGLo"},
		{"abc123", "ab", "ab3z4hnHA5WdU"},
		{"", "xy", "xyw1.V0rbu5mQ"},
		{"!@#$%^&*()", "zz", "zzMEAJ1GZvANE"},
		{"longerpassword", "AA", "AAt4vbXD0zBFE"},
		{"short", "12", "128Q9Am4iRrT6"},
	}

	for _, tc := range testCases {
		t.Run(tc.password+" (Go-native)", func(t *testing.T) {
			hash, err := DESCryptHash(tc.password, tc.salt)
			if err != nil {
				t.Fatalf("DESCryptHash() error = %v", err)
			}

			if hash != tc.expected {
				t.Errorf("DESCryptHash() = %v, want %v for password '%s' and salt '%s'",
					hash, tc.expected, tc.password, tc.salt)
			}

			err = DESPasswordVerify(tc.password, tc.expected)
			if err != nil {
				t.Errorf("DESPasswordVerify() failed for standard hash: %v", err)
			}
		})
	}
}
