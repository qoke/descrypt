package descryptcheck

import (
	"testing"
)

func TestCDESPasswordVerify(t *testing.T) {
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
		t.Run(tc.name+" (C-backed)", func(t *testing.T) {
			if tc.malformed {
				err := CDESPasswordVerify(tc.inputPassword, tc.expectedHash)
				if err == nil {
					t.Errorf("CDESPasswordVerify() should fail with malformed hash")
				}

				err = CDESPasswordVerify(tc.inputPassword, tc.expectedHash+"X")
				if err == nil {
					t.Errorf("CDESPasswordVerify() should fail with malformed hash")
				}
				return
			}

			if tc.empty {
				err := CDESPasswordVerify("", tc.expectedHash)
				if err == nil {
					t.Errorf("CDESPasswordVerify() should fail with empty password")
				}

				err = CDESPasswordVerify(tc.inputPassword, "")
				if err == nil {
					t.Errorf("CDESPasswordVerify() should fail with empty hash")
				}
				return
			}

			hash, err := CdesCryptHash(tc.inputPassword, tc.salt)
			if err != nil {
				t.Fatalf("CdesCryptHash() error = %v", err)
			}

			err = CDESPasswordVerify(tc.inputPassword, hash)
			if err != nil {
				t.Errorf("CDESPasswordVerify() failed for correct password: %v", err)
			}

			err = CDESPasswordVerify(tc.wrongPassword, hash)
			if err == nil {
				t.Errorf("CDESPasswordVerify() should fail for wrong password")
			}
		})

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

func TestCDESPasswordVerify_Generated(t *testing.T) {
	passwords := []string{"abc123", "", "!@#$$%^&*()", "longerpassword", "short"}
	salts := []string{"ab", "xy", "zz", "AA", "12"}

	for _, pw := range passwords {
		for _, salt := range salts {
			hashC, errC := CdesCryptHash(pw, salt)
			hashGo, errGo := DESCryptHash(pw, salt)

			if errC != nil {
				t.Errorf("CdesCryptHash() error = %v for password '%s' salt '%s'", errC, pw, salt)
				continue
			}
			if errGo != nil {
				t.Errorf("DESCryptHash() error = %v for password '%s' salt '%s'", errGo, pw, salt)
				continue
			}
			if hashC != hashGo {
				t.Errorf("C and Go-native hashes differ: password='%s', salt='%s', C='%s', Go='%s'", pw, salt, hashC, hashGo)
			}

			err := CDESPasswordVerify(pw, hashC)
			if err != nil {
				t.Errorf("CDESPasswordVerify() failed for generated hash: password='%s', salt='%s', hash='%s', err=%v", pw, salt, hashC, err)
			}
			err = DESPasswordVerify(pw, hashGo)
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

			wrongHashC, _ := CdesCryptHash(wrong, salt)
			wrongHashGo, _ := DESCryptHash(wrong, salt)
			if wrongHashC == hashC {
				t.Errorf("CdesCryptHash() should generate different hashes for different passwords: password='%s', wrong='%s', hash='%s'", pw, wrong, hashC)
			}
			if wrongHashGo == hashGo {
				t.Errorf("DESCryptHash() should generate different hashes for different passwords: password='%s', wrong='%s', hash='%s'", pw, wrong, hashGo)
			}

			err = CDESPasswordVerify(wrong, hashC)
			if err == nil {
				t.Errorf("CDESPasswordVerify() should have failed for wrong password: got nil error for password='%s', hash='%s'", wrong, hashC)
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
		t.Run(tc.password+" (C-backed)", func(t *testing.T) {
			hash, err := CdesCryptHash(tc.password, tc.salt)
			if err != nil {
				t.Fatalf("CdesCryptHash() error = %v", err)
			}

			if hash != tc.expected {
				t.Errorf("CdesCryptHash() = %v, want %v for password '%s' and salt '%s'",
					hash, tc.expected, tc.password, tc.salt)
			}

			err = CDESPasswordVerify(tc.password, tc.expected)
			if err != nil {
				t.Errorf("CDESPasswordVerify() failed for standard hash: %v", err)
			}
		})
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
