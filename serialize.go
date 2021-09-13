// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cookiejar

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/cascax/persistent-cookiejar/internal"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// Save saves the cookies to the persistent cookie file.
// Before the file is written, it reads any cookies that
// have been stored from it and merges them into j.
func (j *Jar) Save() error {
	if j.filename == "" {
		return nil
	}
	return j.save(time.Now())
}

// MarshalJSON implements json.Marshaler by encoding all persistent cookies
// currently in the jar.
func (j *Jar) MarshalJSON() ([]byte, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	entries, err := j.allPersistentEntries()
	if err != nil {
		return nil, err
	}
	// Marshaling entries can never fail.
	data, _ := json.Marshal(entries)
	return data, nil
}

// save is like Save but takes the current time as a parameter.
func (j *Jar) save(now time.Time) error {
	locked, err := internal.LockFile(j.filename)
	if err != nil {
		return err
	}
	defer locked.Close()
	f, err := os.OpenFile(j.filename, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	// TODO optimization: if the file hasn't changed since we
	// loaded it, don't bother with the merge step.

	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.mergeFrom(f); err != nil {
		// The cookie file is probably corrupt.
		log.Printf("cannot read cookie file to merge it; ignoring it: %v", err)
	}
	j.deleteExpired(now)
	if err := f.Truncate(0); err != nil {
		return errors.WithMessage(err, "cannot truncate file")
	}
	if _, err := f.Seek(0, 0); err != nil {
		return err
	}
	return j.writeTo(f)
}

// load loads the cookies from j.filename. If the file does not exist,
// no error will be returned and no cookies will be loaded.
func (j *Jar) load() error {
	if _, err := os.Stat(filepath.Dir(j.filename)); os.IsNotExist(err) {
		// The directory that we'll store the cookie jar
		// in doesn't exist, so don't bother trying
		// to acquire the lock.
		return nil
	}
	locked, err := internal.LockFile(j.filename)
	if err != nil {
		return err
	}
	defer locked.Close()
	f, err := os.Open(j.filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	if err := j.mergeFrom(f); err != nil {
		return err
	}
	return nil
}

// mergeFrom reads all the cookies from r and stores them in the Jar.
func (j *Jar) mergeFrom(r io.Reader) error {
	decoder := json.NewDecoder(r)
	// Cope with old cookiejar format by just discarding
	// cookies, but still return an error if it's invalid JSON.
	var data json.RawMessage
	if err := decoder.Decode(&data); err != nil {
		if err == io.EOF {
			// Empty file.
			return nil
		}
		return err
	}
	var entries []entry
	if err := json.Unmarshal(data, &entries); err != nil {
		log.Printf("warning: discarding cookies in invalid format (error: %v)", err)
		return nil
	}
	if err := j.merge(entries); err != nil {
		return err
	}
	return nil
}

// writeTo writes all the cookies in the jar to w
// as a JSON array.
func (j *Jar) writeTo(w io.Writer) error {
	encoder := json.NewEncoder(w)
	entries, err := j.allPersistentEntries()
	if err != nil {
		return err
	}
	if err := encoder.Encode(entries); err != nil {
		return err
	}
	return nil
}

// allPersistentEntries returns all the entries in the jar, sorted by primarly by canonical host
// name and secondarily by path length.
func (j *Jar) allPersistentEntries() ([]entry, error) {
	var entries []entry
	var err error
	for _, submap := range j.entries {
		for _, e := range submap {
			if e.Persistent {
				if len(j.encryptedKey) > 0 {
					e.EncryptedValue, err = encrypt([]byte(e.Value), j.encryptedKey)
					if err != nil {
						return nil, errors.WithMessage(err, "encrypt value error")
					}
					e.Value = ""
				}
				entries = append(entries, e)
			}
		}
	}
	sort.Sort(byCanonicalHost{entries})
	return entries, nil
}

// encrypt returns the text encrypted by AES-GCM and encoded by base64
func encrypt(plaintext []byte, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", errors.WithMessage(err, "invalid encrypt key")
	}
	mode, err := cipher.NewGCM(block)
	if err != nil {
		return "", errors.WithMessage(err, "GCM error")
	}
	nonce := make([]byte, mode.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return "", errors.WithMessage(err, "make nonce error")
	}
	encrypted := mode.Seal(nil, nonce, plaintext, nil)

	// use base64 encoding nonce and encrypted data
	dataLen := len(nonce) + len(encrypted)
	buf := bytes.NewBuffer(make([]byte, 0, base64.StdEncoding.EncodedLen(dataLen)+3))
	buf.Write([]byte("v01"))
	encoder := base64.NewEncoder(base64.StdEncoding, buf)
	_, _ = encoder.Write(nonce)
	_, _ = encoder.Write(encrypted)
	err = encoder.Close()
	if err != nil {
		return "", errors.WithMessage(err, "base64 encoding error")
	}
	return buf.String(), nil
}

func decrypt(encryptedText string, key []byte) ([]byte, error) {
	if !strings.HasPrefix(encryptedText, "v01") {
		return nil, errors.New("invalid value")
	}
	encryptedData := make([]byte, base64.StdEncoding.DecodedLen(len(encryptedText)-3))
	n, err := base64.StdEncoding.Decode(encryptedData, []byte(encryptedText)[3:])
	if err != nil {
		return nil, errors.WithMessage(err, "base64 decode error")
	}
	encryptedData = encryptedData[:n]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("invalid decrypt key")
	}
	mode, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.WithMessage(err, "GCM error")
	}
	nonce := encryptedData[:mode.NonceSize()]
	ciphertext := encryptedData[mode.NonceSize():]
	decrypted, err := mode.Open(nil, nonce, ciphertext, nil)
	return decrypted, err
}
