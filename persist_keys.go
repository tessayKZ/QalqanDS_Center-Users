package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"QalqanDS/qalqan"

	"fyne.io/fyne/v2/widget"
)

const headerLen = 16

func writeCurrentKeysFile() error {
	if keysFilePath == "" || len(currentRKey) == 0 || len(currentPlainKikey) != qalqan.DEFAULT_KEY_LEN {
		return fmt.Errorf("keys context is not initialized")
	}

	data, err := os.ReadFile(keysFilePath)
	if err != nil {
		return fmt.Errorf("read %s: %w", keysFilePath, err)
	}

	isCenter := strings.EqualFold(filepath.Base(keysFilePath), "center.bin")

	hasFooter, _ := parseFooter(data)
	var footer [qalqan.BLOCKLEN]byte
	if hasFooter && len(data) >= 2*qalqan.BLOCKLEN {
		off := len(data) - 2*qalqan.BLOCKLEN
		copy(footer[:], data[off:off+qalqan.BLOCKLEN])
	}

	const (
		kikeyLen  = 32
		circleCnt = 100
		key32     = 32
		imitLen   = qalqan.BLOCKLEN
		footerLen = qalqan.BLOCKLEN
	)

	var sessIn = SkeyInCnt
	var sessOut = SkeyOutCnt

	users := len(session_keys)
	if users <= 0 {
		return fmt.Errorf("no session keys loaded in memory")
	}

	var bodyLen int

	if isCenter {
		bodyLen = headerLen + kikeyLen + circleCnt*key32 + users*(sessIn+sessOut)*key32
	} else {
		bodyLen = headerLen + kikeyLen + circleCnt*key32 + (sessIn+sessOut)*key32
	}
	total := bodyLen + imitLen
	if hasFooter {
		total += footerLen
	}

	newFile := make([]byte, total)
	off := 0

	copy(newFile[off:off+headerLen], currentHeader[:])
	off += headerLen

	encKikey := make([]byte, kikeyLen)
	qalqan.Encrypt(currentPlainKikey[0:16], currentRKey, qalqan.DEFAULT_KEY_LEN, qalqan.BLOCKLEN, encKikey[0:16])
	qalqan.Encrypt(currentPlainKikey[16:32], currentRKey, qalqan.DEFAULT_KEY_LEN, qalqan.BLOCKLEN, encKikey[16:32])
	copy(newFile[off:off+kikeyLen], encKikey)
	off += kikeyLen

	enc32 := func(dst, src32 []byte) {
		qalqan.Encrypt(src32[0:16], currentRKey, qalqan.DEFAULT_KEY_LEN, qalqan.BLOCKLEN, dst[0:16])
		qalqan.Encrypt(src32[16:32], currentRKey, qalqan.DEFAULT_KEY_LEN, qalqan.BLOCKLEN, dst[16:32])
	}

	circleStart := headerLen + kikeyLen
	circleLen := circleCnt * key32
	copy(newFile[off:off+circleLen], data[circleStart:circleStart+circleLen])
	off += circleLen

	firstUser, lastUser := 0, users
	if !isCenter {
		lastUser = 1
	}
	for u := firstUser; u < lastUser; u++ {
		if isCenter {
			for i := 0; i < sessOut; i++ {
				enc32(newFile[off:off+key32], session_keys[u].Out[i][:])
				off += key32
			}
			for i := 0; i < sessIn; i++ {
				enc32(newFile[off:off+key32], session_keys[u].In[i][:])
				off += key32
			}
		} else {
			for i := 0; i < sessIn; i++ {
				enc32(newFile[off:off+key32], session_keys[u].In[i][:])
				off += key32
			}
			for i := 0; i < sessOut; i++ {
				enc32(newFile[off:off+key32], session_keys[u].Out[i][:])
				off += key32
			}
		}
	}

	if hasFooter {
		copy(newFile[off:off+footerLen], footer[:])
		off += footerLen
	}

	imit := make([]byte, imitLen)
	qalqan.Qalqan_Imit(uint64(off), rimitkey, bytes.NewReader(newFile[:off]), imit)
	copy(newFile[off:off+imitLen], imit)

	if err := os.WriteFile(keysFilePath, newFile, 0600); err != nil {
		return fmt.Errorf("write %s: %w", keysFilePath, err)
	}
	return nil
}

func persistKeysToDiskAsync(logs *widget.RichText) {
	go func() {
		if err := writeCurrentKeysFile(); err != nil {
			uiLog(logs, fmt.Sprintf("Ошибка сохранения ключей: %v", err))
			return
		}
	}()
}
