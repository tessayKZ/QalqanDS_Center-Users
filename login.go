package main

import (
	"QalqanDS/qalqan"
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

var (
	keysFilePath      string
	currentRKey       []byte
	currentPlainKikey []byte
	currentHeader     [16]byte
)

func setWindowIcon(win fyne.Window) {
	if res, err := fyne.LoadResourceFromPath("assets/ico.ico"); err == nil {
		win.SetIcon(res)
	}
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

func ShowLogin(app fyne.App, win fyne.Window) {
	langPref := app.Preferences().String("lang")
	if langPref == "" {
		langPref = "EN"
	}
	currentLang = langPref

	passEntry = widget.NewPasswordEntry()
	signIn = widget.NewButton(tr("sign_in"), nil)

	langSelect := widget.NewSelect([]string{"KZ", "RU", "EN"}, nil)
	langSelect.PlaceHolder = tr("select_language")

	logо := canvas.NewImageFromFile("assets/login.png")
	logо.FillMode = canvas.ImageFillContain
	logо.SetMinSize(fyne.NewSize(270, 160))
	win.SetFixedSize(true)

	bg := canvas.NewImageFromFile("assets/background.png")
	bg.FillMode = canvas.ImageFillStretch

	applyI18nLogin := func() {
		passEntry.SetPlaceHolder(tr("enter_password"))
		signIn.SetText(tr("sign_in"))
		langSelect.PlaceHolder = tr("select_language")
	}

	langSelect.OnChanged = func(s string) {
		setLang(app, s)
		applyI18nLogin()
	}

	signIn.OnTapped = func() {
		password := passEntry.Text
		if password == "" {
			dialog.ShowInformation(tr("error"), tr("enter_password"), win)
			return
		}

		exePath, err := os.Executable()
		if err != nil {
			dialog.ShowError(fmt.Errorf("can't locate executable: %w", err), win)
			return
		}
		exeDir := filepath.Dir(exePath)

		centerPath := filepath.Join(exeDir, "center.bin")
		abcPath := filepath.Join(exeDir, "abc.bin")

		centerExists := fileExists(centerPath)
		abcExists := fileExists(abcPath)

		if centerExists && abcExists {
			dialog.ShowInformation(
				tr("error"),
				tr("both_keyfiles_found"),
				win,
			)
			return
		}

		var keysPath string
		if centerExists {
			keysPath = centerPath
		} else if abcExists {
			keysPath = abcPath
		} else {
			dialog.ShowError(fmt.Errorf(tr("no_keyfiles_found")), win)
			return
		}

		isCenterMode = strings.EqualFold(filepath.Base(keysPath), "center.bin")

		updateKeysDates(keysPath)

		if !keysExpiryCache.IsZero() {
			now := time.Now()
			if !now.Before(keysExpiryCache) {
				dialog.ShowError(
					fmt.Errorf(tr("keys_expired_error"), keysExpiryCache.Format("02.01.2006")),
					win,
				)
				return
			}
			if keysExpiryCache.Sub(now) <= 14*24*time.Hour {
				leftDays := int(keysExpiryCache.Sub(now).Hours() / 24)
				if leftDays < 0 {
					leftDays = 0
				}
				dialog.ShowInformation(
					tr("warning"),
					fmt.Sprintf(tr("keys_expiry_warning"),
						leftDays, daysWord(leftDays), keysExpiryCache.Format("02.01.2006")),
					win,
				)
			}
		}

		data, err := os.ReadFile(keysPath)
		if err != nil {
			dialog.ShowError(fmt.Errorf("can't open %s: %w", keysPath, err), win)
			return
		}
		if len(data) < qalqan.BLOCKLEN {
			dialog.ShowInformation(tr("error"), tr("file_too_short"), win)
			return
		}

		br := bytes.NewBuffer(data)

		var hdr [16]byte
		var encKikey [qalqan.DEFAULT_KEY_LEN]byte
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			dialog.ShowError(fmt.Errorf("read 16-byte header: %w", err), win)
			return
		}
		if _, err := io.ReadFull(br, encKikey[:]); err != nil {
			dialog.ShowError(fmt.Errorf("read kikey: %w", err), win)
			return
		}
		currentHeader = hdr

		isCenter := strings.EqualFold(filepath.Base(keysPath), "center.bin")

		var inCnt, outCnt int
		if isCenter {
			inCnt = int(binary.BigEndian.Uint16(hdr[4:6]))
			outCnt = int(binary.BigEndian.Uint16(hdr[6:8]))
		} else {
			inCnt = int(binary.BigEndian.Uint16(hdr[1:3]))
			outCnt = int(binary.BigEndian.Uint16(hdr[3:5]))
		}

		if inCnt < 0 {
			inCnt = 0
		}
		if outCnt < 0 {
			outCnt = 0
		}
		if inCnt > 8000 {
			inCnt = 8000
		}
		if outCnt > 8000 {
			outCnt = 8000
		}

		SkeyInCnt, SkeyOutCnt = inCnt, outCnt

		key32 := qalqan.Hash512(password)
		keyHex := hex.EncodeToString(key32[:])

		rKey := make([]byte, qalqan.EXPKLEN)
		qalqan.Kexp(key32[:], qalqan.DEFAULT_KEY_LEN, qalqan.BLOCKLEN, rKey)

		kikey := make([]byte, qalqan.DEFAULT_KEY_LEN)
		copy(kikey, encKikey[:])
		for i := 0; i < qalqan.DEFAULT_KEY_LEN; i += qalqan.BLOCKLEN {
			qalqan.DecryptOFB(kikey[i:i+qalqan.BLOCKLEN], rKey, qalqan.DEFAULT_KEY_LEN, qalqan.BLOCKLEN, kikey[i:i+qalqan.BLOCKLEN])
		}

		qalqan.Kexp(kikey, qalqan.DEFAULT_KEY_LEN, qalqan.BLOCKLEN, rimitkey)

		imitstream := bytes.NewBuffer(data)
		calcImit := make([]byte, qalqan.BLOCKLEN)
		qalqan.Qalqan_Imit(uint64(len(data)-qalqan.BLOCKLEN), rimitkey, imitstream, calcImit)
		fileImit := make([]byte, qalqan.BLOCKLEN)
		if _, err := imitstream.Read(fileImit[:]); err != nil {
			dialog.ShowError(fmt.Errorf("read rimit: %w", err), win)
			return
		}
		if subtle.ConstantTimeCompare(calcImit, fileImit) != 1 {
			dialog.ShowInformation(tr("error"), tr("file_corrupted"), win)
			return
		}

		const circleCount = 100
		circle_keys = make([][qalqan.DEFAULT_KEY_LEN]byte, circleCount)
		if err := qalqan.LoadCircleKeys(br, rKey, &circle_keys, circleCount); err != nil {
			dialog.ShowError(err, win)
			return
		}

		rem := br.Len()
		sessBytes := rem - qalqan.BLOCKLEN

		hasFooter := len(data) >= 2*qalqan.BLOCKLEN &&
			bytes.Equal(data[len(data)-2*qalqan.BLOCKLEN:len(data)-2*qalqan.BLOCKLEN+4], []byte{'Q', 'P', 'W', 'D'})
		if hasFooter {
			sessBytes -= qalqan.BLOCKLEN
		}

		bytesPerUser := (SkeyInCnt + SkeyOutCnt) * qalqan.DEFAULT_KEY_LEN
		users := 1
		if isCenter {
			if bytesPerUser <= 0 || sessBytes < bytesPerUser {
				dialog.ShowError(fmt.Errorf("bad layout: sessBytes=%d perUser=%d", sessBytes, bytesPerUser), win)
				return
			}
			users = sessBytes / bytesPerUser
			if users <= 0 || users > 255 {
				dialog.ShowError(fmt.Errorf("bad layout: users=%d", users), win)
				return
			}
		}

		var loadErr error
		if isCenter {
			loadErr = qalqan.LoadSessionKeysForCenter(br, rKey, &session_keys, SkeyInCnt, SkeyOutCnt, users)
		} else {
			loadErr = qalqan.LoadSessionKeysInThenOutForUser(br, rKey, &session_keys, SkeyInCnt, SkeyOutCnt, users)
		}
		if loadErr != nil {
			dialog.ShowError(loadErr, win)
			return
		}

		nextOutIdx = make([]int, len(session_keys))
		nextCircleIdx = 0

		if isCenter {
			localUserNumber = 0x33
			localUserIndex = 0
		} else {
			userNum := hdr[0]
			if userNum == 0 {
				userNum = 1
			}
			localUserNumber = userNum
			localUserIndex = 0
		}

		lastKeyHashHex = keyHex
		keysFilePath = keysPath

		currentRKey = append([]byte(nil), rKey...)
		currentPlainKikey = append([]byte(nil), kikey...)

		hasFooter, changed := parseFooter(data)
		if !hasFooter || !changed {
			ShowChangePassword(app, win, keysPath, data, kikey)
			return
		}

		runOnMain(func() {
			InitMainUI(app, win)
			win.SetFixedSize(false)
			win.Resize(fyne.NewSize(860, 560))
			win.CenterOnScreen()
		})
	}

	applyI18nLogin()
	langSelect.SetSelected(currentLang)

	topBar := container.NewHBox(
		layout.NewSpacer(),
		container.NewGridWrap(fyne.NewSize(60, 28), langSelect),
	)

	passWrap := container.NewGridWrap(fyne.NewSize(280, 36), passEntry)
	btnWrap := container.NewGridWrap(fyne.NewSize(110, 36), signIn)

	centerCol := container.NewVBox(
		container.NewCenter(logо),
		widget.NewLabel(" "),
		container.NewCenter(passWrap),
		widget.NewLabel(" "),
		container.NewCenter(btnWrap),
	)

	root := container.NewBorder(
		topBar, nil, nil, nil,
		container.NewCenter(centerCol),
	)

	win.SetContent(container.NewStack(bg, container.NewPadded(root)))
}

var (
	passEntry *widget.Entry
	signIn    *widget.Button
)
