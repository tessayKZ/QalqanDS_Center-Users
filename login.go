package main

import (
	"QalqanDS/qalqan"
	"bytes"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
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
		exePath, err = os.Executable()
		if err != nil {
			dialog.ShowError(fmt.Errorf("can't locate executable: %w", err), win)
			return
		}
		exeDir = filepath.Dir(exePath)

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

		isCenter := strings.EqualFold(filepath.Base(keysPath), "center.bin")

		var abcHeader [16]byte
		var encKikey [qalqan.DEFAULT_KEY_LEN]byte

		if isCenter {
			if _, err := io.ReadFull(br, encKikey[:]); err != nil {
				dialog.ShowError(fmt.Errorf("read kikey (center): %w", err), win)
				return
			}
		} else {
			if _, err := io.ReadFull(br, abcHeader[:]); err != nil {
				dialog.ShowError(fmt.Errorf("read abc header: %w", err), win)
				return
			}
			if _, err := io.ReadFull(br, encKikey[:]); err != nil {
				dialog.ShowError(fmt.Errorf("read kikey (abc): %w", err), win)
				return
			}
		}

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
			dialog.ShowInformation(tr("error"), tr("wrong_password"), win)
			return
		}

		circle_keys = [100][qalqan.DEFAULT_KEY_LEN]byte{}
		session_keys = nil

		qalqan.LoadCircleKeys(data, br, rKey, &circle_keys)
		qalqan.LoadSessionKeys(data, br, rKey, &session_keys)
		session_keys_ro = cloneSessionKeys(session_keys)

		if isCenter {
			localUserNumber = 0x33
			localUserIndex = 0
		} else {
			userNum := abcHeader[0]
			if userNum == 0 {
				userNum = 1
			}
			localUserNumber = userNum
			localUserIndex = 0
		}

		lastKeyHashHex = keyHex

		hasFooter, changed := parseFooter(data)
		if !hasFooter || !changed {
			ShowChangePassword(app, win, keysPath, data, kikey)
			return
		}

		InitMainUI(app, win)
		win.SetFixedSize(false)
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
