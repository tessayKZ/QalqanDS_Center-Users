package main

import (
	"QalqanDS/qalqan"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

/*
	футер: 16 байт перед финальным IMIT-блоком

[0..3]  = 'Q','P','W','D'
[4]     = версия (1)
[5]     = flags (bit0 = 1 если пароль уже меняли)
[6..15] = 0
*/
var footerMagic = [4]byte{'Q', 'P', 'W', 'D'}

func buildFooter(changed bool) [qalqan.BLOCKLEN]byte {
	var f [qalqan.BLOCKLEN]byte
	copy(f[0:4], footerMagic[:])
	f[4] = 1
	if changed {
		f[5] = f[5] | 0x01
	}
	return f
}

func parseFooter(data []byte) (hasFooter bool, changed bool) {
	if len(data) < 2*qalqan.BLOCKLEN {
		return false, false
	}
	off := len(data) - 2*qalqan.BLOCKLEN
	if off < 0 {
		return false, false
	}
	if data[off+0] == 'Q' && data[off+1] == 'P' && data[off+2] == 'W' && data[off+3] == 'D' {
		changed = (data[off+5] & 0x01) != 0
		return true, changed
	}
	return false, false
}

func passwordValid(p string) (ok bool, hasLen, hasUpper, hasLower, hasDigit, hasSpec bool) {
	if len([]rune(p)) >= 10 {
		hasLen = true
	}
	for _, r := range p {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSpec = true
		}
	}
	ok = hasLen && hasUpper && hasLower && hasDigit && hasSpec
	return
}

func ShowChangePassword(app fyne.App, parent fyne.Window, filePath string, fileData []byte, plainKikey []byte) {
	parent.Hide()
	win := app.NewWindow(tr("change_password"))
	win.Resize(fyne.NewSize(560, 460))
	win.CenterOnScreen()
	win.SetFixedSize(true)
	setWindowIcon(win)

	win.SetOnClosed(func() {
		parent.Show()
	})

	bg := canvas.NewImageFromFile("assets/background.png")
	bg.FillMode = canvas.ImageFillStretch

	newPass := widget.NewPasswordEntry()
	newPass.SetPlaceHolder(tr("new_password"))
	confirm := widget.NewPasswordEntry()
	confirm.SetPlaceHolder(tr("confirm_password"))

	type ruleRow struct {
		icon  *widget.Icon
		label *widget.Label
		box   *fyne.Container
	}
	makeRule := func(text string) *ruleRow {
		i := widget.NewIcon(theme.CancelIcon())
		l := widget.NewLabel(text)
		row := container.NewHBox(i, widget.NewLabel(""), l)
		return &ruleRow{icon: i, label: l, box: row}
	}

	lenRow := makeRule(tr("rule_min_length"))
	uppRow := makeRule(tr("rule_upper"))
	lowRow := makeRule(tr("rule_lower"))
	digRow := makeRule(tr("rule_digit"))
	specRow := makeRule(tr("rule_special"))
	matchRow := makeRule(tr("rule_match"))

	setOK := func(r *ruleRow, ok bool) {
		if ok {
			r.icon.SetResource(theme.ConfirmIcon())
		} else {
			r.icon.SetResource(theme.CancelIcon())
		}
	}
	updateHints := func() {
		ok, hasLen, hasUpper, hasLower, hasDigit, hasSpec := passwordValid(newPass.Text)
		_ = ok
		setOK(lenRow, hasLen)
		setOK(uppRow, hasUpper)
		setOK(lowRow, hasLower)
		setOK(digRow, hasDigit)
		setOK(specRow, hasSpec)
		setOK(matchRow, newPass.Text != "" && confirm.Text != "" && newPass.Text == confirm.Text)
	}
	newPass.OnChanged = func(string) { updateHints() }
	confirm.OnChanged = func(string) { updateHints() }

	saveBtn := widget.NewButton(tr("save"), func() {
		ok, _, _, _, _, _ := passwordValid(newPass.Text)
		if !ok {
			dialog.ShowInformation(tr("error"), tr("password_not_valid"), win)
			return
		}
		if newPass.Text != confirm.Text {
			dialog.ShowInformation(tr("error"), tr("passwords_mismatch"), win)
			return
		}

		newKey32 := qalqan.Hash512(newPass.Text)
		newRKey := make([]byte, qalqan.EXPKLEN)
		qalqan.Kexp(newKey32[:], qalqan.DEFAULT_KEY_LEN, qalqan.BLOCKLEN, newRKey)

		if len(plainKikey) != qalqan.DEFAULT_KEY_LEN {
			dialog.ShowError(fmt.Errorf("kikey: bad kikey length"), win)
			return
		}
		newEncKikey := make([]byte, qalqan.DEFAULT_KEY_LEN)
		qalqan.Encrypt(plainKikey[0:16], newRKey, qalqan.DEFAULT_KEY_LEN, qalqan.BLOCKLEN, newEncKikey[0:16])
		qalqan.Encrypt(plainKikey[16:32], newRKey, qalqan.DEFAULT_KEY_LEN, qalqan.BLOCKLEN, newEncKikey[16:32])

		users := len(session_keys)
		if users <= 0 {
			dialog.ShowError(fmt.Errorf("no session keys loaded"), win)
			return
		}

		isCenter := strings.EqualFold(filepath.Base(filePath), "center.bin")

		var abcHeader [16]byte
		if !isCenter {
			if len(fileData) < 16+qalqan.DEFAULT_KEY_LEN {
				dialog.ShowError(fmt.Errorf("abc.bin: too short"), win)
				return
			}
			copy(abcHeader[:], fileData[:16])
		}

		const (
			abcHdrLen   = 16
			kikeyLen    = 32
			circleCount = 100
			sessPerDir  = 1000
			key32       = 32
			footerLen   = qalqan.BLOCKLEN
			imitLen     = qalqan.BLOCKLEN
		)

		var bodyLen int
		if isCenter {
			bodyLen = kikeyLen + circleCount*key32 + users*2*sessPerDir*key32
		} else {
			bodyLen = abcHdrLen + kikeyLen + circleCount*key32 + 2*sessPerDir*key32
		}
		total := bodyLen + footerLen + imitLen

		newFile := make([]byte, total)
		off := 0

		if !isCenter {
			copy(newFile[off:off+abcHdrLen], abcHeader[:])
			off += abcHdrLen
		}

		copy(newFile[off:off+kikeyLen], newEncKikey)
		off += kikeyLen

		enc32 := func(dst []byte, src32 []byte) {
			qalqan.Encrypt(src32[0:16], newRKey, qalqan.DEFAULT_KEY_LEN, qalqan.BLOCKLEN, dst[0:16])
			qalqan.Encrypt(src32[16:32], newRKey, qalqan.DEFAULT_KEY_LEN, qalqan.BLOCKLEN, dst[16:32])
		}

		for i := 0; i < circleCount; i++ {
			enc32(newFile[off:off+key32], circle_keys[i][:])
			off += key32
		}

		for u := 0; u < users; u++ {
			for i := 0; i < sessPerDir; i++ {
				enc32(newFile[off:off+key32], session_keys[u].In[i][:])
				off += key32
			}
			for i := 0; i < sessPerDir; i++ {
				enc32(newFile[off:off+key32], session_keys[u].Out[i][:])
				off += key32
			}
		}

		f := buildFooter(true)
		copy(newFile[off:off+footerLen], f[:])
		off += footerLen

		imit := make([]byte, imitLen)
		qalqan.Qalqan_Imit(uint64(off), rimitkey, bytes.NewReader(newFile[:off]), imit)
		copy(newFile[off:off+imitLen], imit)

		if err := os.WriteFile(filePath, newFile, 0600); err != nil {
			dialog.ShowError(err, win)
			return
		}

		dialog.ShowInformation(tr("success"), tr("password_changed_ok"), win)
		win.Close()
		InitMainUI(app, parent)
		parent.Show()
	})

	cancelBtn := widget.NewButton(tr("cancel"), func() {
		parent.Show()
		win.Close()
	})

	title := widget.NewLabelWithStyle(tr("change_password"), fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	sub := widget.NewLabelWithStyle(tr("please_change_password"), fyne.TextAlignCenter, fyne.TextStyle{Italic: true})

	form := container.NewVBox(
		widget.NewForm(
			widget.NewFormItem(tr("new_password"), newPass),
			widget.NewFormItem(tr("confirm_password"), confirm),
		),
		widget.NewSeparator(),
		widget.NewLabel(tr("password_rules")),
		container.NewVBox(
			lenRow.box,
			uppRow.box,
			lowRow.box,
			digRow.box,
			specRow.box,
			matchRow.box,
		),
	)

	scroll := container.NewVScroll(container.NewPadded(form))
	scroll.SetMinSize(fyne.NewSize(520, 260))

	actions := container.NewHBox(
		layout.NewSpacer(),
		container.NewGridWrap(fyne.NewSize(140, 36), cancelBtn),
		layout.NewSpacer(),
		container.NewGridWrap(fyne.NewSize(180, 36), saveBtn),
		layout.NewSpacer(),
	)

	card := widget.NewCard("", "", container.NewVBox(
		container.NewPadded(title),
		container.NewPadded(sub),
		widget.NewSeparator(),
		scroll,
		widget.NewSeparator(),
		container.NewPadded(actions),
	))

	cardWrap := container.NewGridWrap(fyne.NewSize(540, 420), card)

	content := container.NewStack(
		bg,
		container.NewCenter(cardWrap),
	)

	win.SetContent(content)
	updateHints()
	win.Show()
}
