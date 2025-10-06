package main

import (
	"QalqanDS/qalqan"
	"bytes"
	crand "crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	mrand "math/rand"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

const (
	// file types
	FileTypeGeneric = 0x00
	FileTypeVideo   = 0x77
	FileTypePhoto   = 0x88
	FileTypeText    = 0x00
	FileTypeAudio   = 0x55

	// key types
	KeyTypeCircle     = 0x00
	KeyTypeSessionOut = 0x01
	KeyTypeSessionIn  = 0x02

	MaxPlainSize int64 = 2 * 1024 * 1024 * 1024 // 2Gb

	MaxEncryptedSize int64 = MaxPlainSize + 64
)

// simple progress-aware reader for dialogs
type progressReader struct {
	r        io.Reader
	total    int64
	read     int64
	lastEmit time.Time
	emit     func(f float64)
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 {
		p.read += int64(n)
		// обновляем ~25 раз/сек или при завершении
		if time.Since(p.lastEmit) > 40*time.Millisecond || p.read == p.total {
			if p.total > 0 && p.emit != nil {
				p.emit(float64(p.read) / float64(p.total))
			}
			p.lastEmit = time.Now()
		}
	}
	return n, err
}

func uiLog(logs *widget.RichText, msg string) {
	runOnMain(func() { addLog(logs, msg) })
}

type ServiceInfo struct {
	Owner        byte // [1]
	FileType     byte // [4]
	KeyType      byte // [5]
	CircleIndex  int  // [6] (0..99) или 0, если не используется
	SessionIndex int  // [7..8] (0..999) или -1, если не используется
}

func buildServiceInfo(fileTypeCode, keyType byte, circleNo int, usedIdx int) [qalqan.BLOCKLEN]byte {
	var s [qalqan.BLOCKLEN]byte
	s[0] = 0x00
	s[1] = localUserNumber
	s[2] = 0x04
	s[3] = byte(qalqan.DEFAULT_KEY_LEN) // 0x20
	s[4] = fileTypeCode
	s[5] = keyType
	if circleNo >= 0 && circleNo < 100 {
		s[6] = byte(circleNo)
	}
	if usedIdx >= 0 && usedIdx < 1000 {
		stored := usedIdx + 1             // 1-based
		s[7] = byte((stored >> 8) & 0xFF) // HI8 -> [7]
		s[8] = byte(stored & 0x03)        // LO2 -> [8] (2 младших бита)
	}
	// [9..15] = 0
	return s
}

func cloneSessionKeys(src []qalqan.SessionKeySet) []qalqan.SessionKeySet {
	if len(src) == 0 {
		return nil
	}
	dst := make([]qalqan.SessionKeySet, len(src))
	copy(dst, src)
	return dst
}

func suggestEncryptedNameFromPath(p string) string {
	b := baseName(p)
	if strings.EqualFold(filepath.Ext(b), ".bin") {
		return b // уже .bin
	}
	return b + ".bin"
}

func fileTypeDefaultExt(ft byte) string {
	switch ft {
	case FileTypePhoto:
		return ".jpg"
	case FileTypeText:
		return ".txt"
	case FileTypeAudio:
		return ".mp3"
	case FileTypeVideo:
		return ".mp4"
	default:
		return ".bin"
	}
}

func suggestDecryptedNameFromPath(p string, fileType byte) string {
	b := baseName(p) // "report.pdf.bin"
	name := b
	if strings.EqualFold(filepath.Ext(b), ".bin") {
		name = b[:len(b)-len(".bin")] // "report.pdf"
	}

	if filepath.Ext(name) == "" {
		name += fileTypeDefaultExt(fileType)
	}
	if strings.TrimSpace(name) == "" {
		name = "File_" + time.Now().Format("2006-01-02_15-04") + fileTypeDefaultExt(fileType)
	}
	return name
}

var (
	isCenterMode    bool
	session_keys    []qalqan.SessionKeySet
	session_keys_ro []qalqan.SessionKeySet
	circle_keys     [100][qalqan.DEFAULT_KEY_LEN]byte
	rimitkey        []byte

	localUserIndex       = 0
	localUserNumber byte = 1

	lastKeyHashHex string
)

func init() {
	rimitkey = make([]byte, qalqan.EXPKLEN)
}

func ApplyLocalUserContext(keysPath string, users int) {
	base := strings.ToLower(filepath.Base(keysPath))
	if strings.Contains(base, "center") || users > 1 {
		localUserNumber = 0x33
		localUserIndex = 0
	} else {
		localUserNumber = 1
		localUserIndex = 0
	}
}

func sessionKeyAllZero(k *[qalqan.DEFAULT_KEY_LEN]byte) bool {
	for i := 0; i < qalqan.DEFAULT_KEY_LEN; i++ {
		if k[i] != 0 {
			return false
		}
	}
	return true
}

func getSessionKeyExact(userIdx int, useOut bool, idx int) []uint8 {
	if len(session_keys_ro) == 0 || userIdx < 0 || userIdx >= len(session_keys_ro) || idx < 0 || idx >= 1000 {
		return nil
	}
	var key []byte
	if useOut {
		if sessionKeyAllZero(&session_keys_ro[userIdx].Out[idx]) {
			return nil
		}
		key = session_keys_ro[userIdx].Out[idx][:]
	} else {
		if sessionKeyAllZero(&session_keys_ro[userIdx].In[idx]) {
			return nil
		}
		key = session_keys_ro[userIdx].In[idx][:]
	}
	rkey := make([]uint8, qalqan.EXPKLEN)
	qalqan.Kexp(key, qalqan.DEFAULT_KEY_LEN, qalqan.BLOCKLEN, rkey)
	return rkey
}

func useAndDeleteSessionOut(userIdx int, start int) ([]uint8, int) {
	if len(session_keys) == 0 || userIdx < 0 || userIdx >= len(session_keys) {
		return nil, -1
	}
	idx := start % 1000
	found := false
	for i := 0; i < 1000; i++ {
		try := (start + i) % 1000
		if !sessionKeyAllZero(&session_keys[userIdx].Out[try]) {
			idx = try
			found = true
			break
		}
	}
	if !found {
		return nil, -1
	}

	key := session_keys[userIdx].Out[idx][:]
	rkey := make([]uint8, qalqan.EXPKLEN)
	qalqan.Kexp(key, qalqan.DEFAULT_KEY_LEN, qalqan.BLOCKLEN, rkey)

	for i := 0; i < qalqan.DEFAULT_KEY_LEN; i++ {
		session_keys[userIdx].Out[idx][i] = 0
	}
	return rkey, idx
}

func useAndDeleteCircleKey(circleKeyNumber int) []uint8 {
	if circleKeyNumber < 0 || circleKeyNumber >= len(circle_keys) {
		return nil
	}
	key := circle_keys[circleKeyNumber][:qalqan.DEFAULT_KEY_LEN]
	rkey := make([]uint8, qalqan.EXPKLEN)
	qalqan.Kexp(key, qalqan.DEFAULT_KEY_LEN, qalqan.BLOCKLEN, rkey)
	return rkey
}

func countRemainingSessionOut(userIdx int) int {
	if len(session_keys) == 0 || userIdx < 0 || userIdx >= len(session_keys) {
		return 0
	}
	cnt := 0
	for i := 0; i < 1000; i++ {
		if !sessionKeyAllZero(&session_keys[userIdx].Out[i]) {
			cnt++
		}
	}
	return cnt
}

func baseName(path string) string {
	b := filepath.Base(path)
	if b == "." || b == "/" || b == "\\" || b == "" {
		return "file"
	}
	return b
}

func chooseKeyForEncryption(targetUserIdx int) (rKey []byte, keyType byte, circleKeyNumber byte, sessionKeyNumber byte, usedIdx int, err error) {
	if len(session_keys) > 0 {
		uidx := targetUserIdx
		if uidx < 0 || uidx >= len(session_keys) {
			uidx = localUserIndex
		}
		start := 0
		if rk, idx := useAndDeleteSessionOut(uidx, start); rk != nil && idx >= 0 {
			return rk, KeyTypeSessionOut, 0, byte(idx), idx, nil
		}
		return nil, 0, 0, 0, -1, fmt.Errorf("session keys empty for user #%d", uidx+1)
	}

	if len(circle_keys) > 0 {
		cn := mrand.Intn(100)
		if rk := useAndDeleteCircleKey(cn); rk != nil {
			return rk, KeyTypeCircle, byte(cn), 0, -1, nil
		}
	}
	return nil, 0, 0, 0, -1, fmt.Errorf("no encryption keys available")
}

func makeLogsArea() (*widget.RichText, fyne.CanvasObject) {
	logs := widget.NewRichText(&widget.TextSegment{Text: "", Style: widget.RichTextStyleInline})
	logs.Wrapping = fyne.TextWrapWord

	scroll := container.NewVScroll(logs)
	scroll.SetMinSize(fyne.NewSize(0, 170))

	iconClear, err := fyne.LoadResourceFromPath("assets/clear.png")
	if err != nil {
		iconClear = theme.DeleteIcon()
	}
	clearLogBtn = widget.NewButtonWithIcon(tr("clear_log"), iconClear, func() {
		logs.Segments = []widget.RichTextSegment{}
		logs.Refresh()
	})

	toolbar := container.NewHBox(
		layout.NewSpacer(),
		container.NewGridWrap(fyne.NewSize(140, 36), clearLogBtn),
	)

	card := widget.NewCard("", "", container.NewVBox(
		toolbar,
		container.NewPadded(scroll),
	))
	return logs, card
}

func addLog(logs *widget.RichText, text string) {
	logs.Segments = append(logs.Segments, &widget.TextSegment{
		Text:  text + "\n",
		Style: widget.RichTextStyleInline,
	})
	logs.Refresh()
}

func encodeHashBoxContent() string {
	if lastKeyHashHex == "" {
		return "—"
	}
	if len(lastKeyHashHex) > 96 {
		return lastKeyHashHex[:96] + "…"
	}
	return lastKeyHashHex
}

func InitMainUI(app fyne.App, win fyne.Window) {
	bgImage := canvas.NewImageFromFile("assets/background.png")
	bgImage.FillMode = canvas.ImageFillStretch
	if icon, err := fyne.LoadResourceFromPath("assets/icon.ico"); err == nil {
		win.SetIcon(icon)
	}

	selectedLanguage := widget.NewSelect([]string{"KZ", "RU", "EN"}, nil)
	selectedLanguage.PlaceHolder = tr("select_language")
	selectedLanguage.OnChanged = func(code string) {
		setLang(app, code)
		if encBtn != nil {
			encBtn.SetText(tr("encrypt"))
		}
		if decBtn != nil {
			decBtn.SetText(tr("decrypt"))
		}
		if keysLeftCaptionLabel != nil {
			keysLeftCaptionLabel.SetText(tr("keys_left"))
		}
		if encHintLabel != nil {
			encHintLabel.SetText(tr("encrypt_card_hint"))
		}
		if decHintLabel != nil {
			decHintLabel.SetText(tr("decrypt_card_hint"))
		}
		if clearLogBtn != nil {
			clearLogBtn.SetText(tr("clear_log"))
		}
		if modeLabel != nil {
			modeLabel.SetText(getModeLabelText())
		}
		selectedLanguage.PlaceHolder = tr("select_language")
		if recipientCard != nil {
			recipientCard.Subtitle = tr("encrypt_to")
			recipientCard.Refresh()
		}

	}

	logs, logsArea := makeLogsArea()

	keysLeftLabel = widget.NewLabelWithStyle(fmt.Sprintf("%d", countRemainingSessionOut(localUserIndex)),
		fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	keysLeftLabel.TextStyle.Monospace = true
	keysLeftCaptionLabel = widget.NewLabelWithStyle(tr("keys_left"), fyne.TextAlignCenter, fyne.TextStyle{Italic: true})

	keysCard := widget.NewCard("", "", container.NewVBox(
		container.NewCenter(keysLeftLabel),
		container.NewCenter(keysLeftCaptionLabel),
	))
	keysWrap := container.NewGridWrap(fyne.NewSize(140, 120), keysCard)

	var recipientWrap fyne.CanvasObject
	if isCenterMode && len(session_keys) > 0 {
		opts := make([]string, len(session_keys))
		for i := range session_keys {
			opts[i] = strconv.Itoa(i + 1) // "1", "2", ...
		}
		recipientSelect = widget.NewSelect(opts, func(val string) {
			if i, err := strconv.Atoi(val); err == nil {
				selectedUserIdx = i - 1
				keysLeftLabel.SetText(fmt.Sprintf("%d", countRemainingSessionOut(selectedUserIdx)))
			}
		})
		selectedUserIdx = 0
		recipientSelect.SetSelected(opts[0])
		keysLeftLabel.SetText(fmt.Sprintf("%d", countRemainingSessionOut(selectedUserIdx)))

		recipientCard = widget.NewCard("", tr("encrypt_to"), container.NewVBox(recipientSelect))
		recipientWrap = container.NewGridWrap(fyne.NewSize(200, 120), recipientCard)
	} else {
		selectedUserIdx = localUserIndex
	}

	encBtn = makeEncryptButton(win, logs, keysLeftLabel)
	decBtn = makeDecryptButton(win, logs)

	encBtnWrap := container.NewGridWrap(fyne.NewSize(130, 44), encBtn)
	decBtnWrap := container.NewGridWrap(fyne.NewSize(130, 44), decBtn)

	encIcon, _ := fyne.LoadResourceFromPath("assets/encrypt.png")
	if encIcon == nil {
		encIcon = theme.ConfirmIcon()
	}
	decIcon, _ := fyne.LoadResourceFromPath("assets/decrypt.png")
	if decIcon == nil {
		decIcon = theme.CancelIcon()
	}

	encHintLabel = widget.NewLabelWithStyle(tr("encrypt_card_hint"), fyne.TextAlignCenter, fyne.TextStyle{})
	encCard := widget.NewCard("", "", container.NewVBox(
		container.NewCenter(encBtnWrap),
		encHintLabel,
	))
	decHintLabel = widget.NewLabelWithStyle(tr("decrypt_card_hint"), fyne.TextAlignCenter, fyne.TextStyle{})
	decCard := widget.NewCard("", "", container.NewVBox(
		container.NewCenter(decBtnWrap),
		decHintLabel,
	))

	encCardWrap := container.NewGridWrap(fyne.NewSize(280, 160), encCard)
	decCardWrap := container.NewGridWrap(fyne.NewSize(280, 160), decCard)

	modeLabel = widget.NewLabelWithStyle(getModeLabelText(), fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	topBar := container.NewHBox(
		container.NewPadded(modeLabel),
		layout.NewSpacer(),
		container.NewGridWrap(fyne.NewSize(65, 28), selectedLanguage),
	)

	rowElems := []fyne.CanvasObject{layout.NewSpacer(), keysWrap}
	if recipientWrap != nil {
		rowElems = append(rowElems, widget.NewLabel("  "), recipientWrap)
	}
	rowElems = append(rowElems, layout.NewSpacer())
	infoRow := container.NewHBox(rowElems...)

	progressBar = widget.NewProgressBar()
	progressBar.Min = 0
	progressBar.Max = 1
	progressLabel = widget.NewLabel("")
	progressCard = widget.NewCard("", "", container.NewVBox(
		container.NewCenter(progressLabel),
		progressBar,
	))
	progressCard.Hide()

	actionsRow := container.NewHBox(
		layout.NewSpacer(),
		encCardWrap,
		widget.NewLabel(" "),
		decCardWrap,
		layout.NewSpacer(),
	)

	mainUI := container.NewVBox(
		topBar,
		widget.NewLabel(" "),
		infoRow,
		widget.NewLabel(" "),
		progressCard,
		widget.NewLabel(" "),
		actionsRow,
		widget.NewLabel(" "),
		logsArea,
	)

	content := container.NewStack(bgImage, container.NewPadded(mainUI))

	win.SetContent(content)

	selectedLanguage.SetSelected(currentLang)

	if lastKeyHashHex != "" {
		addLog(logs, fmt.Sprintf(tr("keys_loaded_hash"), encodeHashBoxContent()))
	} else {
		addLog(logs, tr("keys_loaded"))
	}
}

var (
	keysLeftLabel              *widget.Label
	encBtn, decBtn             *widget.Button
	keysLeftCaptionLabel       *widget.Label
	encHintLabel, decHintLabel *widget.Label
	clearLogBtn                *widget.Button
	modeLabel                  *widget.Label

	progressCard  *widget.Card
	progressBar   *widget.ProgressBar
	progressLabel *widget.Label
	progressTitle string

	selectedUserIdx int
	recipientSelect *widget.Select
	recipientCard   *widget.Card
)

func runOnMain(f func())     { fyne.Do(f) }
func runOnMainWait(f func()) { fyne.DoAndWait(f) }

func uiProgressStart(title string) {
	progressTitle = title
	runOnMain(func() {
		if progressLabel != nil {
			progressLabel.SetText(title + "… 0%")
		}
		if progressBar != nil {
			progressBar.SetValue(0)
		}
		if progressCard != nil {
			progressCard.Show()
		}
	})
}

func uiProgressSet(f float64) {
	runOnMain(func() {
		if progressBar != nil {
			progressBar.SetValue(f)
		}
		if progressLabel != nil {
			progressLabel.SetText(fmt.Sprintf("%s… %d%%", progressTitle, int(f*100)))
		}
	})
}

func uiProgressDone() {
	runOnMain(func() {
		if progressCard != nil {
			progressCard.Hide()
		}
	})
}

func getModeLabelText() string {
	if isCenterMode {
		return tr("mode_center")
	}
	return tr("mode_user")
}

func ownerToUserIndex(owner byte) int {
	idx := int(owner)
	if idx >= 0 && idx < len(session_keys_ro) {
		return idx
	}
	return localUserIndex
}

func SetLastKeyHashFromBytes(b []byte) {
	lastKeyHashHex = hex.EncodeToString(b)
}

func SetLastKeyHash(hexStr string) {
	lastKeyHashHex = hexStr
}

func makeEncryptButton(win fyne.Window, logs *widget.RichText, keysLeft *widget.Label) *widget.Button {
	icon, err := fyne.LoadResourceFromPath("assets/encrypt.png")
	if err != nil {
		icon = theme.ConfirmIcon()
	}
	btn := widget.NewButtonWithIcon(tr("encrypt"), icon, func() {
		if (len(session_keys) == 0 && len(circle_keys) == 0) || rimitkeyAllZero() {
			dialog.ShowError(fmt.Errorf(tr("need_keys_first")), win)
			return
		}

		fileDialog := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				addLog(logs, fmt.Sprintf(tr("open_error"), err))
				return
			}
			if reader == nil {
				return
			}
			defer reader.Close()

			uri := reader.URI()

			lr := &io.LimitedReader{R: reader, N: MaxPlainSize + 1}
			data, err := io.ReadAll(lr)
			if err != nil {
				uiLog(logs, fmt.Sprintf(tr("read_error"), err))
				return
			}
			if int64(len(data)) > MaxPlainSize || lr.N == 0 {
				dialog.ShowError(fmt.Errorf(tr("file_too_big")), win)
				return
			}

			// в центре шифруем для selectedUserIdx, иначе — для localUserIndex
			targetIdx := selectedUserIdx
			if !isCenterMode {
				targetIdx = localUserIndex
			}
			rKey, keyType, circleNo, _, usedIdx, err := chooseKeyForEncryption(targetIdx)

			if err != nil || rKey == nil {
				dialog.ShowError(fmt.Errorf(tr("need_keys_first")), win)
				return
			}

			// IV
			iv := make([]byte, qalqan.BLOCKLEN)
			if _, err := crand.Read(iv); err != nil {
				uiLog(logs, fmt.Sprintf(tr("iv_generation_error"), err))
				return
			}

			ext := strings.ToLower(filepath.Ext(uri.Path()))
			var fileTypeCode byte
			switch ext {
			case ".jpg", ".jpeg", ".png", ".bmp", ".gif", ".webp", ".tiff":
				fileTypeCode = FileTypePhoto
			case ".txt", ".md", ".log", ".csv":
				fileTypeCode = FileTypeText
			case ".mp3", ".wav", ".ogg", ".m4a", ".flac":
				fileTypeCode = FileTypeAudio
			case ".mp4", ".mov", ".avi", ".mkv", ".wmv", ".flv", ".webm", ".m4v":
				fileTypeCode = FileTypeVideo
			default:
				fileTypeCode = FileTypeGeneric
			}
			svc := buildServiceInfo(fileTypeCode, keyType, int(circleNo), usedIdx)

			runOnMain(func() {
			})
			uiProgressStart(tr("encrypting"))

			selPath := uri.Path()
			selName := uri.Name()

			go func(selPath, selName string, payload []byte, svc [qalqan.BLOCKLEN]byte, rKey, iv []byte, keyType byte, usedIdx int) {
				defer func() {
					if r := recover(); r != nil {
						uiLog(logs, fmt.Sprintf("panic (encrypt): %v", r))
					}
					uiProgressDone()
				}()

				ctBuf := &bytes.Buffer{}
				pr := &progressReader{
					r:     bytes.NewReader(payload),
					total: int64(len(payload)),
					emit: func(f float64) {
						runOnMain(func() {
							uiProgressSet(f)
						})
					},
				}
				qalqan.EncryptOFB_File(len(payload), rKey, iv, pr, ctBuf)

				out := &bytes.Buffer{}
				out.Write(svc[:])
				meta := make([]byte, qalqan.BLOCKLEN)
				qalqan.Qalqan_Imit(uint64(qalqan.BLOCKLEN), rimitkey, bytes.NewReader(svc[:]), meta)
				out.Write(meta)
				out.Write(iv)
				out.Write(ctBuf.Bytes())
				fileImit := make([]byte, qalqan.BLOCKLEN)
				qalqan.Qalqan_Imit(uint64(out.Len()), rimitkey, bytes.NewReader(out.Bytes()), fileImit)
				out.Write(fileImit)

				if keyType == KeyTypeSessionOut && usedIdx >= 0 {
					runOnMain(func() {
						keysLeft.SetText(fmt.Sprintf("%d", countRemainingSessionOut(targetIdx)))
					})
				}
				runOnMainWait(func() {

					saveDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
						if err != nil {
							addLog(logs, fmt.Sprintf(tr("save_error"), err))
							return
						}
						if writer == nil {
							return
						}
						defer writer.Close()

						if _, err = writer.Write(out.Bytes()); err != nil {
							addLog(logs, fmt.Sprintf(tr("write_error"), err))
							return
						}
						addLog(logs, tr("encrypt_saved_ok"))
					}, win)

					base := selPath
					if strings.TrimSpace(base) == "" {
						base = baseName(selName)
					}
					saveDialog.SetFileName(suggestEncryptedNameFromPath(base))
					saveDialog.SetFilter(storage.NewExtensionFileFilter([]string{".bin"}))
					saveDialog.Show()
				})
			}(
				selPath,
				selName,
				append([]byte(nil), data...),
				svc,
				append([]byte(nil), rKey...),
				append([]byte(nil), iv...),
				keyType, usedIdx,
			)
		}, win)

		fileDialog.Show()
	})
	return btn
}

func rimitkeyAllZero() bool {
	if len(rimitkey) == 0 {
		return true
	}
	for _, b := range rimitkey {
		if b != 0 {
			return false
		}
	}
	return true
}

func makeDecryptButton(win fyne.Window, logs *widget.RichText) *widget.Button {
	icon, err := fyne.LoadResourceFromPath("assets/decrypt.png")
	if err != nil {
		icon = theme.CancelIcon()
	}
	btn := widget.NewButtonWithIcon(tr("decrypt"), icon, func() {
		if len(session_keys_ro) == 0 && len(circle_keys) == 0 {
			dialog.ShowError(fmt.Errorf(tr("need_keys_first")), win)
			return
		}

		fileDialog := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				addLog(logs, fmt.Sprintf(tr("open_error"), err))
				return
			}
			if reader == nil {
				return
			}
			defer reader.Close()

			uri := reader.URI()
			uiLog(logs, "Файл выбран для расшифрования: "+uri.String())

			lr := &io.LimitedReader{R: reader, N: MaxEncryptedSize + 1}
			data, err := io.ReadAll(lr)
			if err != nil {
				uiLog(logs, fmt.Sprintf(tr("read_error"), err))
				return
			}
			if int64(len(data)) > MaxEncryptedSize || lr.N == 0 {
				dialog.ShowError(fmt.Errorf(tr("file_too_big")), win)
				return
			}

			if len(data) < 3*qalqan.BLOCKLEN {
				uiLog(logs, tr("file_too_short"))
				return
			}

			// Проверка общего IMIT
			calc := make([]byte, qalqan.BLOCKLEN)
			qalqan.Qalqan_Imit(uint64(len(data)-qalqan.BLOCKLEN), rimitkey, bytes.NewReader(data[:len(data)-qalqan.BLOCKLEN]), calc)
			rimit := data[len(data)-qalqan.BLOCKLEN:]
			if subtle.ConstantTimeCompare(calc, rimit) != 1 {
				uiLog(logs, tr("file_corrupted"))
				return
			}

			// Заголовок
			serviceinfo := data[:qalqan.BLOCKLEN]
			storedMetaImit := data[qalqan.BLOCKLEN : 2*qalqan.BLOCKLEN]
			comp := make([]byte, qalqan.BLOCKLEN)
			qalqan.Qalqan_Imit(uint64(qalqan.BLOCKLEN), rimitkey, bytes.NewReader(serviceinfo), comp)
			if subtle.ConstantTimeCompare(comp, storedMetaImit) != 1 {
				uiLog(logs, tr("file_info_imit_mismatch"))
				return
			}

			pos := 2 * qalqan.BLOCKLEN
			userNumber := serviceinfo[1]
			fileType := serviceinfo[4]
			keyType := serviceinfo[5]
			circleKeyNumber := int(serviceinfo[6])
			low := int(serviceinfo[8] & 0x03)
			high := int(serviceinfo[7])
			sessionIndex := ((high << 8) | low) - 1

			if len(data) < pos+qalqan.BLOCKLEN {
				uiLog(logs, tr("invalid_file_no_iv"))
				return
			}
			iv := data[pos : pos+qalqan.BLOCKLEN]
			pos += qalqan.BLOCKLEN
			end := len(data) - qalqan.BLOCKLEN
			if end < pos {
				uiLog(logs, tr("invalid_file_not_enough_data"))
				return
			}
			ct := data[pos:end]
			if len(ct)%qalqan.BLOCKLEN != 0 {
				uiLog(logs, tr("invalid_file_not_enough_data"))
				return
			}

			// Ключ
			var rKey []byte
			switch keyType {
			case KeyTypeCircle:
				rKey = useAndDeleteCircleKey(circleKeyNumber)
			case KeyTypeSessionOut:
				uidx := ownerToUserIndex(userNumber)
				if sessionIndex < 0 || sessionIndex >= 1000 {
					uiLog(logs, tr("invalid_session_index"))
					return
				}
				rKey = getSessionKeyExact(uidx, false, sessionIndex)
				if rKey == nil {
					rKey = getSessionKeyExact(uidx, true, sessionIndex)
				}
			case KeyTypeSessionIn:
				uidx := ownerToUserIndex(userNumber)
				if sessionIndex < 0 || sessionIndex >= 1000 {
					uiLog(logs, tr("invalid_session_index"))
					return
				}
				rKey = getSessionKeyExact(uidx, true, sessionIndex)
				if rKey == nil {
					rKey = getSessionKeyExact(uidx, false, sessionIndex)
				}
			default:
				uiLog(logs, fmt.Sprintf(tr("unknown_key_type"), keyType))
				return
			}
			if rKey == nil {
				uiLog(logs, tr("decryption_key_not_available"))
				return
			}
			uiProgressStart(tr("decrypting"))

			go func(encPath string, ct, iv, rKey []byte, fileType byte) {
				defer func() {
					if r := recover(); r != nil {
						uiLog(logs, fmt.Sprintf("panic (decrypt): %v", r))
					}
					uiProgressDone()
				}()

				out := &bytes.Buffer{}
				pr := &progressReader{
					r:     bytes.NewReader(ct),
					total: int64(len(ct)),
					emit: func(f float64) {
						runOnMain(func() {
							uiProgressSet(f)
						})
					},
				}
				if err := qalqan.DecryptOFB_File(len(ct), rKey, iv, pr, out); err != nil {
					uiLog(logs, fmt.Sprintf(tr("decrypt_error"), err))
					return
				}
				plain := out.Bytes()

				runOnMainWait(func() {

					saveDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
						if err != nil {
							addLog(logs, fmt.Sprintf(tr("save_error"), err))
							return
						}
						if writer == nil {
							return
						}
						defer writer.Close()

						if _, err := writer.Write(plain); err != nil {
							addLog(logs, fmt.Sprintf(tr("write_error"), err))
							return
						}
						addLog(logs, tr("decrypt_saved_ok"))
					}, win)

					saveDialog.SetFileName(suggestDecryptedNameFromPath(encPath, fileType))
					saveDialog.Show()
				})

			}(
				uri.Path(),                   // encPath
				append([]byte(nil), ct...),   // ct
				append([]byte(nil), iv...),   // iv
				append([]byte(nil), rKey...), // rKey
				fileType,                     // fileType
			)
		}, win)

		fileDialog.SetFilter(storage.NewExtensionFileFilter([]string{".bin"}))
		fileDialog.Show()
	})

	return btn
}

func UI_OnKeysLoaded(
	kikey []byte,
	sess []qalqan.SessionKeySet,
	circ [100][qalqan.DEFAULT_KEY_LEN]byte,
	imitKey []byte,
	passwordHash32 [32]byte,
) {
	session_keys = sess
	session_keys_ro = cloneSessionKeys(sess)
	circle_keys = circ
	if len(imitKey) == qalqan.EXPKLEN {
		rimitkey = make([]byte, qalqan.EXPKLEN)
		copy(rimitkey, imitKey)
	}
}
