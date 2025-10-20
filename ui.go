package main

import (
	"QalqanDS/qalqan"
	"bytes"
	crand "crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"os"
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
	FileTypeGeneric = 0x00
	FileTypeVideo   = 0x77
	FileTypePhoto   = 0x88
	FileTypeText    = 0x00
	FileTypeAudio   = 0x55

	MaxPlainSize int64 = 2 * 1024 * 1024 * 1024 // 2Gb

	MaxEncryptedSize int64 = MaxPlainSize + 80 // (serviceinfo + metaImit + IV + fileImit) +16 = 64

	KeysValidityDays = 90
	KeyValidityDays  = 30
)

type KeyPref int

const (
	KeyPrefSession KeyPref = iota
	KeyPrefCircle
)

var SkeyInCnt int
var SkeyOutCnt int

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

func SetLocalUserNumber(n int) {
	if n <= 0 || n > 255 {
		n = 1
	}
	localUserNumber = byte(n)
}

func buildServiceInfo(fileTypeCode, keyType byte, circleNo int, usedIdx int) [qalqan.BLOCKLEN]byte {
	var s [qalqan.BLOCKLEN]byte
	s[0] = 0x00
	if isCenterMode {
		s[1] = 0x33 // метка Центра
	} else {
		s[1] = byte(localUserNumber) // номер отправителя (1..N)
	}
	s[2] = 0x04
	s[3] = byte(qalqan.DEFAULT_KEY_LEN) // 0x20
	s[4] = fileTypeCode
	s[5] = keyType

	if circleNo >= 0 && circleNo < len(circle_keys) {
		s[6] = byte(circleNo)
	}

	if usedIdx > 0 && usedIdx <= 0xFFFF {
		s[7] = byte(usedIdx >> 8)
		s[8] = byte(usedIdx)
	}
	// [9..15] = 0
	return s
}

func decodeSessionIndex(si []byte) int {
	if len(si) < 9 {
		return -1
	}

	nBE := int(si[7])<<8 | int(si[8])
	return (nBE - 1) // если -1 (нет индекса), иначе 0-базовый индекс
}

func keyPrefIsSession() bool { return keyPref == KeyPrefSession }

func suggestEncryptedNameFromPath(p string) string {
	b := baseName(p)
	if strings.EqualFold(filepath.Ext(b), ".bin") {
		return b
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
	b := baseName(p)
	name := b
	if strings.EqualFold(filepath.Ext(b), ".bin") {
		name = b[:len(b)-len(".bin")]
	}

	if filepath.Ext(name) == "" {
		name += fileTypeDefaultExt(fileType)
	}
	if strings.TrimSpace(name) == "" {
		name = "File_" + time.Now().Format("2006-01-02_15-04") + fileTypeDefaultExt(fileType)
	}
	return name
}

func readKeysExpiryDates(path string, centerMode bool) (keysExp, keyExp time.Time, err error) {
	f, err := os.Open(path)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	defer f.Close()

	hdr := make([]byte, 16)
	if _, err = io.ReadFull(f, hdr); err != nil {
		return time.Time{}, time.Time{}, err
	}

	if centerMode {
		ke := unix32LEToTime(hdr[0:4])
		e := unix32LEToTime(hdr[4:8])

		if ke.IsZero() {
			start := be16DaysToTime(hdr[0], hdr[1])
			if !start.IsZero() {
				ke = start.AddDate(0, 0, KeysValidityDays)
			}
		}
		if e.IsZero() {
			start := be16DaysToTime(hdr[2], hdr[3])
			if !start.IsZero() {
				e = start.AddDate(0, 0, KeyValidityDays)
			}
		}
		return ke, e, nil
	}

	if t := unix32LEToTime(hdr[5:9]); !t.IsZero() {
		return t, time.Time{}, nil
	}

	startKeys := be16DaysToTime(hdr[5], hdr[6])
	startKey := be16DaysToTime(hdr[7], hdr[8])
	if !startKeys.IsZero() {
		startKeys = startKeys.AddDate(0, 0, KeysValidityDays)
	}
	if !startKey.IsZero() {
		startKey = startKey.AddDate(0, 0, KeyValidityDays)
	}
	return startKeys, startKey, nil
}

func ruDays(n int) string {
	a := n % 100
	if a >= 11 && a <= 14 {
		return "дней"
	}
	b := n % 10
	switch b {
	case 1:
		return "день"
	case 2, 3, 4:
		return "дня"
	default:
		return "дней"
	}
}

func enDays(n int) string {
	if n == 1 {
		return "day"
	}
	return "days"
}

func daysWord(n int) string {
	switch strings.ToUpper(currentLang) {
	case "RU":
		return ruDays(n)
	case "KZ":
		return "күн"
	default:
		return enDays(n)
	}
}

func formatKeysCountdownText(exp time.Time) string {
	if exp.IsZero() {
		return ""
	}
	now := time.Now()
	leftDays := int(exp.Sub(now).Hours() / 24)
	if leftDays < 0 {
		leftDays = 0
	}
	d := exp.Format("02.01.2006")
	return fmt.Sprintf(tr("keys_countdown"), leftDays, daysWord(leftDays), d)
}

func unix32LEToTime(b []byte) time.Time {
	if len(b) < 4 {
		return time.Time{}
	}
	ts := binary.LittleEndian.Uint32(b)
	if ts == 0 {
		return time.Time{}
	}
	return time.Unix(int64(ts), 0).In(time.Local)
}

func be16DaysToTime(hi, lo byte) time.Time {
	days := int64(hi)<<8 | int64(lo)
	if days <= 0 {
		return time.Time{}
	}
	return time.Unix(days*86400, 0).In(time.Local)
}

func updateKeysDates(keysPath string) {
	keysExp, _, err := readKeysExpiryDates(keysPath, isCenterMode)
	if err != nil {
		keysDatesText = ""
		keysExpiryCache = time.Time{}
	} else {
		keysExpiryCache = keysExp
		keysDatesText = formatKeysCountdownText(keysExpiryCache)
	}
	if keysDateLabel != nil {
		runOnMain(func() { keysDateLabel.SetText(keysDatesText) })
	}
}

var (
	isCenterMode    bool
	session_keys    []qalqan.SessionKeySet
	circle_keys     [][qalqan.DEFAULT_KEY_LEN]byte
	rimitkey        []byte
	localUserIndex       = 0
	localUserNumber byte = 1
	keysDateLabel   *widget.Label
	keysDatesText   string
	lastKeyHashHex  string
	keysExpiryCache time.Time
	nextOutIdx      []int
	nextCircleIdx   int
)

func init() {
	rimitkey = make([]byte, qalqan.EXPKLEN)
}

func ApplyLocalUserContext(keysPath string, users int) {
	base := strings.ToLower(filepath.Base(keysPath))
	if strings.Contains(base, "center") || users > 1 {
		isCenterMode = true
		localUserNumber = 0x33
		localUserIndex = 0
	} else {
		isCenterMode = false
		localUserNumber = 1
		localUserIndex = 0
	}
	updateKeysDates(keysPath)
}

func sessionKeyAllZero(k *[qalqan.DEFAULT_KEY_LEN]byte) bool {
	for i := 0; i < qalqan.DEFAULT_KEY_LEN; i++ {
		if k[i] != 0 {
			return false
		}
	}
	return true
}

func circleKeyAllZero(k *[qalqan.DEFAULT_KEY_LEN]byte) bool {
	for i := 0; i < qalqan.DEFAULT_KEY_LEN; i++ {
		if k[i] != 0 {
			return false
		}
	}
	return true
}

func useCircleKey(circleKeyNumber int) []uint8 {
	if circleKeyNumber < 0 || circleKeyNumber >= len(circle_keys) {
		return nil
	}
	if circleKeyAllZero(&circle_keys[circleKeyNumber]) {
		return nil
	}
	key := circle_keys[circleKeyNumber][:]
	rkey := make([]uint8, qalqan.EXPKLEN)
	qalqan.Kexp(key, qalqan.DEFAULT_KEY_LEN, qalqan.BLOCKLEN, rkey)

	return rkey
}

func pickAnyCircleKey() (int, []byte) {
	n := len(circle_keys)
	if n == 0 {
		return -1, nil
	}

	available := make([]int, 0, n)
	for i := 0; i < n; i++ {
		if !circleKeyAllZero(&circle_keys[i]) {
			available = append(available, i)
		}
	}
	if len(available) == 0 {
		return -1, nil
	}

	r, err := crand.Int(crand.Reader, big.NewInt(int64(len(available))))
	if err != nil {
		idx := available[0]
		if rk := useCircleKey(idx); rk != nil {
			nextCircleIdx = (idx + 1) % n
			return idx, rk
		}
		return -1, nil
	}

	idx := available[r.Int64()]
	if rk := useCircleKey(idx); rk != nil {
		nextCircleIdx = (idx + 1) % n
		return idx, rk
	}

	for _, j := range available {
		if rk := useCircleKey(j); rk != nil {
			nextCircleIdx = (j + 1) % n
			return j, rk
		}
	}
	return -1, nil
}

func useAndDeleteSessionIn(userIdx, idx int) ([]uint8, int) {
	if len(session_keys) == 0 || userIdx < 0 || userIdx >= len(session_keys) {
		return nil, -1
	}
	inCnt := len(session_keys[userIdx].In)
	if idx < 0 || idx >= inCnt {
		return nil, -1
	}
	if sessionKeyAllZero(&session_keys[userIdx].In[idx]) {
		return nil, -1
	}
	raw := session_keys[userIdx].In[idx][:]
	rkey := make([]uint8, qalqan.EXPKLEN)
	qalqan.Kexp(raw, qalqan.DEFAULT_KEY_LEN, qalqan.BLOCKLEN, rkey)

	for j := 0; j < qalqan.DEFAULT_KEY_LEN; j++ {
		session_keys[userIdx].In[idx][j] = 0
	}
	return rkey, idx
}

func useAndDeleteSessionOut(userIdx int, start int) ([]uint8, int) {
	if len(session_keys) == 0 || userIdx < 0 || userIdx >= len(session_keys) {
		return nil, -1
	}
	outCnt := len(session_keys[userIdx].Out)
	if outCnt <= 0 {
		return nil, -1
	}

	for ofs := 0; ofs < outCnt; ofs++ {
		idx := (start + ofs) % outCnt
		if !sessionKeyAllZero(&session_keys[userIdx].Out[idx]) {
			raw := session_keys[userIdx].Out[idx][:]
			rkey := make([]uint8, qalqan.EXPKLEN)
			qalqan.Kexp(raw, qalqan.DEFAULT_KEY_LEN, qalqan.BLOCKLEN, rkey)

			for j := 0; j < qalqan.DEFAULT_KEY_LEN; j++ {
				session_keys[userIdx].Out[idx][j] = 0
			}

			nextOutIdx[userIdx] = (idx + 1) % outCnt
			if nextOutIdx[userIdx] >= outCnt {
				nextOutIdx[userIdx] = 0
			}

			if isCenterMode {
				_ = writeCurrentKeysFile()
			}
			return rkey, idx
		}
	}
	return nil, -1
}

func countRemainingSessionOut(userIdx int) int {
	if len(session_keys) == 0 || userIdx < 0 || userIdx >= len(session_keys) {
		return 0
	}
	cnt := 0
	for i := 0; i < len(session_keys[userIdx].Out); i++ {
		if !sessionKeyAllZero(&session_keys[userIdx].Out[i]) {
			cnt++
		}
	}
	return cnt
}

func countRemainingSessionIn(userIdx int) int {
	if len(session_keys) == 0 || userIdx < 0 || userIdx >= len(session_keys) {
		return 0
	}
	cnt := 0
	for i := 0; i < len(session_keys[userIdx].In); i++ {
		if !sessionKeyAllZero(&session_keys[userIdx].In[i]) {
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

func chooseKeyForEncryption(targetUserIdx int, useSession bool) (rKey []byte, keyTypeByte byte, circleIndex int, usedIdx int, err error) {
	if useSession {
		if len(session_keys) == 0 {
			return nil, 0, -1, -1, fmt.Errorf("no session keys loaded")
		}
		uidx := targetUserIdx
		if uidx < 0 || uidx >= len(session_keys) {
			uidx = localUserIndex
		}
		start := nextOutIdx[uidx]
		if rk, idx := useAndDeleteSessionOut(uidx, start); rk != nil && idx >= 0 {
			return rk, 0x01, -1, idx, nil // 0x01 = session
		}
		return nil, 0, -1, -1, fmt.Errorf("session keys empty for user #%d", uidx+1)
	}

	if ci, rk := pickAnyCircleKey(); rk != nil {
		return rk, 0x00, ci, -1, nil // 0x00 = circle
	}
	return nil, 0, -1, -1, fmt.Errorf("no circle keys available")
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
		layout.NewSpacer(),
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

func keyPrefOptions() []string {
	return []string{tr("key_type_session"), tr("key_type_circle")}
}
func keyPrefToLabel(p KeyPref) string {
	if p == KeyPrefCircle {
		return tr("key_type_circle")
	}
	return tr("key_type_session")
}
func labelToKeyPref(s string) KeyPref {
	if s == tr("key_type_circle") {
		return KeyPrefCircle
	}
	return KeyPrefSession
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
		if keysLeftLabel != nil {
			idx := selectedUserIdx
			if !isCenterMode {
				idx = localUserIndex
			}
			keysLeftLabel.SetText(formatKeysLeft(idx))
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
		if keyTypeCard != nil {
			keyTypeCard.Subtitle = tr("select_key_type")
			keyTypeCard.Refresh()
		}
		if keyTypeSelect != nil {
			keyTypeSelect.Options = keyPrefOptions()
			keyTypeSelect.SetSelected(keyPrefToLabel(keyPref))
		}
		if keysLeftCaptionLabel != nil {
			keysLeftCaptionLabel.SetText(tr("keys_left"))
		}
		if keysDateLabel != nil {
			keysDateLabel.SetText(formatKeysCountdownText(keysExpiryCache))
		}
	}

	logs, logsArea := makeLogsArea()

	keysLeftLabel = widget.NewLabelWithStyle(formatKeysLeft(localUserIndex),
		fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	keysLeftLabel.TextStyle.Monospace = true

	keysLeftCaptionLabel = widget.NewLabelWithStyle(tr("keys_left"),
		fyne.TextAlignCenter, fyne.TextStyle{Italic: true})

	keysCard := widget.NewCard("", "", container.NewVBox(
		container.NewCenter(keysLeftLabel),
		container.NewCenter(keysLeftCaptionLabel),
	))
	keysWrap := container.NewGridWrap(fyne.NewSize(280, 100), keysCard)

	if len(session_keys) > 0 {
		keyPref = KeyPrefSession
	} else {
		keyPref = KeyPrefCircle
	}

	keyTypeSelect = widget.NewSelect(keyPrefOptions(), func(s string) {
		keyPref = labelToKeyPref(s)
	})
	keyTypeSelect.SetSelected(keyPrefToLabel(keyPref))

	keyTypeCard = widget.NewCard("", tr("select_key_type"), container.NewVBox(keyTypeSelect))
	keyTypeWrap := container.NewGridWrap(fyne.NewSize(200, 100), keyTypeCard)

	var recipientWrap fyne.CanvasObject
	if isCenterMode && len(session_keys) > 0 {
		opts := make([]string, len(session_keys))
		for i := range session_keys {
			opts[i] = strconv.Itoa(i + 1)
		}
		recipientSelect = widget.NewSelect(opts, func(val string) {
			if i, err := strconv.Atoi(val); err == nil {
				selectedUserIdx = i - 1
				keysLeftLabel.SetText(formatKeysLeft(selectedUserIdx))
			}
		})
		selectedUserIdx = 0
		recipientSelect.SetSelected(opts[0])
		keysLeftLabel.SetText(formatKeysLeft(selectedUserIdx))

		recipientCard = widget.NewCard("", tr("encrypt_to"), container.NewVBox(recipientSelect))
		recipientWrap = container.NewGridWrap(fyne.NewSize(200, 100), recipientCard)
	} else {
		selectedUserIdx = localUserIndex
	}

	encBtn = makeEncryptButton(win, logs, keysLeftLabel)
	decBtn = makeDecryptButton(win, logs)

	encBtnWrap := container.NewGridWrap(fyne.NewSize(130, 44), encBtn)
	decBtnWrap := container.NewGridWrap(fyne.NewSize(130, 44), decBtn)

	encIcon, _ := fyne.LoadResourceFromPath("assets/encrypt.png")
	if encIcon == nil {
	}
	decIcon, _ := fyne.LoadResourceFromPath("assets/decrypt.png")
	if decIcon == nil {
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

	encCardWrap := container.NewGridWrap(fyne.NewSize(285, 110), encCard)
	decCardWrap := container.NewGridWrap(fyne.NewSize(285, 110), decCard)

	modeLabel = widget.NewLabelWithStyle(getModeLabelText(), fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	keysDateLabel = widget.NewLabelWithStyle(keysDatesText, fyne.TextAlignLeading, fyne.TextStyle{Italic: true})

	left := container.NewHBox(
		modeLabel,
		widget.NewLabel("  "),
		keysDateLabel,
	)

	topBar := container.NewHBox(
		container.NewPadded(left),
		layout.NewSpacer(),
		container.NewGridWrap(fyne.NewSize(65, 28), selectedLanguage),
	)

	rowElems := []fyne.CanvasObject{layout.NewSpacer(), keysWrap, widget.NewLabel("  "), keyTypeWrap}
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
	keysLeftCaptionLabel       *widget.Label
	encBtn, decBtn             *widget.Button
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
	keyPref         KeyPref
	keyTypeSelect   *widget.Select
	keyTypeCard     *widget.Card
)

func formatKeysLeft(uIdx int) string {
	return fmt.Sprintf(tr("keys_left_inout"),
		countRemainingSessionIn(uIdx),
		countRemainingSessionOut(uIdx),
	)
}

func runOnMain(f func()) { fyne.Do(f) }

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
	return fmt.Sprintf("%s %s", tr("mode_user"), fmt.Sprintf(tr("user_n"), int(localUserNumber+1)))
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
		if rimitkeyAllZero() {
			dialog.ShowError(fmt.Errorf(tr("need_keys_first")), win)
			return
		}
		if (len(session_keys) == 0 || (countRemainingSessionIn(localUserIndex)+countRemainingSessionOut(localUserIndex) == 0)) && noCircleKeys() {
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

			uri := reader.URI()

			go func(reader fyne.URIReadCloser, uri fyne.URI) {
				defer reader.Close()

				lr := &io.LimitedReader{R: reader, N: MaxPlainSize + 1}
				data, err := io.ReadAll(lr)
				if err != nil {
					uiLog(logs, fmt.Sprintf(tr("read_error"), err))
					return
				}
				if int64(len(data)) > MaxPlainSize || lr.N == 0 {
					runOnMain(func() { dialog.ShowError(fmt.Errorf(tr("file_too_big")), win) })
					return
				}

				targetIdx := selectedUserIdx
				if !isCenterMode {
					targetIdx = localUserIndex
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

				useSession := keyPrefIsSession()
				rKey, keyTypeByte, circleNo, usedIdx, err := chooseKeyForEncryption(targetIdx, useSession)
				if err != nil || rKey == nil {
					runOnMain(func() { dialog.ShowError(fmt.Errorf(tr("need_keys_first")), win) })
					return
				}

				iv := make([]byte, qalqan.BLOCKLEN)
				if _, err := crand.Read(iv); err != nil {
					uiLog(logs, fmt.Sprintf(tr("iv_generation_error"), err))
					return
				}

				svc := buildServiceInfo(fileTypeCode, keyTypeByte, circleNo, usedIdx+1)

				uiProgressStart(tr("encrypting"))

				selPath := uri.Path()
				selName := uri.Name()

				ctBuf := &bytes.Buffer{}
				pr := &progressReader{
					r:     bytes.NewReader(data),
					total: int64(len(data)),
					emit:  func(f float64) { runOnMain(func() { uiProgressSet(f) }) },
				}
				qalqan.EncryptOFB_File(len(data), rKey, iv, pr, ctBuf)

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

				if useSession && usedIdx >= 0 {
					runOnMain(func() {
						keysLeft.SetText(formatKeysLeft(targetIdx))
					})
					persistKeysToDiskAsync(logs)
				}

				runOnMain(func() {
					saveDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
						if err != nil {
							addLog(logs, fmt.Sprintf(tr("save_error"), err))
							return
						}
						if writer == nil {
							return
						}

						go func() {
							defer writer.Close()
							data := out.Bytes()
							const chunk = 8 << 20 // 8MB
							for off := 0; off < len(data); off += chunk {
								end := off + chunk
								if end > len(data) {
									end = len(data)
								}
								if _, werr := writer.Write(data[off:end]); werr != nil {
									runOnMain(func() {
										addLog(logs, fmt.Sprintf(tr("write_error"), werr))
										uiProgressDone()
									})
									return
								}
								runOnMain(func() { uiProgressSet(float64(end) / float64(len(data))) })
							}
							runOnMain(func() {
								uiProgressDone()
								addLog(logs, tr("encrypt_saved_ok"))
							})
						}()
					}, win)

					base := selPath
					if strings.TrimSpace(base) == "" {
						base = baseName(selName)
					}
					saveDialog.Resize(fyne.NewSize(700, 700))
					saveDialog.SetFileName(suggestEncryptedNameFromPath(base))
					saveDialog.SetFilter(storage.NewExtensionFileFilter([]string{".bin"}))
					saveDialog.Show()
				})
			}(reader, uri)
		}, win)

		fileDialog.Resize(fyne.NewSize(700, 700))
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

func noCircleKeys() bool {
	for i := 0; i < len(circle_keys); i++ {
		if !circleKeyAllZero(&circle_keys[i]) {
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
		if len(session_keys) == 0 && noCircleKeys() {
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

			calc := make([]byte, qalqan.BLOCKLEN)
			qalqan.Qalqan_Imit(uint64(len(data)-qalqan.BLOCKLEN), rimitkey, bytes.NewReader(data[:len(data)-qalqan.BLOCKLEN]), calc)
			rimit := data[len(data)-qalqan.BLOCKLEN:]
			if subtle.ConstantTimeCompare(calc, rimit) != 1 {
				uiLog(logs, tr("file_corrupted"))
				return
			}

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
			sessionIndex := decodeSessionIndex(serviceinfo)

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

			var rKey []byte
			var uidx int

			if isCenterMode {
				if userNumber == 0x33 {
					uiLog(logs, tr("center_file_decrypt_on_recipient"))
					return
				}
				uidx = int(userNumber)
				if uidx < 0 || uidx >= len(session_keys) {
					uiLog(logs, fmt.Sprintf(tr("unknown_sender"), userNumber))
					return
				}
			} else {
				uidx = localUserIndex
			}

			if keyType == 0x00 {
				rKey = useCircleKey(circleKeyNumber)
			} else {
				if sessionIndex < 0 || sessionIndex >= len(session_keys[uidx].In) {
					uiLog(logs, tr("invalid_session_index"))
					return
				}
				rKey, _ = useAndDeleteSessionIn(uidx, sessionIndex)
			}

			if rKey == nil {
				uiLog(logs, tr("decryption_key_not_available"))
				return
			}

			if keyType == 0x01 {
				if keysLeftLabel != nil {
					runOnMain(func() { keysLeftLabel.SetText(formatKeysLeft(uidx)) })
				}
				if isCenterMode && recipientSelect != nil {
					runOnMain(func() {
						selectedUserIdx = uidx
						recipientSelect.SetSelected(strconv.Itoa(uidx + 1))
					})
				}
				persistKeysToDiskAsync(logs)
			}

			uiProgressStart(tr("decrypting"))

			go func(encPath string, ct, iv, rKey []byte, fileType byte) {
				defer func() {
					if r := recover(); r != nil {
						uiLog(logs, fmt.Sprintf("panic (decrypt): %v", r))
					}
				}()

				out := &bytes.Buffer{}
				pr := &progressReader{
					r:     bytes.NewReader(ct),
					total: int64(len(ct)),
					emit:  func(f float64) { runOnMain(func() { uiProgressSet(f) }) },
				}
				if err := qalqan.DecryptOFB_File(len(ct), rKey, iv, pr, out); err != nil {
					runOnMain(func() { uiProgressDone() })
					uiLog(logs, fmt.Sprintf(tr("decrypt_error"), err))
					return
				}
				plain := out.Bytes()

				runOnMain(func() { uiProgressDone() })

				runOnMain(func() {
					saveDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
						if err != nil {
							addLog(logs, fmt.Sprintf(tr("save_error"), err))
							return
						}
						if writer == nil {
							return
						}

						go func() {
							defer writer.Close()

							uiProgressStart(tr("saving"))

							const chunk = 8 << 20 // 8MB
							lastUpdate := time.Now()

							for off := 0; off < len(plain); off += chunk {
								end := off + chunk
								if end > len(plain) {
									end = len(plain)
								}
								if _, werr := writer.Write(plain[off:end]); werr != nil {
									runOnMain(func() {
										addLog(logs, fmt.Sprintf(tr("write_error"), werr))
										uiProgressDone()
									})
									return
								}
								if time.Since(lastUpdate) >= 60*time.Millisecond || end == len(plain) {
									prog := float64(end) / float64(len(plain))
									runOnMain(func() { uiProgressSet(prog) })
									lastUpdate = time.Now()
								}
							}

							runOnMain(func() {
								addLog(logs, tr("decrypt_saved_ok"))
								uiProgressDone()
							})
						}()
					}, win)

					saveDialog.Resize(fyne.NewSize(700, 700))
					saveDialog.SetFileName(suggestDecryptedNameFromPath(encPath, fileType))
					saveDialog.SetFilter(nil)
					saveDialog.Show()
				})

			}(
				uri.Path(),
				append([]byte(nil), ct...),
				append([]byte(nil), iv...),
				append([]byte(nil), rKey...),
				fileType,
			)
		}, win)

		fileDialog.Resize(fyne.NewSize(700, 700))
		fileDialog.SetFilter(storage.NewExtensionFileFilter([]string{".bin"}))
		fileDialog.Show()
	})

	return btn
}

func UI_OnKeysLoaded(
	kikey []byte,
	sess []qalqan.SessionKeySet,
	circ [][qalqan.DEFAULT_KEY_LEN]byte,
	imitKey []byte,
	passwordHash32 [32]byte,
) {
	session_keys = sess
	circle_keys = circ
	if len(imitKey) == qalqan.EXPKLEN {
		rimitkey = make([]byte, qalqan.EXPKLEN)
		copy(rimitkey, imitKey)
	}
	nextOutIdx = make([]int, len(session_keys))
	nextCircleIdx = 0
}
