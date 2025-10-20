package main

import (
	"QalqanDS/qalqan"
	"bytes"
	crand "crypto/rand"
	"encoding/binary"
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
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func sanitizeFileName(s string) string {
	forbidden := `<>:"/\|?*`
	s = strings.Map(func(r rune) rune {
		if r < 32 {
			return -1
		}
		if strings.ContainsRune(forbidden, r) {
			return '_'
		}
		return r
	}, s)
	s = strings.Trim(s, " .")
	if s == "" {
		s = "archive"
	}
	return s
}

func baseNoExt(p string) string {
	b := filepath.Base(p)
	return strings.TrimSuffix(b, filepath.Ext(b))
}

func commonPrefix(basenames []string) string {
	if len(basenames) == 0 {
		return ""
	}
	p := basenames[0]
	for _, s := range basenames[1:] {
		for !strings.HasPrefix(s, p) && len(p) > 0 {
			p = p[:len(p)-1]
		}
		if p == "" {
			break
		}
	}
	p = strings.Trim(p, " -_.")
	if len(p) > 40 {
		p = p[:40]
	}
	return p
}

func suggestArchiveName(files []string) string {
	ts := time.Now().Format("2006-01-02_15-04")
	if len(files) == 0 {
		return "archive_" + ts + ".bin"
	}
	if len(files) == 1 {
		name := sanitizeFileName(baseNoExt(files[0])) + "_" + ts + ".bin"
		return name
	}
	dir := filepath.Dir(files[0])
	same := true
	for _, f := range files[1:] {
		if filepath.Dir(f) != dir {
			same = false
			break
		}
	}
	if same {
		name := sanitizeFileName(filepath.Base(dir)) + "_" + ts + ".bin"
		return name
	}
	bases := make([]string, len(files))
	for i, f := range files {
		bases[i] = baseNoExt(f)
	}
	if pref := commonPrefix(bases); len(pref) >= 3 {
		return sanitizeFileName(pref) + "_" + ts + ".bin"
	}
	return fmt.Sprintf("archive_%d_%s.bin", len(files), ts)
}

func iconFrom(path string, fallback fyne.Resource) fyne.Resource {
	if res, err := fyne.LoadResourceFromPath(path); err == nil && res != nil {
		return res
	}
	return fallback
}

const svcMultiFlag byte = 0x88

func setMultiFlag(s *[qalqan.BLOCKLEN]byte) {
	s[9] = svcMultiFlag
}

func isMultiArchiveFlag(si []byte) bool {
	return len(si) >= 10 && si[9] == svcMultiFlag
}

const (
	qpkgMagic        = "QPKG"
	qpkgVersion uint = 1
)

func qpkgPlainLen(files []string) (int64, error) {
	var total int64 = 4 + 4 + 4 // magic(4) + version(u32) + count(u32)
	for _, p := range files {
		info, err := os.Stat(p)
		if err != nil {
			return 0, err
		}
		if info.IsDir() {
			return 0, fmt.Errorf("directory not supported: %s", p)
		}
		name := filepath.Base(p)
		if name == "" {
			return 0, fmt.Errorf("bad filename: %s", p)
		}
		if len(name) > 65535 {
			return 0, fmt.Errorf("filename too long: %s", name)
		}
		total += 2 + int64(len(name)) + 8 + info.Size() // per-file: nameLen(u16) + name + size(u64) + data
	}
	return total, nil
}

func writeQpkg(w io.Writer, files []string) error {
	if _, err := w.Write([]byte(qpkgMagic)); err != nil {
		return err
	}
	var b8 [8]byte
	binary.BigEndian.PutUint32(b8[:4], uint32(qpkgVersion))
	if _, err := w.Write(b8[:4]); err != nil {
		return err
	}
	binary.BigEndian.PutUint32(b8[:4], uint32(len(files)))
	if _, err := w.Write(b8[:4]); err != nil {
		return err
	}

	buf := make([]byte, 1<<20) // 1 Mb
	for _, p := range files {
		name := filepath.Base(p)
		f, err := os.Open(p)
		if err != nil {
			return err
		}

		if len(name) > 65535 {
			f.Close()
			return fmt.Errorf("filename too long: %s", name)
		}
		binary.BigEndian.PutUint16(b8[:2], uint16(len(name)))
		if _, err := w.Write(b8[:2]); err != nil {
			f.Close()
			return err
		}
		if _, err := w.Write([]byte(name)); err != nil {
			f.Close()
			return err
		}

		info, _ := f.Stat()
		binary.BigEndian.PutUint64(b8[:8], uint64(info.Size()))
		if _, err := w.Write(b8[:8]); err != nil {
			f.Close()
			return err
		}

		if _, err := io.CopyBuffer(w, f, buf); err != nil {
			f.Close()
			return err
		}
		f.Close()
	}
	return nil
}

func uniquePath(p string) string {
    if _, err := os.Stat(p); os.IsNotExist(err) {
        return p
    }
    dir := filepath.Dir(p)
    base := filepath.Base(p)
    ext := filepath.Ext(base)
    name := strings.TrimSuffix(base, ext)
    for i := 1; ; i++ {
        cand := filepath.Join(dir, fmt.Sprintf("%s_%d%s", name, i, ext))
        if _, err := os.Stat(cand); os.IsNotExist(err) {
            return cand
        }
    }
}

func unpackQpkg(r io.Reader, dest string) error {
	var b8 [8]byte
	magic := make([]byte, 4)
	if _, err := io.ReadFull(r, magic); err != nil {
		return err
	}
	if string(magic) != qpkgMagic {
		return fmt.Errorf("bad qpkg magic")
	}
	if _, err := io.ReadFull(r, b8[:4]); err != nil {
		return err
	}
	ver := binary.BigEndian.Uint32(b8[:4])
	if ver != uint32(qpkgVersion) {
		return fmt.Errorf("unsupported qpkg version %d", ver)
	}
	if _, err := io.ReadFull(r, b8[:4]); err != nil {
		return err
	}
	n := int(binary.BigEndian.Uint32(b8[:4]))

	for i := 0; i < n; i++ {
		if _, err := io.ReadFull(r, b8[:2]); err != nil {
			return err
		}
		nl := int(binary.BigEndian.Uint16(b8[:2]))
		if nl <= 0 || nl > 65535 {
			return fmt.Errorf("bad name length")
		}
		name := make([]byte, nl)
		if _, err := io.ReadFull(r, name); err != nil {
			return err
		}
		clean := filepath.Base(string(name))
		if clean == "" || clean == "." {
			clean = fmt.Sprintf("file_%d", i+1)
		}
		clean = sanitizeFileName(clean)

		if _, err := io.ReadFull(r, b8[:8]); err != nil {
			return err
		}
		sz := int64(binary.BigEndian.Uint64(b8[:8]))

		outPath := uniquePath(filepath.Join(dest, clean))
		out, err := os.Create(outPath)
		if err != nil {
			return err
		}
		if _, err := io.CopyN(out, r, sz); err != nil {
			out.Close()
			return err
		}
		if err := out.Close(); err != nil {
			return err
		}
	}
	return nil
}

func ShowMultiEncryptWindow(win fyne.Window, logs *widget.RichText, keysLeft *widget.Label) {
	files := []string{}
	selected := -1
	var totalSize int64
	var dlg *dialog.CustomDialog

	human := func(n int64) string {
		const kb = 1024
		const mb = 1024 * kb
		const gb = 1024 * mb
		switch {
		case n >= gb:
			return fmt.Sprintf("%.2f Gb", float64(n)/float64(gb))
		case n >= mb:
			return fmt.Sprintf("%.2f Mb", float64(n)/float64(mb))
		case n >= kb:
			return fmt.Sprintf("%.2f Kb", float64(n)/float64(kb))
		default:
			return fmt.Sprintf("%d B", n)
		}
	}
	recalc := func() {
		var sum int64
		for _, p := range files {
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				sum += st.Size()
			}
		}
		totalSize = sum
	}

	infoLbl := widget.NewLabelWithStyle("", fyne.TextAlignCenter, fyne.TextStyle{Italic: true})
	updateInfo := func() {
		recalc()
		infoLbl.SetText(fmt.Sprintf("%s: %d  •  %s: %s",
			tr("selected"), len(files),
			tr("size"), human(totalSize),
		))
	}

	newItem := func() fyne.CanvasObject {
		title := widget.NewLabelWithStyle("file", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
		sub := widget.NewLabelWithStyle("path • size", fyne.TextAlignLeading, fyne.TextStyle{Italic: true})
		return container.NewVBox(title, sub)
	}
	updateItem := func(i widget.ListItemID, o fyne.CanvasObject) {
		if i < 0 || i >= len(files) {
			return
		}
		p := files[i]
		title := filepath.Base(p)
		sizeStr := "—"
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			sizeStr = human(st.Size())
		}
		v := o.(*fyne.Container)
		v.Objects[0].(*widget.Label).SetText(title)
		v.Objects[1].(*widget.Label).SetText(filepath.Dir(p) + "  •  " + sizeStr)
	}

	list := widget.NewList(
		func() int { return len(files) },
		newItem,
		updateItem,
	)
	list.OnSelected = func(id widget.ListItemID) { selected = int(id) }

	addUnique := func(ps ...string) {
		exists := map[string]bool{}
		for _, e := range files {
			exists[e] = true
		}
		for _, p := range ps {
			if p == "" {
				continue
			}
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				if !exists[p] {
					files = append(files, p)
					exists[p] = true
				}
			}
		}
	}

	addFilesBtn := widget.NewButtonWithIcon(
		tr("add_file"),
		iconFrom("assets/addfile.png", theme.ContentAddIcon()),
		func() {
			fd := dialog.NewFileOpen(func(rc fyne.URIReadCloser, err error) {
				if err != nil || rc == nil {
					return
				}
				p := rc.URI().Path()
				rc.Close()
				addUnique(p)
				list.Refresh()
				updateInfo()
			}, win)
			fd.Resize(fyne.NewSize(800, 650))
			fd.Show()
		},
	)

	addFolderBtn := widget.NewButtonWithIcon(
		tr("add_folder"),
		iconFrom("assets/addfolder.png", theme.FolderOpenIcon()),
		func() {
			fdlg := dialog.NewFolderOpen(func(listURI fyne.ListableURI, err error) {
				if err != nil || listURI == nil {
					return
				}
				entries, _ := listURI.List()
				toAdd := []string{}
				for _, u := range entries {
					if u == nil {
						continue
					}
					p := u.Path()
					if st, err := os.Stat(p); err == nil && !st.IsDir() {
						toAdd = append(toAdd, p)
					}
				}
				addUnique(toAdd...)
				list.Refresh()
				updateInfo()
			}, win)
			fdlg.Resize(fyne.NewSize(800, 650))
			fdlg.Show()
		},
	)

	removeBtn := widget.NewButtonWithIcon(
		tr("remove"),
		iconFrom("assets/remove.png", theme.DeleteIcon()),
		func() {
			if selected >= 0 && selected < len(files) {
				files = append(files[:selected], files[selected+1:]...)
				selected = -1
				list.Refresh()
				updateInfo()
			}
		},
	)

	clearBtn := widget.NewButtonWithIcon(
		tr("clear"),
		iconFrom("assets/clear.png", theme.ViewRefreshIcon()),
		func() {
			files = files[:0]
			selected = -1
			list.Refresh()
			updateInfo()
		},
	)

	encryptBtn := widget.NewButtonWithIcon(
		tr("encrypt"),
		iconFrom("assets/encrypt.png", theme.ConfirmIcon()),
		func() {
			if len(files) == 0 {
				dialog.ShowInformation(tr("warning"), tr("nothing_selected"), win)
				return
			}
			if totalSize > MaxPlainSize {
				dialog.ShowError(fmt.Errorf(tr("file_too_big")), win)
				return
			}
			targetIdx := selectedUserIdx
			if !isCenterMode {
				targetIdx = localUserIndex
			}
			dlg.Hide()
			encryptFilesAsQpkg(win, logs, keysLeft, files, targetIdx)
		},
	)

	listCard := widget.NewCard("", "", container.NewMax(list))
	listWrap := container.NewGridWrap(fyne.NewSize(680, 320), listCard)

	header := container.NewHBox(layout.NewSpacer(), infoLbl, layout.NewSpacer())

	const BTN_H float32 = 40
	wrap := func(w float32, o fyne.CanvasObject) fyne.CanvasObject {
		return container.NewGridWrap(fyne.NewSize(w, BTN_H), o)
	}

	actionsGrid := container.New(
		layout.NewGridLayoutWithColumns(5),
		wrap(160, addFilesBtn),
		wrap(160, addFolderBtn),
		wrap(160, removeBtn),
		wrap(160, clearBtn),
		wrap(160, encryptBtn),
	)
	footer := container.NewVBox(
		widget.NewSeparator(),
		container.NewCenter(actionsGrid),
	)

	body := container.NewBorder(nil, nil, nil, nil, listWrap)

	bg := canvas.NewImageFromFile("assets/background.png")
	bg.FillMode = canvas.ImageFillStretch

	content := container.NewStack(
		bg,
		container.NewPadded(container.NewBorder(header, footer, nil, nil, body)),
	)

	dlg = dialog.NewCustom(tr("multiple_files"), tr("close"), content, win)
	dlg.Resize(fyne.NewSize(860, 560))

	updateInfo()
	dlg.Show()
}

func encryptFilesAsQpkg(win fyne.Window, logs *widget.RichText, keysLeft *widget.Label, files []string, targetIdx int) {
	useSession := keyPrefIsSession()
	rKey, keyTypeByte, circleNo, usedIdx, err := chooseKeyForEncryption(targetIdx, useSession)
	if err != nil || rKey == nil {
		dialog.ShowError(fmt.Errorf(tr("need_keys_first")), win)
		return
	}

	totalLen, err := qpkgPlainLen(files)
	if err != nil {
		dialog.ShowError(err, win)
		return
	}
	if totalLen > MaxPlainSize {
		dialog.ShowError(fmt.Errorf(tr("file_too_big")), win)
		return
	}

	iv := make([]byte, qalqan.BLOCKLEN)
	if _, err := crand.Read(iv); err != nil {
		uiLog(logs, fmt.Sprintf(tr("iv_generation_error"), err))
		return
	}

	svc := buildServiceInfo(FileTypeGeneric, keyTypeByte, circleNo, usedIdx+1)
	setMultiFlag(&svc)

	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(writeQpkg(pw, files)) }()

	uiProgressStart(tr("encrypting"))

	ctBuf := &bytes.Buffer{}
	src := &progressReader{
		r:     pr,
		total: totalLen,
		emit:  func(f float64) { runOnMain(func() { uiProgressSet(f) }) },
	}

	var encErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				encErr = fmt.Errorf("encrypt failed: %v", r)
			}
		}()
		qalqan.EncryptOFB_File(int(totalLen), rKey, iv, src, ctBuf)
	}()
	if encErr != nil {
		runOnMain(func() { uiProgressDone() })
		dialog.ShowError(encErr, win)
		return
	}

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
		runOnMain(func() { keysLeft.SetText(formatKeysLeft(targetIdx)) })
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
				const chunk = 8 << 20
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

		saveDialog.Resize(fyne.NewSize(700, 700))
		saveDialog.SetFileName(suggestArchiveName(files))
		saveDialog.SetFilter(storage.NewExtensionFileFilter([]string{".bin"}))
		saveDialog.Show()
	})
}
