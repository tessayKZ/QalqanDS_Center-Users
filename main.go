package main

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/theme"
)

var Version = "dev"
var Commit = "none"
var Date = "unknown"

type blackTextTheme struct{}

func (blackTextTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	base := theme.DefaultTheme()
	switch name {
	case theme.ColorNameForeground,
		theme.ColorNamePrimary,
		theme.ColorNameDisabled,
		theme.ColorNamePlaceHolder,
		theme.ColorNameHyperlink:
		return color.Black
	default:
		return base.Color(name, variant)
	}
}
func (blackTextTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}
func (blackTextTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}
func (blackTextTheme) Size(name fyne.ThemeSizeName) float32 {
	return theme.DefaultTheme().Size(name)
}

func main() {
	myApp := app.NewWithID("QalqanDS")
	myApp.Settings().SetTheme(&blackTextTheme{})
	win := myApp.NewWindow("QalqanDS")
	setWindowIcon(win)

	ShowLogin(myApp, win)
	win.Resize(fyne.NewSize(350, 250))
	win.SetFixedSize(false)
	win.CenterOnScreen()
	win.ShowAndRun()
}

/* TODO:
1. Добавить выбор нескольких файлов для зашифрования в один файл .bin;
2. Обновить инструкцию пользования QalqanDS
3. Сделать чтобы Циркулярные и сессионые выбирались по порядку // func useAndDeleteSessionOut(userIdx int, start int) ([]uint8, int) {

0 tgjXqmWmzg
1 jTeDVqbmZS
*/
