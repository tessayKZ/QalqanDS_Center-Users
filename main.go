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