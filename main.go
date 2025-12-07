package main

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/theme"
)

const debugMainUI = false // for debug - true

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
	myApp := app.NewWithID("Qalqan-DS")
	myApp.Settings().SetTheme(&blackTextTheme{})
	win := myApp.NewWindow("Qalqan-DS")
	setWindowIcon(win)

	if debugMainUI {
		langPref := myApp.Preferences().String("lang")
		if langPref == "" {
			langPref = "EN"
		}
		currentLang = langPref

		isCenterMode = false

		InitMainUI(myApp, win)

		win.SetFixedSize(false)
		win.Resize(fyne.NewSize(1200, 720))
		win.CenterOnScreen()
	} else {
		ShowLogin(myApp, win)
		win.Resize(fyne.NewSize(350, 250))
		win.SetFixedSize(false)
		win.CenterOnScreen()
	}

	win.ShowAndRun()
}
