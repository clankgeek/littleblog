package climages

import (
	"fmt"
	"image"
	"strconv"
	"strings"

	"golang.org/x/image/draw"
)

// Color représente une couleur RGB
type Color struct {
	R, G, B int
}

// Fonction pour redimensionner l'image
func Resize(img image.Image, maxWidth int) image.Image {
	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()

	// Si l'image est déjà plus petite, la retourner telle quelle
	if width <= maxWidth {
		return img
	}

	// Calculer les nouvelles dimensions en gardant le ratio
	ratio := float64(maxWidth) / float64(width)
	newWidth := maxWidth
	newHeight := int(float64(height) * ratio)

	// Créer une nouvelle image redimensionnée
	dst := image.NewRGBA(image.Rect(0, 0, newWidth, newHeight))

	// Utiliser l'interpolation de haute qualité
	draw.CatmullRom.Scale(dst, dst.Bounds(), img, bounds, draw.Over, nil)

	return dst
}

// ToHex convertit une couleur en hexadécimal
func (c Color) ToHex() string {
	return fmt.Sprintf("#%02x%02x%02x", c.R, c.G, c.B)
}

// Darken assombrit une couleur par un pourcentage
func (c Color) Darken(percent float64) Color {
	factor := 1.0 - percent/100.0
	return Color{
		R: int(float64(c.R) * factor),
		G: int(float64(c.G) * factor),
		B: int(float64(c.B) * factor),
	}
}

// Lighten éclaircit une couleur par un pourcentage
func (c Color) Lighten(percent float64) Color {
	factor := percent / 100.0
	return Color{
		R: c.R + int(float64(255-c.R)*factor),
		G: c.G + int(float64(255-c.G)*factor),
		B: c.B + int(float64(255-c.B)*factor),
	}
}

// HexToColor convertit un hex en Color
func HexToColor(hex string) Color {
	hex = strings.TrimPrefix(hex, "#")
	if len(hex) != 6 {
		return Color{0, 0, 0}
	}

	r, _ := strconv.ParseInt(hex[0:2], 16, 64)
	g, _ := strconv.ParseInt(hex[2:4], 16, 64)
	b, _ := strconv.ParseInt(hex[4:6], 16, 64)

	return Color{int(r), int(g), int(b)}
}
