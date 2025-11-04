package clblog

import (
	"fmt"
	"html/template"
	"littleblog/internal/models/clcaptchas"
	"littleblog/internal/models/clconfig"
	"littleblog/internal/models/climages"
	"littleblog/internal/models/clposts"
	"littleblog/internal/models/gormzerologger"
	"log"
	"slices"
	"strings"
	"unicode"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/mysql"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var (
	instance *Littleblog
)

type Littleblog struct {
	Blogs         map[string]clconfig.BlogsConfig
	BlogsId       map[uint]string
	Db            *gorm.DB
	Configuration *clconfig.Config
	Captcha       *clcaptchas.Captchas
	Version       string
	BuildID       string
}

func GetInstance() *Littleblog {
	if instance == nil {
		instance = &Littleblog{}
	}
	return instance
}

func Init(config *clconfig.Config, version string, buildid string) *Littleblog {
	instance = &Littleblog{
		Configuration: config,
		Version:       version,
		BuildID:       buildid,
	}
	instance.initDatabase()
	instance.initConfigurationBlogs()
	instance.initCaptcha()
	return instance
}

func (bl *Littleblog) initCaptcha() {
	bl.Captcha = clcaptchas.New(bl.Configuration.Database.Redis.Addr, bl.Configuration.Database.Redis.Db)
}

func (bl *Littleblog) initDatabase() {
	var err error

	// Créer le logger GORM avec Zerolog
	level := "warn"
	if bl.Configuration.Logger.Level == "debug" || !bl.Configuration.Production {
		level = "trace"
	}
	gormLogger := gormzerologger.New(level)

	var db *gorm.DB
	switch bl.Configuration.Database.Db {
	case "sqlite":
		db, err = gorm.Open(sqlite.Open(bl.Configuration.Database.Path), &gorm.Config{
			Logger: gormLogger,
		})
	case "mysql":
		db, err = gorm.Open(mysql.Open(bl.Configuration.Database.Dsn), &gorm.Config{
			Logger: gormLogger,
		})
	default:
		err = fmt.Errorf("le type de database doit etre sqlite ou mysql")
	}

	if err != nil {
		log.Fatal(err, "Erreur connexion base de données:")
	}

	err = db.AutoMigrate(&clposts.Post{}, &clposts.Comment{})
	if err != nil {
		log.Fatal(err, "Erreur migration:")
	}

	bl.Db = db
}

func (bl *Littleblog) GetConfItem(c *gin.Context, withId bool, id uint) clconfig.BlogsConfig {
	if withId {
		if item, ok := bl.BlogsId[id]; ok {
			return bl.Blogs[item]
		}
	} else {
		host, found := c.Get("hostname")
		if found {
			return bl.Blogs[host.(string)]
		}
	}
	if item, ok := bl.BlogsId[0]; ok {
		return bl.Blogs[item]
	}
	return clconfig.BlogsConfig{}
}

func (lb *Littleblog) initConfigurationBlogs() {
	lb.BlogsId = make(map[uint]string, len(lb.Configuration.Blogs))
	lb.Blogs = make(map[string]clconfig.BlogsConfig, len(lb.Configuration.Blogs))

	var idfound []uint
	var err error
	for _, item := range lb.Configuration.Blogs {
		if slices.Contains(idfound, item.Id) {
			log.Fatal("l'id dans les blogs doit etre unique")
		}
		idfound = append(idfound, item.Id)

		if item.Favicon == "" {
			item.Favicon = "/files/img/linux.png"
		}

		item.LinkRSS, err = GenerateDynamicRSS(item.Menu, item.SiteName)
		if err != nil {
			log.Fatal(err.Error())
		}
		item.ThemeCSS = GenerateThemeCSS(item.Theme)
		lb.Blogs[item.Hostname] = item
		lb.BlogsId[item.Id] = item.Hostname
	}
}

func GenerateDynamicRSS(Menu []clconfig.MenuItem, SiteName string) (template.HTML, error) {
	rssStr := ""
	for _, item := range Menu {
		if item.Key == "" {
			continue
		}
		slugifiedKey := Slugify(item.Key)
		if slugifiedKey == "files" || slugifiedKey == "static" {
			return "", fmt.Errorf("la clé du menu doit etre différente de 'files' et de 'static'")
		}
		rssStr += fmt.Sprintf("    <link rel=\"alternate\" type=\"application/rss+xml\" title=\"%s - %s\" href=\"/rss.xml/%s\"/>\n", SiteName, slugifiedKey, slugifiedKey)
	}
	return template.HTML(rssStr), nil
}

func Slugify(s string) string {
	var result strings.Builder

	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			result.WriteRune(r)
		} else if unicode.IsSpace(r) {
			result.WriteRune('-')
		} else if r == '-' {
			result.WriteRune(r)
		}
	}

	return result.String()
}

// GenerateThemeCSS génère le CSS pour un thème basé sur une couleur
func GenerateThemeCSS(colorName string) string {
	// Couleurs de base prédéfinies
	baseColors := map[string]string{
		"blue":   "#007bff",
		"red":    "#dc3545",
		"green":  "#28a745",
		"yellow": "#ffc107",
		"purple": "#6f42c1",
		"cyan":   "#17a2b8",
		"orange": "#fd7e14",
		"pink":   "#e83e8c",
		"gray":   "#6c757d",
		"grey":   "#6c757d",
		"black":  "#000000",
	}

	// Récupérer la couleur de base
	baseHex, exists := baseColors[strings.ToLower(colorName)]
	if !exists {
		// Si la couleur n'existe pas, on assume que c'est un hex
		if strings.HasPrefix(colorName, "#") {
			baseHex = colorName
		} else {
			baseHex = "#007bff" // Fallback sur blue
		}
	}

	baseColor := climages.HexToColor(baseHex)

	// Générer les variations
	primaryHover := baseColor.Darken(20)
	success := baseColor.Lighten(15)
	danger := baseColor.Darken(30)
	warning := baseColor.Lighten(40)
	info := baseColor.Darken(10)
	light := baseColor.Lighten(80)
	dark := baseColor.Darken(70)
	border := baseColor.Lighten(60)

	// Générer le CSS
	css := fmt.Sprintf(`:root {
 --primary-color: %s;
 --primary-hover: %s;
 --success-color: %s;
 --danger-color: %s;
 --warning-color: %s;
 --info-color: %s;
 --light-color: %s;
 --dark-color: %s;
 --border-color: %s;
 --shadow: 0 2px 10px rgba(%d,%d,%d,0.1);
 --shadow-hover: 0 8px 25px rgba(%d,%d,%d,0.15);
 --border-radius: 8px;
 --transition: all 0.3s ease;
 --gradient: linear-gradient(135deg, %s 0%%, %s 100%%);
}`,
		baseColor.ToHex(),
		primaryHover.ToHex(),
		success.ToHex(),
		danger.ToHex(),
		warning.ToHex(),
		info.ToHex(),
		light.ToHex(),
		dark.ToHex(),
		border.ToHex(),
		baseColor.R, baseColor.G, baseColor.B,
		baseColor.R, baseColor.G, baseColor.B,
		baseColor.ToHex(),
		primaryHover.ToHex(),
	)

	return css
}
