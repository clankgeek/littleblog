package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"html/template"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"io/fs"
	"log"
	mrand "math/rand"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/gin-contrib/gzip"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/tdewolff/minify/v2"

	"github.com/andskur/argon2-hashing"
	"github.com/tdewolff/minify/v2/css"
	htmlmin "github.com/tdewolff/minify/v2/html"
	"github.com/tdewolff/minify/v2/js"
	"github.com/ulule/limiter/v3"
	ginlimiter "github.com/ulule/limiter/v3/drivers/middleware/gin"
	"github.com/ulule/limiter/v3/drivers/store/memory"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer/html"
	"golang.org/x/image/draw"
	"gopkg.in/yaml.v3"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const VERSION string = "0.5.0"

// global instance
var (
	db            *gorm.DB
	md            goldmark.Markdown
	configuration *Config
	theme         string
	rsslink       template.HTML
	BuildID       string
)

//go:embed templates/**/*.html
var templatesFS embed.FS

//go:embed ressources/js
//go:embed ressources/css
//go:embed ressources/img
var staticFS embed.FS

// Models avec tags GORM
type Post struct {
	ID          uint          `json:"id" gorm:"primaryKey"`
	Title       string        `json:"title" gorm:"not null"`
	Content     string        `json:"content" gorm:"type:text;not null"`
	ContentHTML template.HTML `json:"content_html" gorm:"-"`
	Excerpt     string        `json:"excerpt"`
	Author      string        `json:"author" gorm:"not null"`
	CreatedAt   time.Time     `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt   time.Time     `json:"updated_at" gorm:"autoUpdateTime"`
	LikeCount   int           `json:"like_count" gorm:"default:0"`
	Tags        string        `json:"-" gorm:"type:text"`
	Category    string        `json:"category" gorm:"type:text"`
	TagsList    []string      `json:"tags" gorm:"-"`
	Comments    []Comment     `json:"comments,omitempty" gorm:"foreignKey:PostID"`
}

type Comment struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	PostID    uint      `json:"post_id" gorm:"not null;index"`
	Author    string    `json:"author" gorm:"not null"`
	Content   string    `json:"content" gorm:"type:text;not null"`
	CreatedAt time.Time `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt time.Time `json:"updated_at" gorm:"autoUpdateTime"`
	Post      Post      `json:"-" gorm:"foreignKey:PostID"`
}

type Like struct {
	ID     uint   `gorm:"primaryKey"`
	PostID uint   `gorm:"not null;index"`
	UserIP string `gorm:"not null;index"`
	Post   Post   `gorm:"foreignKey:PostID"`
}

// Requests structs
type CreateCommentRequest struct {
	Author  string `json:"author" binding:"required"`
	Content string `json:"content" binding:"required"`
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type CreatePostRequest struct {
	Title    string   `json:"title" binding:"required"`
	Content  string   `json:"content" binding:"required"`
	Excerpt  string   `json:"excerpt"`
	Author   string   `json:"author"`
	Tags     []string `json:"tags"`
	Category string   `json:"category"`
}

type UpdatePostRequest struct {
	Title    string   `json:"title" binding:"required"`
	Content  string   `json:"content" binding:"required"`
	Excerpt  string   `json:"excerpt"`
	Tags     []string `json:"tags"`
	Category string   `json:"category"`
}

type Config struct {
	SiteName    string     `yaml:"sitename"`
	Description string     `yaml:"description"`
	Theme       string     `yaml:"theme"`
	DBPath      string     `yaml:"dbpath"`
	Admin_login string     `yaml:"admin_login"`
	Admin_pass  string     `yaml:"admin_pass"`
	Admin_hash  string     `yaml:"admin_pass_hash"`
	Production  bool       `yaml:"production"`
	Listen      string     `yaml:"listen"`
	Menu        []MenuItem `yaml:"menu"`
}

type MenuItem struct {
	Key   string `yaml:"key"`
	Value string `yaml:"value"`
}

// RSS représente le flux RSS complet
type RSS struct {
	XMLName xml.Name `xml:"rss"`
	Version string   `xml:"version,attr"`
	Channel Channel  `xml:"channel"`
}

// Channel représente le canal RSS
type Channel struct {
	Title         string    `xml:"title"`
	Link          string    `xml:"link"`
	Description   string    `xml:"description"`
	Language      string    `xml:"language"`
	Copyright     string    `xml:"copyright,omitempty"`
	Generator     string    `xml:"generator"`
	LastBuildDate string    `xml:"lastBuildDate"`
	Items         []RSSItem `xml:"item"`
}

// RSSItem représente un article dans le flux RSS
type RSSItem struct {
	Title       string `xml:"title"`
	Link        string `xml:"link"`
	Description string `xml:"description"`
	Author      string `xml:"author,omitempty"`
	Category    string `xml:"category,omitempty"`
	GUID        string `xml:"guid"`
	PubDate     string `xml:"pubDate"`
}

// Color représente une couleur RGB
type Color struct {
	R, G, B int
}

func createExampleConfig(filename string) error {
	example := &Config{
		SiteName:    "Mon Blog Tech",
		Description: "Blog qui utilise littleblog",
		Theme:       "blue",
		DBPath:      "./blog.db",
		Admin_login: "admin",
		Admin_pass:  "admin123",
		Admin_hash:  "",
		Production:  false,
		Listen:      ":8080",
		Menu: []MenuItem{
			{Key: "menu1", Value: "Mon premier menu"},
			{Key: "menu2", Value: "Mon second menu"},
		},
	}
	return writeConfigYaml(filename, example)
}

func writeConfigYaml(filename string, conf *Config) error {
	data, err := yaml.Marshal(conf)
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

func handleExampleCreation() error {
	filename := "littleblog.yaml"
	if err := createExampleConfig(filename); err != nil {
		return fmt.Errorf("erreur création exemple: %v", err)
	}

	fmt.Printf("✅ Fichier exemple créé: %s\n", filename)
	fmt.Println("⚠️  Admin_pass sera automatiquement hash en argon2 dans Admin_hash au premier lancement")
	return nil
}

func loadAndConvertConfig(configFile string) (*Config, error) {
	// Charger la configuration YAML
	yamlConfig, err := loadConfig(configFile)
	if err != nil {
		return nil, fmt.Errorf("erreur chargement config: %v", err)
	}

	// Convertir en config interne
	conf := convertConfig(yamlConfig)

	if conf.DBPath == "" {
		return nil, fmt.Errorf("DBPath ne peut pas etre vide")
	}

	if conf.Listen == "" {
		conf.Listen = ":8080"
	}

	if conf.Admin_pass != "" {
		if len(conf.Admin_pass) < 8 {
			return nil, fmt.Errorf("le mot de passe doit contenir au moins 8 caractères")
		}

		hash, err := argon2.GenerateFromPassword([]byte(conf.Admin_pass), argon2.DefaultParams)
		if err != nil {
			return nil, err
		}
		conf.Admin_hash = string(hash)
		conf.Admin_pass = ""
		err = writeConfigYaml(configFile, conf)
		if err != nil {
			return nil, err
		}
	}

	theme = GenerateThemeCSS(conf.Theme)
	rsslink, err = GenerateDynamicRSS(conf)
	if err != nil {
		return nil, err
	}

	return conf, nil
}

// Convertir la config YAML en config interne
func convertConfig(yamlConfig *Config) *Config {
	conf := &Config{
		SiteName:    yamlConfig.SiteName,
		Description: yamlConfig.Description,
		Theme:       yamlConfig.Theme,
		DBPath:      yamlConfig.DBPath,
		Admin_login: yamlConfig.Admin_login,
		Admin_pass:  yamlConfig.Admin_pass,
		Admin_hash:  yamlConfig.Admin_hash,
		Production:  yamlConfig.Production,
		Listen:      yamlConfig.Listen,
		Menu:        yamlConfig.Menu,
	}

	return conf
}

// Charger la configuration YAML
func loadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("impossible de lire le fichier %s: %v", filename, err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("erreur de parsing YAML: %v", err)
	}

	return &config, nil
}

// Initialiser le convertisseur Markdown
func initMarkdown() {
	md = goldmark.New(
		goldmark.WithExtensions(
			extension.GFM,
			extension.Table,
			extension.Strikethrough,
			extension.TaskList,
		),
		goldmark.WithParserOptions(
			parser.WithAutoHeadingID(),
		),
		goldmark.WithRendererOptions(
			html.WithHardWraps(),
			html.WithXHTML(),
			html.WithUnsafe(),
		),
	)
	log.Println("Convertisseur Markdown initialisé")
}

// Convertir Markdown en HTML
func convertMarkdownToHTML(markdown string) template.HTML {
	var buf bytes.Buffer
	if err := md.Convert([]byte(markdown), &buf); err != nil {
		log.Printf("Erreur conversion Markdown: %v", err)
		return template.HTML("<pre>" + template.HTMLEscapeString(markdown) + "</pre>")
	}
	return template.HTML(buf.String())
}

// Hooks GORM
func (p *Post) BeforeSave(tx *gorm.DB) error {
	if len(p.TagsList) > 0 {
		p.Tags = strings.Join(p.TagsList, ",")
	}
	return nil
}

func (p *Post) AfterFind(tx *gorm.DB) error {
	if p.Tags != "" {
		p.TagsList = strings.Split(p.Tags, ",")
	}
	p.ContentHTML = convertMarkdownToHTML(p.Content)
	return nil
}

// Middleware d'authentification
func authRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		userID := session.Get("user_id")
		if userID == nil {
			if c.Request.Header.Get("Content-Type") == "application/json" {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentification requise"})
			} else {
				c.Redirect(http.StatusTemporaryRedirect, "/admin/login")
			}
			c.Abort()
			return
		}
		c.Set("authenticated", true)
		c.Next()
	}
}

// Générer une clé secrète aléatoire
func generateSecretKey() []byte {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		log.Fatal("Erreur génération clé secrète:", err)
	}
	return key
}

func initDatabase() {
	var err error

	db, err = gorm.Open(sqlite.Open(configuration.DBPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		log.Fatal("Erreur connexion base de données:", err)
	}

	err = db.AutoMigrate(&Post{}, &Comment{}, &Like{})
	if err != nil {
		log.Fatal("Erreur migration:", err)
	}

	var count int64
	db.Model(&Post{}).Count(&count)

	if count == 0 {
		seedDatabase()
	}

	log.Println("Base de données initialisée avec succès")
}

func getFirstMenuKey(conf *Config) string {
	if len(conf.Menu) > 0 {
		return slugify(conf.Menu[0].Key)
	}
	return ""
}

func seedDatabase() {
	log.Println("Création des données d'exemple...")

	posts := []Post{
		{
			Title: "Bienvenue sur mon blog",
			Content: `# Bienvenue !

Ceci est le premier article avec le moteur de blog **littleblog**, qui utilise un backend en **Gin Gonic** et un frontend en **Alpine.js**.

## Fonctionnalités

- Infinity scroll sur la liste des articles
- Articles avec contenu Markdown
- Recherche en temps réel
- Administration des articles
- Upload d'images

## Composants

- Backend
  - Language Go
  - Gin Web Framework
  - Accès à la base de données avec GORM
  - Base de données Sqlite3
  - Middleware Session pour la page d'administration
  - Templates inclus dans le binaire
  - Configuration en Yaml (autogénéré par le binaire)
  - API RESTful (json)

- Frontend
  - Html + CSS (via template Gin)
  - Framework Alpine.js
  - **N'utilise pas nodejs**

N'hésitez pas à laisser un commentaire !`,
			Excerpt:   "Premier article de présentation du blog avec les technologies utilisées.",
			Author:    "Admin",
			LikeCount: 5,
			TagsList:  []string{"accueil", "présentation"},
			Category:  getFirstMenuKey(configuration),
		},
	}

	for i := range posts {
		result := db.Create(&posts[i])
		if result.Error != nil {
			log.Printf("Erreur création post %d: %v", i+1, result.Error)
		}
	}

	log.Println("Données d'exemple créées avec succès")
}

func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[mrand.Intn(len(charset))]
	}
	return string(b)
}

// Fonction pour redimensionner l'image
func resizeImage(img image.Image, maxWidth int) image.Image {
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

func GenerateMenu(items []MenuItem, category string) template.HTML {
	menuStr := ""
	for _, item := range items {
		key := slugify(item.Key)
		active := ""
		if key == category {
			active = " active"
		}
		menuStr += fmt.Sprintf("<a href=\"/%s\" class=\"nav-link%s\">%s</a>&nbsp;", key, active, item.Value)
	}
	return safeHtml(menuStr)
}

func GenerateDynamicRSS(conf *Config) (template.HTML, error) {
	rssStr := ""
	for _, item := range conf.Menu {
		slugifiedKey := slugify(item.Key)
		if slugifiedKey == "files" || slugifiedKey == "static" {
			return "", fmt.Errorf("la clé du menu doit etre différente de 'files' et de 'static'")
		}
		rssStr += fmt.Sprintf("<link rel=\"alternate\" type=\"application/rss+xml\" title=\"%s - %s\" href=\"/rss.xml/%s\"/>\n", conf.SiteName, slugifiedKey, slugifiedKey)
	}
	return safeHtml(rssStr), nil
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

	baseColor := HexToColor(baseHex)

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

func safeCSS(css string) template.CSS {
	return template.CSS(css)
}

func safeHtml(html string) template.HTML {
	return template.HTML(html)
}

func escapeJS(s string) template.JS {
	// Échappe les caractères problématiques pour JavaScript
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	s = strings.ReplaceAll(s, "\t", `\t`)
	return template.JS(s)
}

func jsonify(v any) template.JS {
	if v == nil {
		return template.JS("[]")
	}

	// Vérifier si c'est un slice vide
	if reflect.ValueOf(v).Kind() == reflect.Slice && reflect.ValueOf(v).Len() == 0 {
		return template.JS("[]")
	}

	b, err := json.Marshal(v)
	if err != nil {
		return template.JS("[]")
	}

	return template.JS(b)
}

func middlewareRenderTime() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Stocker le temps de début pour utilisation dans les handlers
		c.Set("requestStart", time.Now())
		c.Next()
	}
}

func getRenderTime(c *gin.Context) any {
	start, _ := c.Get("requestStart")
	duration := time.Since(start.(time.Time))
	return fmt.Sprintf("Page générée en %s", formatDuration(duration))
}

func formatDuration(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%.2fµs", float64(d.Nanoseconds())/1000)
	}
	if d < time.Second {
		return fmt.Sprintf("%.2fms", float64(d.Nanoseconds())/1e6)
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}

func middlewareCORS(c *gin.Context) {
	c.Header("Access-Control-Allow-Origin", "*")
	c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")

	if c.Request.Method == "OPTIONS" {
		c.AbortWithStatus(204)
		return
	}

	c.Next()
}

func newMiddlewareLimiter() gin.HandlerFunc {
	rate := limiter.Rate{
		Period: 1 * time.Minute,
		Limit:  5,
	}
	mstore := memory.NewStore()
	instance := limiter.New(mstore, rate)
	return ginlimiter.NewMiddleware(instance)
}

func newMiddlewareSession() gin.HandlerFunc {
	store := cookie.NewStore(generateSecretKey())
	store.Options(sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7,
		HttpOnly: true,
		Secure:   configuration.Production,
	})
	return sessions.Sessions("littleblog", store)
}

// Middleware pour minifier les fichiers statiques CSS/JS
func ServeMinifiedStatic(m *minify.M) gin.HandlerFunc {
	return func(c *gin.Context) {
		path := strings.TrimPrefix(c.Request.URL.Path, "/files/")
		content, err := fs.ReadFile(staticFS, "ressources/"+path)
		if err != nil {
			pageNotFound(c, "Fichier non trouvé")
			return
		}

		ext := filepath.Ext(path)
		var contentType string
		var minified []byte

		switch ext {
		case ".css":
			contentType = "text/css"
			minified, err = m.Bytes("text/css", content)
		case ".js":
			contentType = "application/javascript"
			minified, err = m.Bytes("application/javascript", content)
		case ".svg":
			// En-têtes de cache pour SVG
			c.Header("Cache-Control", "public, max-age=31536000, immutable")
			c.Header("ETag", generateETag(content))
			c.Data(http.StatusOK, "image/svg+xml", content)
			return
		default:
			c.Data(http.StatusOK, "application/octet-stream", content)
			return
		}

		if err != nil {
			minified = content
		}

		// En-têtes de cache pour CSS et JS
		c.Header("Cache-Control", "public, max-age=31536000, immutable")
		c.Header("ETag", generateETag(minified))

		c.Data(http.StatusOK, contentType, minified)
	}
}

// Fonction helper pour générer un ETag
func generateETag(content []byte) string {
	hash := sha256.Sum256(content)
	return fmt.Sprintf(`"%x"`, hash[:16])
}

func getTemplates(production bool) *template.Template {
	m := minify.New()

	if production {
		m.AddFunc("text/html", htmlmin.Minify)
	}

	tmpl := template.New("").Funcs(template.FuncMap{
		"safeCSS":  safeCSS,
		"escapeJS": escapeJS,
		"jsonify":  jsonify,
	})

	// Lire tous les fichiers HTML
	fs.WalkDir(templatesFS, "templates", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".html" {
			return err
		}

		content, _ := fs.ReadFile(templatesFS, path)
		minified, err := m.Bytes("text/html", content)
		if err != nil {
			minified = content
		}

		tmpl.New(path).Parse(string(minified))
		return nil
	})

	return tmpl
}

func initConfiguration() {
	configFile, shouldCreateExample, versionDisplay, err := parseCommandLineArgs()
	if err != nil {
		fmt.Println("Usage:")
		fmt.Println("  littleblog -config littleblog.yaml")
		fmt.Println("  littleblog -example  (pour créer un fichier exemple)")
		fmt.Println("  littleblog -version  (affiche la version)")
		os.Exit(1)
	}

	if versionDisplay {
		println(VERSION)
		os.Exit(0)
	}

	// Handle example creation
	if shouldCreateExample {
		if err := handleExampleCreation(); err != nil {
			log.Fatalf("❌ %v", err)
		}
		os.Exit(1)
	}

	// Load and validate configuration
	conf, err := loadAndConvertConfig(configFile)
	if err != nil {
		log.Fatalf("❌ %v", err)
		os.Exit(1)
	}
	configuration = conf
}

func setMiddleware(r *gin.Engine) {
	// use Compression, with gzip
	r.Use(gzip.Gzip(gzip.BestSpeed))

	// Configuration des sessions
	r.Use(newMiddlewareSession())

	// Calculate time elapsed
	r.Use(middlewareRenderTime())

	// CORS
	r.Use(middlewareCORS)
}

func newServer() *gin.Engine {
	if configuration.Production {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.Default()

	// parser les templates
	r.SetHTMLTemplate(getTemplates(configuration.Production))

	return r
}

func slugify(s string) string {
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

func setRoutes(r *gin.Engine) {
	m := minify.New()
	m.AddFunc("text/css", css.Minify)
	m.AddFunc("application/javascript", js.Minify)

	// middleware rate limiter
	middlewareLimiter := newMiddlewareLimiter()

	//default
	r.NoRoute(func(c *gin.Context) {
		pageNotFound(c, "Page non trouvée")
	})

	// Route statiques
	r.Static("/static/", "./static")
	r.GET("/files/css/*.css", ServeMinifiedStatic(m))
	r.GET("/files/js/*.js", ServeMinifiedStatic(m))
	r.GET("/files/img/*.svg", ServeMinifiedStatic(m))

	// Routes publiques
	r.GET("/", indexHandler)
	r.GET("/:category", indexHandler)
	r.GET("/post/:id", postHandler)

	// Routes d'authentification
	r.GET("/admin/login", loginPageHandler)
	r.POST("/admin/login", middlewareLimiter, loginHandler)
	r.POST("/admin/logout", logoutHandler)

	// Routes d'administration protégées
	admin := r.Group("/admin")
	admin.Use(authRequired())
	{
		admin.GET("/", adminDashboardHandler)
		admin.POST("/upload/image", uploadImageHandler)
		admin.GET("/posts", adminPostsHandler)
		admin.GET("/posts/new", newPostPageHandler)
		admin.POST("/posts", createPostHandler)
		admin.GET("/posts/:id/edit", editPostPageHandler)
		admin.PUT("/posts/:id", updatePostHandler)
		admin.DELETE("/posts/:id", deletePostHandler)
	}

	// API publiques
	api := r.Group("/api")
	{
		api.GET("/posts", getPostsAPI)
		api.GET("/posts/:id", getPostAPI)
		api.GET("/posts/:id/comments", getCommentsAPI)
		api.POST("/posts/:id/comments", addCommentAPI)
		api.GET("/posts/:id/like-status", getLikeStatusAPI)
		api.POST("/posts/:id/like", toggleLikeAPI)
		api.GET("/search", searchPostsAPI)
	}

	// Flux RSS
	r.GET("/rss.xml", rssHandler)
	r.GET("/rss.xml/:category", rssHandler)
}

func startServer(r *gin.Engine) {
	listen := ""
	if strings.HasPrefix(configuration.Listen, ":") {
		listen = "localhost" + configuration.Listen
	}

	log.Printf("Serveur démarré sur http://%s\n", listen)
	log.Printf("Admin: http://%s/admin/login\n", listen)
	r.Run(configuration.Listen)
}

func parseCommandLineArgs() (configFile string, shouldCreateExample bool, versionDisplay bool, err error) {
	var config = flag.String("config", "", "Fichier de configuration YAML")
	var example = flag.Bool("example", false, "Créer un fichier de configuration exemple")
	var version = flag.Bool("version", false, "version du produit")
	flag.Parse()

	if *version {
		return "", false, true, nil
	}

	if *example {
		return "", true, false, nil
	}

	if *config == "" {
		return "", false, false, fmt.Errorf("fichier de configuration requis")
	}

	return *config, false, false, nil
}

func main() {
	if BuildID == "" {
		BuildID = VERSION
	}

	initConfiguration()
	initMarkdown()
	initDatabase()

	r := newServer()

	setMiddleware(r)
	setRoutes(r)

	startServer(r)
}

// ============= HANDLERS PUBLICS =============

func indexHandler(c *gin.Context) {
	session := sessions.Default(c)
	isAdmin := session.Get("user_id") != nil
	category := slugify(c.Param("category"))
	memories := ""

	if isAdmin {
		memories = getMemUsage()
	}

	c.HTML(http.StatusOK, "index", gin.H{
		"title":           configuration.SiteName,
		"siteName":        configuration.SiteName,
		"description":     configuration.Description,
		"isAuthenticated": isAdmin,
		"showSearch":      true,
		"currentYear":     time.Now().Year(),
		"ogType":          "website",
		"theme":           theme,
		"version":         VERSION,
		"category":        category,
		"menu":            GenerateMenu(configuration.Menu, category),
		"rsslink":         rsslink,
		"BuildID":         BuildID,
		"memories":        memories,
		"renderTime":      getRenderTime(c),
	})
}

func pageNotFound(c *gin.Context, title string) {
	c.HTML(http.StatusNotFound, "404_not_found", gin.H{
		"title":       title,
		"siteName":    configuration.SiteName,
		"description": "La page que vous recherchez n'existe pas.",
		"currentYear": time.Now().Year(),
		"theme":       theme,
		"version":     VERSION,
		"BuildID":     BuildID,
		"menu":        GenerateMenu(configuration.Menu, ""),
	})
}

func postHandler(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		pageNotFound(c, "Page non trouvée")
		return
	}

	var post Post
	result := db.First(&post, uint(id))
	if result.Error != nil {
		pageNotFound(c, "Article non trouvé")
		return
	}

	session := sessions.Default(c)
	isAdmin := session.Get("user_id") != nil

	c.HTML(http.StatusOK, "posts", gin.H{
		"title":           post.Title,
		"siteName":        configuration.SiteName,
		"description":     configuration.Description,
		"post":            post,
		"isAuthenticated": isAdmin,
		"showSearch":      false,
		"currentYear":     time.Now().Year(),
		"ogTitle":         post.Title,
		"ogType":          "article",
		"theme":           theme,
		"version":         VERSION,
		"menu":            GenerateMenu(configuration.Menu, post.Category),
		"BuildID":         BuildID,
		"renderTime":      getRenderTime(c),
	})
}

// ============= HANDLERS D'AUTHENTIFICATION =============

func loginPageHandler(c *gin.Context) {
	session := sessions.Default(c)
	if session.Get("user_id") != nil {
		c.Redirect(http.StatusTemporaryRedirect, "/admin")
		return
	}

	c.HTML(http.StatusOK, "admin_login", gin.H{
		"title":    "Connexion Admin",
		"siteName": configuration.SiteName,
		"theme":    theme,
		"version":  VERSION,
		"BuildID":  BuildID,
	})
}

func loginHandler(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Données invalides"})
		return
	}

	// Vérification login / pass
	err := argon2.CompareHashAndPassword([]byte(configuration.Admin_hash), []byte(req.Password))
	if err != nil || req.Username != configuration.Admin_login {
		log.Printf("Tentative de connexion échouée - User: %s, IP: %s", req.Username, c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Identifiants incorrects"})
		return
	}
	log.Printf("Connexion réussie - User: %s, IP: %s", req.Username, c.ClientIP())

	// Créer la session
	session := sessions.Default(c)
	session.Set("user_id", "admin")
	session.Set("username", req.Username)
	if err := session.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur session"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":  "Connexion réussie",
		"redirect": "/admin",
	})
}

func logoutHandler(c *gin.Context) {
	session := sessions.Default(c)
	session.Clear()
	session.Save()

	c.JSON(http.StatusOK, gin.H{"message": "Déconnexion réussie"})
}

// ============= HANDLERS D'ADMINISTRATION =============

func adminDashboardHandler(c *gin.Context) {
	var stats struct {
		TotalPosts    int64
		TotalComments int64
		TotalLikes    int64
		RecentPosts   []Post
	}

	db.Model(&Post{}).Count(&stats.TotalPosts)
	db.Model(&Comment{}).Count(&stats.TotalComments)
	db.Model(&Like{}).Count(&stats.TotalLikes)
	db.Order("created_at desc").Limit(5).Find(&stats.RecentPosts)

	session := sessions.Default(c)
	username := session.Get("username")

	c.HTML(http.StatusOK, "admin_dashboard", gin.H{
		"title":       "Dashboard Admin",
		"siteName":    configuration.SiteName,
		"pageTitle":   "Dashboard",
		"pageIcon":    "📊",
		"currentPage": "dashboard",
		"username":    username,
		"stats":       stats,
		"currentYear": time.Now().Year(),
		"isAdmin":     true,
		"theme":       theme,
		"version":     VERSION,
		"BuildID":     BuildID,
		"memories":    getMemUsage(),
	})
}

func getMemUsage() string {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return fmt.Sprintf("Statistiques mémoire: allouée = %v Mo, total allouée = %d, système = %v Mo, nombre de GC = %v\n", m.Alloc/1024/1024, m.TotalAlloc/1024/1024, m.Sys/1024/1024, m.NumGC)
}

func uploadImageHandler(c *gin.Context) {
	file, header, err := c.Request.FormFile("image")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Fichier non trouvé"})
		return
	}
	defer file.Close()

	// Vérifier le type MIME
	buffer := make([]byte, 512)
	_, err = file.Read(buffer)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur lecture fichier"})
		return
	}

	contentType := http.DetectContentType(buffer)
	if !strings.HasPrefix(contentType, "image/") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Le fichier doit être une image"})
		return
	}

	// Limiter la taille (ex: 10MB avant compression)
	if header.Size > 10*1024*1024 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Image trop grande (max 10MB)"})
		return
	}

	// Réinitialiser le curseur du fichier
	file.Seek(0, 0)

	// Décoder l'image
	img, format, err := image.Decode(file)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur décodage image"})
		return
	}

	// Redimensionner si nécessaire
	processedImg := resizeImage(img, 1600)

	// Créer le dossier uploads s'il n'existe pas
	uploadsDir := "./static/uploads"
	if err := os.MkdirAll(uploadsDir, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur création dossier"})
		return
	}

	// Générer un nom unique (toujours en .jpg pour les images redimensionnées)
	var ext string
	switch format {
	case "jpeg", "jpg":
		ext = ".jpg"
	case "png":
		ext = ".png"
	case "gif":
		ext = ".gif"
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "seule les images jpg, png et gif sont supportées"})
		return
	}

	filename := fmt.Sprintf("%d_%s%s",
		time.Now().Unix(),
		generateRandomString(8),
		ext)

	filepath := filepath.Join(uploadsDir, filename)

	// Créer le fichier de sortie
	out, err := os.Create(filepath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur création fichier"})
		return
	}
	defer out.Close()

	// Encoder l'image selon le format
	switch format {
	case "png":
		// Garder le PNG pour préserver la transparence
		err = png.Encode(out, processedImg)
	case "gif":
		// Garder le GIF original si c'est un GIF
		file.Seek(0, 0)
		_, err = io.Copy(out, file)
	default:
		// Pour JPEG et autres, encoder en JPEG avec qualité 85
		err = jpeg.Encode(out, processedImg, &jpeg.Options{Quality: 85})
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur sauvegarde image"})
		return
	}

	// Obtenir la taille du fichier final
	fileInfo, _ := os.Stat(filepath)
	finalSize := fileInfo.Size()

	// Retourner l'URL de l'image
	imageURL := fmt.Sprintf("/static/uploads/%s", filename)
	c.JSON(http.StatusOK, gin.H{
		"url":      imageURL,
		"filename": filename,
		"size":     finalSize,
		"format":   format,
	})
}

func adminPostsHandler(c *gin.Context) {
	var posts []Post
	db.Order("created_at desc").Find(&posts)

	session := sessions.Default(c)
	username := session.Get("username")

	c.HTML(http.StatusOK, "admin_posts", gin.H{
		"title":       "Gestion des Articles",
		"siteName":    configuration.SiteName,
		"pageTitle":   "Gestion des Articles",
		"pageIcon":    "📝",
		"currentPage": "posts",
		"username":    username,
		"posts":       posts,
		"currentYear": time.Now().Year(),
		"isAdmin":     true,
		"theme":       theme,
		"version":     VERSION,
		"BuildID":     BuildID,
		"memories":    getMemUsage(),
	})
}

func getOptionsCategory() template.HTML {
	var optionsCategory string
	for _, item := range configuration.Menu {
		slugifiedKey := slugify(item.Key)
		optionsCategory += fmt.Sprintf("<option value=\"%s\">%s</option>", slugifiedKey, slugifiedKey)
	}
	return safeHtml(optionsCategory)
}

func newPostPageHandler(c *gin.Context) {
	session := sessions.Default(c)
	username := session.Get("username")

	c.HTML(http.StatusOK, "admin_post_form", gin.H{
		"title":           "Nouvel Article",
		"siteName":        configuration.SiteName,
		"pageTitle":       "Nouvel Article",
		"pageIcon":        "➕",
		"currentPage":     "new_post",
		"username":        username,
		"isEdit":          false,
		"currentYear":     time.Now().Year(),
		"isAdmin":         true,
		"theme":           theme,
		"version":         VERSION,
		"optionsCategory": getOptionsCategory(),
		"BuildID":         BuildID,
		"memories":        getMemUsage(),
	})
}

func editPostPageHandler(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.HTML(http.StatusNotFound, "admin_post_form", gin.H{"title": "Article non trouvé"})
		return
	}

	var post Post
	result := db.First(&post, uint(id))
	if result.Error != nil {
		c.HTML(http.StatusNotFound, "admin_post_form", gin.H{"title": "Article non trouvé"})
		return
	}

	session := sessions.Default(c)
	username := session.Get("username")

	c.HTML(http.StatusOK, "admin_post_form", gin.H{
		"title":           "Éditer Article",
		"siteName":        configuration.SiteName,
		"pageTitle":       "Éditer l'Article",
		"pageIcon":        "✏️",
		"currentPage":     "edit_post",
		"username":        username,
		"post":            post,
		"isEdit":          true,
		"currentYear":     time.Now().Year(),
		"isAdmin":         true,
		"theme":           theme,
		"version":         VERSION,
		"optionsCategory": getOptionsCategory(),
		"BuildID":         BuildID,
		"memories":        getMemUsage(),
	})
}

func createPostHandler(c *gin.Context) {
	var req CreatePostRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Données invalides"})
		return
	}

	// Utiliser l'auteur de la session ou celui fourni
	author := req.Author
	if author == "" {
		session := sessions.Default(c)
		if username := session.Get("username"); username != nil {
			author = username.(string)
		} else {
			author = "Anonymous" // ou retourner une erreur
		}
	}

	post := Post{
		Title:    strings.TrimSpace(req.Title),
		Content:  strings.TrimSpace(req.Content),
		Excerpt:  strings.TrimSpace(req.Excerpt),
		Author:   author,
		TagsList: req.Tags,
		Category: slugify(req.Category),
	}

	if post.Title == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Le titre ne peut pas etre vide"})
		return
	}

	result := db.Create(&post)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur création article"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Article créé avec succès",
		"post_id": post.ID,
	})
}

func updatePostHandler(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ID invalide"})
		return
	}

	var post Post
	result := db.First(&post, uint(id))
	if result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Article non trouvé"})
		return
	}

	var req UpdatePostRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Données invalides"})
		return
	}

	// Mettre à jour les champs
	post.Title = strings.TrimSpace(req.Title)
	post.Content = strings.TrimSpace(req.Content)
	post.Excerpt = strings.TrimSpace(req.Excerpt)
	post.TagsList = req.Tags
	post.Category = slugify(req.Category)

	result = db.Save(&post)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur mise à jour article"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Article mis à jour avec succès"})
}

func deletePostHandler(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ID invalide"})
		return
	}

	// Supprimer dans une transaction (commentaires et likes aussi)
	tx := db.Begin()

	// Supprimer les commentaires
	if err := tx.Where("post_id = ?", uint(id)).Delete(&Comment{}).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur suppression commentaires"})
		return
	}

	// Supprimer les likes
	if err := tx.Where("post_id = ?", uint(id)).Delete(&Like{}).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur suppression likes"})
		return
	}

	// Supprimer l'article
	if err := tx.Delete(&Post{}, uint(id)).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur suppression article"})
		return
	}

	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur validation suppression"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Article supprimé avec succès"})
}

// ============= API HANDLERS =============

// rssHandler génère le flux RSS des posts
func rssHandler(c *gin.Context) {
	var posts []Post

	// Récupérer les 20 derniers posts
	query := db.Order("created_at desc").Limit(20)

	category := c.Param("category")
	if category != "" {
		query = query.Where("category = ?", slugify(category))
	}

	result := query.Find(&posts)
	if result.Error != nil {
		c.XML(http.StatusInternalServerError, gin.H{"error": "Erreur récupération posts"})
		return
	}

	// Obtenir l'URL de base depuis la requête
	scheme := "http"
	if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	baseURL := fmt.Sprintf("%s://%s", scheme, c.Request.Host)

	// Construire le flux RSS
	rss := RSS{
		Version: "2.0",
		Channel: Channel{
			Title:         configuration.SiteName,
			Link:          baseURL,
			Description:   configuration.Description,
			Language:      "fr-FR",
			Generator:     fmt.Sprintf("Littleblog v%s", VERSION),
			LastBuildDate: time.Now().Format(time.RFC1123Z),
			Items:         make([]RSSItem, 0, len(posts)),
		},
	}

	rss.Channel.Copyright = fmt.Sprintf("© %d %s", time.Now().Year(), configuration.SiteName)

	// Convertir les posts en items RSS
	for _, post := range posts {
		// Préparer la description (excerpt ou début du contenu)
		description := post.Excerpt
		if description == "" {
			// Prendre les 200 premiers caractères du contenu si pas d'excerpt
			if len(post.Content) > 200 {
				description = post.Content[:200] + "..."
			} else {
				description = post.Content
			}
		}

		// Category, si aucune catégorie, on prend le 1er tag
		category := ""
		if post.Category != "" {
			category = post.Category
		} else if len(post.TagsList) > 0 {
			category = post.TagsList[0] // RSS 2.0 ne supporte qu'une catégorie par item
		}

		item := RSSItem{
			Title:       post.Title,
			Link:        fmt.Sprintf("%s/post/%d", baseURL, post.ID),
			Description: description,
			Author:      post.Author,
			Category:    category,
			GUID:        fmt.Sprintf("%s/post/%d", baseURL, post.ID),
			PubDate:     post.CreatedAt.Format(time.RFC1123Z),
		}

		rss.Channel.Items = append(rss.Channel.Items, item)
	}

	// Définir le content-type approprié
	c.Header("Content-Type", "application/rss+xml; charset=utf-8")

	output, err := xml.MarshalIndent(rss, "", "  ")
	if err != nil {
		c.XML(http.StatusInternalServerError, gin.H{"error": "Erreur génération RSS"})
		return
	}

	// Ajouter le header XML au début
	xmlWithHeader := []byte(xml.Header + string(output))

	c.Data(http.StatusOK, "application/rss+xml; charset=utf-8", xmlWithHeader)
}

func getPostsAPI(c *gin.Context) {
	// Récupération des paramètres de pagination
	page, err := strconv.Atoi(c.DefaultQuery("page", "1"))
	if err != nil || page < 1 {
		page = 1
	}

	limit, err := strconv.Atoi(c.DefaultQuery("limit", "5"))
	if err != nil || limit < 1 {
		limit = 5
	}
	if limit > 50 { // Limite maximale pour éviter les abus
		limit = 50
	}

	category := slugify(c.DefaultQuery("category", ""))

	// Calcul de l'offset
	offset := (page - 1) * limit

	buildQuery := func() *gorm.DB {
		query := db.Model(&Post{})
		if category != "" {
			query = query.Where("category = ?", category)
		}
		return query
	}

	// Compter le nombre total de posts
	var total int64
	buildQuery().Count(&total)

	// Récupérer les posts avec leurs commentaires
	var posts []Post
	result := buildQuery().
		Preload("Comments").
		Order("created_at desc").
		Limit(limit).
		Offset(offset).
		Find(&posts)

	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur serveur"})
		return
	}

	// Déterminer s'il y a encore des posts
	hasMore := int64(offset+limit) < total

	// Envoyer la réponse structurée pour l'infinite scroll
	c.JSON(http.StatusOK, gin.H{
		"posts":   posts,
		"hasMore": hasMore,
		"total":   total,
		"page":    page,
		"perPage": limit,
	})
}

func getPostAPI(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ID invalide"})
		return
	}

	var post Post
	result := db.First(&post, uint(id))
	if result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Article non trouvé"})
		return
	}

	c.JSON(http.StatusOK, post)
}

func getCommentsAPI(c *gin.Context) {
	idStr := c.Param("id")
	postID, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ID invalide"})
		return
	}

	var comments []Comment
	result := db.Where("post_id = ?", uint(postID)).Order("created_at asc").Find(&comments)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur serveur"})
		return
	}

	c.JSON(http.StatusOK, comments)
}

func addCommentAPI(c *gin.Context) {
	idStr := c.Param("id")
	postID, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ID invalide"})
		return
	}

	var post Post
	result := db.First(&post, uint(postID))
	if result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Article non trouvé"})
		return
	}

	var req CreateCommentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	comment := Comment{
		PostID:  uint(postID),
		Author:  strings.TrimSpace(req.Author),
		Content: strings.TrimSpace(req.Content),
	}

	result = db.Create(&comment)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur création commentaire"})
		return
	}

	c.JSON(http.StatusCreated, comment)
}

func getLikeStatusAPI(c *gin.Context) {
	idStr := c.Param("id")
	postID, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ID invalide"})
		return
	}

	var post Post
	result := db.First(&post, uint(postID))
	if result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Article non trouvé"})
		return
	}

	userIP := c.ClientIP()
	var like Like
	isLiked := db.Where("post_id = ? AND user_ip = ?", uint(postID), userIP).First(&like).Error == nil

	c.JSON(http.StatusOK, gin.H{
		"liked":      isLiked,
		"like_count": post.LikeCount,
	})
}

func toggleLikeAPI(c *gin.Context) {
	idStr := c.Param("id")
	postID, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ID invalide"})
		return
	}

	userIP := c.ClientIP()

	tx := db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	var post Post
	result := tx.First(&post, uint(postID))
	if result.Error != nil {
		tx.Rollback()
		c.JSON(http.StatusNotFound, gin.H{"error": "Article non trouvé"})
		return
	}

	var existingLike Like
	likeExists := tx.Where("post_id = ? AND user_ip = ?", uint(postID), userIP).First(&existingLike).Error == nil

	if likeExists {
		if err := tx.Delete(&existingLike).Error; err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur suppression like"})
			return
		}

		if err := tx.Model(&post).Update("like_count", gorm.Expr("like_count - 1")).Error; err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur mise à jour compteur"})
			return
		}

		post.LikeCount--
	} else {
		newLike := Like{
			PostID: uint(postID),
			UserIP: userIP,
		}

		if err := tx.Create(&newLike).Error; err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur création like"})
			return
		}

		if err := tx.Model(&post).Update("like_count", gorm.Expr("like_count + 1")).Error; err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur mise à jour compteur"})
			return
		}

		post.LikeCount++
	}

	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur validation transaction"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"liked":      !likeExists,
		"like_count": post.LikeCount,
	})
}

func searchPostsAPI(c *gin.Context) {
	query := strings.ToLower(strings.TrimSpace(c.Query("q")))
	if query == "" {
		c.JSON(http.StatusOK, []Post{})
		return
	}

	var posts []Post

	searchTerm := "%" + query + "%"
	result := db.Where(
		"LOWER(title) LIKE ? OR LOWER(content) LIKE ? OR LOWER(excerpt) LIKE ? OR LOWER(tags) LIKE ?",
		searchTerm, searchTerm, searchTerm, searchTerm,
	).Order("created_at desc").Find(&posts)

	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur recherche"})
		return
	}

	c.JSON(http.StatusOK, posts)
}
