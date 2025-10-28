package main

import (
	"bytes"
	"context"
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
	"log/syslog"
	mrand "math/rand"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/andskur/argon2-hashing"
	"github.com/gin-contrib/gzip"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/mojocn/base64Captcha"
	"github.com/penglongli/gin-metrics/ginmetrics"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/tdewolff/minify/v2"
	"github.com/tdewolff/minify/v2/css"
	"github.com/tdewolff/minify/v2/js"
	"github.com/ulule/limiter/v3"
	ginlimiter "github.com/ulule/limiter/v3/drivers/middleware/gin"
	"github.com/ulule/limiter/v3/drivers/store/memory"
	stripmd "github.com/writeas/go-strip-markdown"
	"github.com/yuin/goldmark"
	emoji "github.com/yuin/goldmark-emoji"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer/html"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
	"golang.org/x/image/draw"
	"gopkg.in/natefinch/lumberjack.v2"
	"gopkg.in/yaml.v3"
	"gorm.io/driver/mysql"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const VERSION string = "0.7.0"

// global instance
var (
	db            *gorm.DB
	md            goldmark.Markdown
	configuration *Config
	BuildID       string
	captcha       *captchas
	Blogs         map[string]BlogsConfig
	BlogsId       map[uint]string
)

//go:embed templates/**/*.html
var templatesFS embed.FS

//go:embed ressources/js
//go:embed ressources/css
//go:embed ressources/img
var staticFS embed.FS

type captchas struct {
	store  base64Captcha.Store
	driver base64Captcha.Driver
}

// Models avec tags GORM
type Post struct {
	ID          uint          `json:"id" gorm:"primaryKey"`
	BlogID      uint          `json:"blog_id" gorm:"index"`
	Title       string        `json:"title" gorm:"not null"`
	Content     string        `json:"content" gorm:"type:text;not null"`
	ContentHTML template.HTML `json:"content_html" gorm:"-"`
	Excerpt     string        `json:"excerpt"`
	FirstImage  string        `json:"image" gorm:"type:text"`
	Author      string        `json:"author" gorm:"not null"`
	CreatedAt   time.Time     `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt   time.Time     `json:"updated_at" gorm:"autoUpdateTime"`
	Tags        string        `json:"-" gorm:"type:text"`
	Category    string        `json:"category" gorm:"type:text"`
	TagsList    []string      `json:"tags" gorm:"-"`
	Comments    []Comment     `json:"comments,omitempty" gorm:"foreignKey:PostID"`
	Hide        bool          `json:"hide" gorm:"type:bool"`
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

// Requests structs
type CreateCommentRequest struct {
	CaptchaID     string `json:"captchaID"`
	CaptchaAnswer string `json:"captchaAnswer"`
	Author        string `json:"author" binding:"required"`
	Content       string `json:"content" binding:"required"`
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type CreatePostRequest struct {
	Title     string   `json:"title" binding:"required"`
	Content   string   `json:"content" binding:"required"`
	Excerpt   string   `json:"excerpt"`
	Author    string   `json:"author"`
	Tags      []string `json:"tags"`
	Category  string   `json:"category"`
	CreatedAt string   `json:"createdAt"`
	Hide      bool     `json:"hide"`
}

type UpdatePostRequest struct {
	Title    string   `json:"title" binding:"required"`
	Content  string   `json:"content" binding:"required"`
	Excerpt  string   `json:"excerpt"`
	Tags     []string `json:"tags"`
	Category string   `json:"category"`
	Hide     bool     `json:"hide"`
}

type Config struct {
	TrustedProxies  []string       `yaml:"trustedproxies"`
	TrustedPlatform string         `yaml:"trustedplatform"`
	Database        DatabaseConfig `yaml:"database"`
	StaticPath      string         `yaml:"staticpath"`
	User            UserConfig     `yaml:"user"`
	Production      bool           `yaml:"production"`
	Listen          ListenConfig   `yaml:"listen"`
	Logger          LoggerConfig   `yaml:"logger"`
	Blogs           []BlogsConfig  `yaml:"blogs"`
}

type BlogsConfig struct {
	Id          uint       `yaml:"id"`
	Hostname    string     `yaml:"hostname"`
	SiteName    string     `yaml:"sitename"`
	Logo        string     `yaml:"logoimg"`
	Favicon     string     `yaml:"favicon"`
	Description string     `yaml:"description"`
	Theme       string     `yaml:"theme"`
	Menu        []MenuItem `yaml:"menu"`

	ThemeCSS string        `yaml:"-"`
	LinkRSS  template.HTML `yaml:"-"`
}

type LoggerConfig struct {
	Level  string             `yaml:"level"`
	File   loggerFileConfig   `yaml:"file"`
	Syslog loggerSyslogConfig `yaml:"syslog"`
}

type loggerFileConfig struct {
	Enable     bool   `yaml:"enable"`
	Path       string `yaml:"path"`
	MaxSize    int    `yaml:"maxsize"`
	MaxBackups int    `yaml:"maxbackups"`
	MaxAge     int    `yaml:"maxage"`
	Compress   bool   `yaml:"compress"`
}

type loggerSyslogConfig struct {
	Enable   bool            `yaml:"enable"`
	Protocol string          `yaml:"protocol"`
	Address  string          `yaml:"address"`
	Tag      string          `yaml:"tag"`
	Priority syslog.Priority `yaml:"priority"`
}

// SyslogLevelWriter adapte syslog.Writer pour gérer les niveaux zerolog
type SyslogLevelWriter struct {
	writer *syslog.Writer
}

type ListenConfig struct {
	Website string `yaml:"website"`
	Metrics string `yaml:"metrics"`
}

type UserConfig struct {
	Login string `yaml:"login"`
	Pass  string `yaml:"pass"`
	Hash  string `yaml:"hash"`
}

type DatabaseConfig struct {
	Redis string `yaml:"redis"`
	Db    string `yaml:"db"`
	Path  string `yaml:"path"`
	Dsn   string `yaml:"dsn"`
}

type MenuItem struct {
	Key   string `yaml:"key"`
	Value string `yaml:"value"`
	Link  string `yaml:"link"`
	Img   string `yaml:"img"`
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
	Title       string        `xml:"title"`
	Link        string        `xml:"link"`
	Description string        `xml:"description"`
	Author      string        `xml:"author,omitempty"`
	Category    string        `xml:"category,omitempty"`
	GUID        string        `xml:"guid"`
	PubDate     string        `xml:"pubDate"`
	Enclosure   *RSSEnclosure `xml:"enclosure"`
}

type RSSEnclosure struct {
	URL    string `xml:"url,attr"`
	Length int64  `xml:"length,attr"`
	Type   string `xml:"type,attr"`
}

// Color représente une couleur RGB
type Color struct {
	R, G, B int
}

// Créer un store Redis personnalisé
type RedisStore struct {
	client     *redis.Client
	expiration time.Duration
}

type externalLinkTransformer struct{}

// Remplir Excerpt calculé a partir de content
func (p *Post) FillExcerpt() error {
	// Générer l'excerpt texte si vide
	if p.Content != "" {
		if p.Excerpt == "" {
			p.Excerpt = CleanMarkdownForExcerpt(p.Content)
			p.Excerpt = ExtractExcerpt(p.Excerpt, 500)
		} else {
			p.Excerpt = CleanMarkdownForExcerpt(p.Excerpt)
		}
		p.FirstImage = ""

		found, l := ExtractImages(p.Content, true, true)
		if found {
			p.FirstImage = l[0]
		}
	}
	return nil
}

func CleanMarkdownForExcerpt(content string) string {
	// supprimer les images
	reImage := regexp.MustCompile(`!\[.*?\]\(.*?\)`)
	return reImage.ReplaceAllString(content, "")
}

// ExtractExcerpt génère automatiquement un résumé depuis le contenu Markdown
func ExtractExcerpt(text string, maxLength int) string {
	// Si le texte est déjà assez court
	if utf8.RuneCountInString(text) <= maxLength {
		return text
	}

	runes := []rune(text)

	// D'abord, chercher une fin de phrase (. ! ?)
	cutPoint := maxLength
	for i := maxLength - 1; i >= maxLength-100 && i >= 0; i-- {
		if runes[i] == '.' || runes[i] == '!' || runes[i] == '?' {
			// Inclure le point/ponctuation et avancer d'un caractère
			cutPoint = i + 1
			break
		}
	}

	// Si aucune fin de phrase trouvée, chercher un espace
	if cutPoint == maxLength {
		for i := maxLength - 1; i >= maxLength-50 && i >= 0; i-- {
			if runes[i] == ' ' {
				cutPoint = i
				break
			}
		}
	}

	result := strings.TrimSpace(string(runes[:cutPoint]))

	// Ajouter "..." seulement si on n'a pas terminé sur une ponctuation
	lastChar := runes[cutPoint-1]
	if lastChar != '.' && lastChar != '!' && lastChar != '?' {
		result += "..."
	}

	return result
}

// ExtractImages extrait l'URL des images du Markdown
// Exemple: ![monimage.jpg](/static/uploads/1759683627_d4hhlyrc.jpg)
func ExtractImages(markdown string, firstOnly bool, fileOnly bool) (bool, []string) {
	if markdown == "" {
		return false, nil
	}

	// Pattern pour les images markdown: ![alt](url)
	reImage := regexp.MustCompile(`!\[[^\]]*\]\(([^)]+)\)`)

	var l []string
	found := false

	// Utiliser FindAllStringSubmatch au lieu de FindStringSubmatch
	matches := reImage.FindAllStringSubmatch(markdown, -1)

	for _, match := range matches {
		if len(match) > 1 {
			if fileOnly {
				// match[1] contient déjà le chemin capturé par le groupe ()
				imageURL := strings.TrimSpace(match[1])
				imageURL = strings.Trim(imageURL, `"' `)
				l = append(l, imageURL)
			} else {
				// match[0] contient toute la correspondance ![alt](url)
				imageURL := strings.TrimSpace(match[0])
				l = append(l, imageURL)
			}
			found = true

			if firstOnly {
				break
			}
		}
	}

	return found, l
}

// InitLogger configure le logger global Zerolog
// Setup initialise le logger avec la configuration
func initLogger(cfg LoggerConfig, production bool) {
	// Définir le niveau de log
	level := parseLevel(cfg.Level)
	zerolog.SetGlobalLevel(level)

	// Configurer le format de temps
	zerolog.TimeFieldFormat = time.RFC3339

	var writers []io.Writer

	// Writer pour la console
	if !production {
		consoleWriter := zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: "15:04:05",
			NoColor:    false,
		}
		writers = append(writers, consoleWriter)
	}

	// Writer pour le fichier si activé
	if cfg.File.Enable {
		fileWriter, err := setupFileWriter(cfg.File)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to setup file writer")
		}
		writers = append(writers, fileWriter)
	}

	// Wrtier syslog si activé
	if cfg.Syslog.Enable {
		syslogWriter, err := setupSyslogWriter(cfg.Syslog)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to setup syslog writer")
		}
		writers = append(writers, syslogWriter)
	}

	if len(writers) == 0 {
		writers = append(writers, os.Stdout)
	}

	// Créer un multi-writer
	multi := io.MultiWriter(writers...)

	// Configurer le logger global
	log.Logger = zerolog.New(multi).
		With().
		Timestamp().
		Caller().
		Logger()

	environnment := "developpement"
	if production {
		environnment = "production"
	}
	log.Info().
		Str("environment", environnment).
		Str("level", cfg.Level).
		Bool("log_to_file", cfg.File.Enable).
		Bool("log_to_syslog", cfg.Syslog.Enable).
		Msg("Logger initialized")
}

// setupFileWriter configure le writer pour les fichiers
func setupFileWriter(cfg loggerFileConfig) (io.Writer, error) {
	// Créer le dossier si nécessaire
	dir := filepath.Dir(cfg.Path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	fileWriter := &lumberjack.Logger{
		Filename:   cfg.Path,
		MaxSize:    cfg.MaxSize,
		MaxBackups: cfg.MaxBackups,
		MaxAge:     cfg.MaxAge,
		Compress:   cfg.Compress,
	}

	return fileWriter, nil
}

// setupSyslogWriter configure le writer pour syslog
func setupSyslogWriter(cfg loggerSyslogConfig) (io.Writer, error) {
	// Utiliser un tag par défaut si non spécifié
	tag := cfg.Tag
	if tag == "" {
		tag = "littleblog"
	}
	// Utiliser une priorité par défaut si non spécifiée
	priority := cfg.Priority
	if priority == 0 {
		priority = syslog.LOG_INFO | syslog.LOG_LOCAL0
	}

	var writer *syslog.Writer
	var err error

	// Connexion locale ou distante
	if cfg.Protocol == "" || cfg.Address == "" {
		// Connexion locale (Unix socket)
		writer, err = syslog.New(priority, tag)
	} else {
		// Connexion distante (TCP ou UDP)
		writer, err = syslog.Dial(cfg.Protocol, cfg.Address, priority, tag)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to syslog: %w", err)
	}

	// Wrapper pour adapter syslog.Writer à io.Writer avec le bon niveau
	return &SyslogLevelWriter{writer: writer}, nil
}

// Write implémente io.Writer et route vers la bonne fonction syslog selon le niveau
func (w *SyslogLevelWriter) Write(p []byte) (n int, err error) {
	msg := string(p)

	// Parser le niveau depuis le JSON zerolog
	level := extractLevelFromJSON(msg)

	// Router vers la bonne méthode syslog selon le niveau
	switch level {
	case "debug":
		return len(p), w.writer.Debug(msg)
	case "info":
		return len(p), w.writer.Info(msg)
	case "warn", "warning":
		return len(p), w.writer.Warning(msg)
	case "error":
		return len(p), w.writer.Err(msg)
	case "fatal", "panic":
		return len(p), w.writer.Crit(msg)
	default:
		// Par défaut, utiliser Info
		return len(p), w.writer.Info(msg)
	}
}

// extractLevelFromJSON extrait le niveau de log d'un message JSON zerolog
// Format attendu: {"level":"info",...}
func extractLevelFromJSON(msg string) string {
	// Recherche simple du champ "level" dans le JSON
	// Format: "level":"xxx"
	startIdx := strings.Index(msg, `"level":"`)
	if startIdx == -1 {
		return ""
	}

	// Décaler après "level":"
	startIdx += 9

	// Trouver la fin (guillemet suivant)
	endIdx := strings.Index(msg[startIdx:], `"`)
	if endIdx == -1 {
		return ""
	}

	return msg[startIdx : startIdx+endIdx]
}

func parseLevel(level string) zerolog.Level {
	switch level {
	case "debug":
		return zerolog.DebugLevel
	case "info":
		return zerolog.InfoLevel
	case "warn":
		return zerolog.WarnLevel
	case "error":
		return zerolog.ErrorLevel
	default:
		return zerolog.InfoLevel
	}
}

// WithFields retourne un logger avec des champs prédéfinis
func WithFields(fields map[string]interface{}) zerolog.Logger {
	ctx := log.With()
	for k, v := range fields {
		ctx = ctx.Interface(k, v)
	}
	return ctx.Logger()
}

// WithRequestID retourne un logger avec un request ID
func WithRequestID(requestID string) zerolog.Logger {
	return log.With().Str("request_id", requestID).Logger()
}

// Debug logue un message de debug
func LogDebug(msg string) {
	log.Debug().Msg(msg)
}

// Info logue un message d'information
func LogInfo(msg string) {
	log.Info().Msg(msg)
}

// Info logue avec printf
func LogPrintf(format string, a ...any) {
	log.Info().Msg(fmt.Sprintf(format, a...))
}

// Warn logue un avertissement
func LogWarn(msg string) {
	log.Warn().Msg(msg)
}

// Error logue une erreur
func LogError(err error, msg string) {
	log.Error().Err(err).Msg(msg)
}

// Fatal logue une erreur fatale et arrête le programme
func LogFatal(err error, msg string) {
	log.Fatal().Err(err).Str("msg", msg)
}

func NewRedisStore(client *redis.Client) *RedisStore {
	return &RedisStore{
		client:     client,
		expiration: 5 * time.Minute,
	}
}

func (r *RedisStore) Set(id string, value string) error {
	ctx := context.Background()
	return r.client.Set(ctx, "captcha:"+id, value, r.expiration).Err()
}

func (r *RedisStore) Get(id string, clear bool) string {
	ctx := context.Background()
	key := "captcha:" + id
	val, _ := r.client.Get(ctx, key).Result()
	if clear {
		r.client.Del(ctx, key)
	}
	return val
}

func (r *RedisStore) Verify(id, answer string, clear bool) bool {
	v := r.Get(id, clear)
	return v == answer
}

func newCaptcha(host string) *captchas {
	var store base64Captcha.Store
	if host != "" {
		redisClient := redis.NewClient(&redis.Options{
			Addr: host,
		})
		store = NewRedisStore(redisClient)
	} else {
		store = base64Captcha.DefaultMemStore
	}

	driver := base64Captcha.NewDriverMath(
		80,  // hauteur
		240, // largeur
		6,   // nombre d'opérations à afficher
		base64Captcha.OptionShowHollowLine,
		nil, // couleur de fond
		nil, // police
		nil, // couleurs
	)

	return &captchas{
		store:  store,
		driver: driver,
	}
}

func (cap *captchas) captchaHandler(c *gin.Context) {
	data, err := cap.generateCaptcha(configuration.Production)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, data)
}

func (cap *captchas) generateCaptcha(production bool) (map[string]any, error) {
	captcha := base64Captcha.NewCaptcha(cap.driver, cap.store)

	id, b64s, answer, err := captcha.Generate()
	if err != nil {
		return nil, fmt.Errorf("erreur lors de la génération du CAPTCHA")
	}

	data := gin.H{
		"captcha_id": id,
		"image":      b64s,
		"answer":     "",
	}

	if !production {
		fmt.Printf("CAPTCHA généré - ID: %s, Réponse: %s", id, answer)
		data["answer"] = answer
	}

	return data, nil
}

func (cap *captchas) verifyCaptcha(captchaID string, captchaAnswer string) error {
	captchaID = strings.TrimSpace(captchaID)
	captchaAnswer = strings.TrimSpace(captchaAnswer)

	if captchaID == "" || captchaAnswer == "" {
		return fmt.Errorf("CAPTCHA manquant")
	}

	if !cap.store.Verify(captchaID, captchaAnswer, true) {
		return fmt.Errorf("CAPTCHA incorrect")
	}
	return nil
}

func createExampleConfig(filename string) (string, error) {
	example := &Config{
		Database: DatabaseConfig{
			Db:   "sqlite",
			Path: "./test.db",
		},
		User: UserConfig{
			Login: "admin",
			Pass:  "admin1234",
		},
		StaticPath: "./static",
		Production: false,
		Logger: LoggerConfig{
			Level: "info",
			File: loggerFileConfig{
				Enable: false,
			},
			Syslog: loggerSyslogConfig{
				Enable: false,
			},
		},
		Listen: ListenConfig{
			Website: "0.0.0.0:8080",
			Metrics: "0.0.0.0:8090",
		},
		Blogs: []BlogsConfig{
			{
				Id:          0,
				SiteName:    "Mon Blog Tech",
				Description: "Blog qui utilise littleblog",
				Logo:        "/static/linux.png",
				Favicon:     "/files/img/linux.png",
				Theme:       "blue",
				Menu: []MenuItem{
					{Key: "menu1", Value: "Menu 1"},
					{Key: "menu2", Value: "Menu 2", Img: "/static/linux.png"},
					{Link: "https://github.com/clankgeek/littleblog", Value: "Sur github"},
				},
			},
		},
	}

	if filename == "/etc/" {
		example.Listen.Website = "127.0.0.1:8000"
		example.Listen.Metrics = ""
		example.Production = true
		example.Database.Path = "/var/lib/littleblog/sqlite.db"
		example.StaticPath = "/var/lib/littleblog/static"
		example.Logger.File = loggerFileConfig{
			Enable:     true,
			Path:       "/var/log/littleblog/littleblog.log",
			MaxSize:    100,
			MaxBackups: 30,
			MaxAge:     7,
			Compress:   true,
		}
		filename = "/etc/littleblog/config.yaml"
	}

	return filename, writeConfigYaml(filename, example)
}

func writeConfigYaml(filename string, conf *Config) error {
	data, err := yaml.Marshal(conf)
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

func handleExampleCreation(filename string) error {
	if filename == "" {
		filename = "littleblog.yaml"
	}
	filename, err := createExampleConfig(filename)
	if err != nil {
		return fmt.Errorf("erreur création exemple: %v", err)
	}

	fmt.Printf("✅ Fichier exemple créé: %s", filename)
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

	if conf.Database.Db == "sqlite" && conf.Database.Path == "" {
		return nil, fmt.Errorf("database.path ne peut pas être vide")
	}
	if conf.Database.Db == "mysql" && conf.Database.Dsn == "" {
		return nil, fmt.Errorf("database.dsn ne peut pas être vide")
	}
	if conf.Database.Db == "" {
		return nil, fmt.Errorf("database.db ne peut pas être vide")
	}

	if conf.Listen.Website == "" {
		conf.Listen.Website = "localhost:8080"
	}
	if strings.HasPrefix(conf.Listen.Website, ":") {
		conf.Listen.Website = "localhost" + conf.Listen.Website
	}

	if conf.User.Pass != "" {
		if len(conf.User.Pass) < 8 {
			return nil, fmt.Errorf("le mot de passe doit contenir au moins 8 caractères")
		}

		hash, err := argon2.GenerateFromPassword([]byte(conf.User.Pass), argon2.DefaultParams)
		if err != nil {
			return nil, err
		}
		conf.User.Hash = string(hash)
		conf.User.Pass = ""
		err = writeConfigYaml(configFile, conf)
		if err != nil {
			return nil, err
		}
	}

	BlogsId = make(map[uint]string, len(conf.Blogs))
	Blogs = make(map[string]BlogsConfig, len(conf.Blogs))
	var idfound []uint
	for _, item := range conf.Blogs {
		if slices.Contains(idfound, item.Id) {
			return nil, fmt.Errorf("l'id dans les blogs doit etre unique")
		}
		idfound = append(idfound, item.Id)

		if item.Favicon == "" {
			item.Favicon = "/files/img/linux.png"
		}

		item.LinkRSS, err = GenerateDynamicRSS(item.Menu, item.SiteName)
		if err != nil {
			return nil, err
		}
		item.ThemeCSS = GenerateThemeCSS(item.Theme)
		Blogs[item.Hostname] = item
		BlogsId[item.Id] = item.Hostname
	}

	return conf, nil
}

// Convertir la config YAML en config interne
func convertConfig(yamlConfig *Config) *Config {
	conf := &Config{
		Database:        yamlConfig.Database,
		User:            yamlConfig.User,
		StaticPath:      yamlConfig.StaticPath,
		Production:      yamlConfig.Production,
		Listen:          yamlConfig.Listen,
		TrustedProxies:  yamlConfig.TrustedProxies,
		TrustedPlatform: yamlConfig.TrustedPlatform,
		Logger:          yamlConfig.Logger,
		Blogs:           yamlConfig.Blogs,
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

func (t *externalLinkTransformer) Transform(node *ast.Document, reader text.Reader, pc parser.Context) {
	ast.Walk(node, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}

		if link, ok := n.(*ast.Link); ok {
			link.SetAttributeString("target", []byte("_blank"))
			link.SetAttributeString("rel", []byte("noopener noreferrer"))
		}

		return ast.WalkContinue, nil
	})
}

// Initialiser le convertisseur Markdown
func initMarkdown() {
	md = goldmark.New(
		goldmark.WithExtensions(
			extension.GFM,
			extension.Table,
			extension.Strikethrough,
			extension.TaskList,
			emoji.Emoji,
		),
		goldmark.WithParserOptions(
			parser.WithAutoHeadingID(),
			parser.WithASTTransformers(
				util.Prioritized(&externalLinkTransformer{}, 100),
			),
		),
		goldmark.WithRendererOptions(
			html.WithHardWraps(),
			html.WithXHTML(),
			html.WithUnsafe(),
		),
	)
	LogInfo("Convertisseur Markdown initialisé")
}

// Convertir Markdown en HTML
func convertMarkdownToHTML(markdown string) template.HTML {
	var buf bytes.Buffer
	if err := md.Convert([]byte(markdown), &buf); err != nil {
		LogError(err, "Erreur conversion Markdown")
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
		LogFatal(err, "Erreur génération clé secrète")
	}
	return key
}

func initDatabase() {
	var err error
	switch configuration.Database.Db {
	case "sqlite":
		db, err = gorm.Open(sqlite.Open(configuration.Database.Path), &gorm.Config{
			Logger: logger.Default.LogMode(logger.Info),
		})
	case "mysql":
		db, err = gorm.Open(mysql.Open(configuration.Database.Dsn), &gorm.Config{
			Logger: logger.Default.LogMode(logger.Info),
		})
	default:
		err = fmt.Errorf("le type de database doit etre sqlite ou mysql")
	}
	if err != nil {
		LogFatal(err, "Erreur connexion base de données:")
	}

	err = db.AutoMigrate(&Post{}, &Comment{})
	if err != nil {
		LogFatal(err, "Erreur migration:")
	}

	var count int64
	db.Model(&Post{}).Count(&count)

	LogInfo("Base de données initialisée avec succès")
}

func getFirstMenuKey(conf *BlogsConfig) string {
	if len(conf.Menu) > 0 {
		return slugify(conf.Menu[0].Key)
	}
	return ""
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
		if key == category && item.Link == "" {
			active = " active"
		}
		img := ""
		if item.Img != "" {
			img = fmt.Sprintf("<img src=\"%s\" class=\"icon\"> ", item.Img)
		}
		target := ""
		blank := ""
		if item.Link != "" {
			target = item.Link
			blank = " target=\"_blank\""
		} else {
			target = "/" + key
		}
		menuStr += fmt.Sprintf("<a href=\"%s\" class=\"nav-link%s\"%s>%s%s</a>&nbsp;", target, active, blank, img, item.Value)
	}
	return safeHtml(menuStr)
}

func GenerateDynamicRSS(Menu []MenuItem, SiteName string) (template.HTML, error) {
	rssStr := ""
	for _, item := range Menu {
		if item.Key == "" {
			continue
		}
		slugifiedKey := slugify(item.Key)
		if slugifiedKey == "files" || slugifiedKey == "static" {
			return "", fmt.Errorf("la clé du menu doit etre différente de 'files' et de 'static'")
		}
		rssStr += fmt.Sprintf("    <link rel=\"alternate\" type=\"application/rss+xml\" title=\"%s - %s\" href=\"/rss.xml/%s\"/>\n", SiteName, slugifiedKey, slugifiedKey)
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

func middlerwareLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Traiter la requête
		c.Next()

		// Calculer la latence
		latency := time.Since(start)

		// Récupérer les informations de la requête
		statusCode := c.Writer.Status()
		method := c.Request.Method
		clientIP := c.ClientIP()
		userAgent := c.Request.UserAgent()

		// Construire le chemin complet avec query string
		if raw != "" {
			path = path + "?" + raw
		}

		// Créer l'événement de log avec le niveau approprié
		var logEvent *zerolog.Event
		switch {
		case statusCode == 404:
			logEvent = log.Debug()
		case statusCode >= 500:
			logEvent = log.Error()
		case statusCode >= 400:
			logEvent = log.Warn()
		default:
			logEvent = log.Info()
		}

		// Ajouter les champs et logger
		logEvent.
			Str("method", method).
			Str("path", path).
			Int("status", statusCode).
			Dur("latency", latency).
			Str("ip", clientIP).
			Str("user_agent", userAgent).
			Int("body_size", c.Writer.Size()).
			Msg("HTTP Request")

		// Logger les erreurs s'il y en a
		if len(c.Errors) > 0 {
			for _, err := range c.Errors {
				log.Error().
					Err(err.Err).
					Str("type", strconv.FormatUint(uint64(err.Type), 10)).
					Msg("Request error")
			}
		}
	}
}

func middlewareBlogId() gin.HandlerFunc {
	return func(c *gin.Context) {
		host := c.Request.Host
		if strings.Contains(host, ":") {
			host = strings.Split(host, ":")[0]
		}
		if _, ok := Blogs[host]; ok {
			c.Set("hostname", host)
		}
		c.Next()
	}
}

func middlewareRecovery() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				log.Error().
					Interface("error", err).
					Str("path", c.Request.URL.Path).
					Str("method", c.Request.Method).
					Msg("Panic recovered")

				c.AbortWithStatus(500)
			}
		}()
		c.Next()
	}
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
		return fmt.Sprintf("%dµs", int(d.Nanoseconds())/1000)
	}
	if d < time.Second {
		return fmt.Sprintf("%dms", int(d.Nanoseconds())/1e6)
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

func getTemplates() *template.Template {
	m := minify.New()

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

func createExample(shouldCreateExample bool, configFile string) {
	// Handle example creation
	if shouldCreateExample {
		if err := handleExampleCreation(configFile); err != nil {
			fmt.Printf("❌ %v\n", err)
		}
		os.Exit(1)
	}

	_, err := os.Stat(configFile)
	if err != nil && os.IsNotExist(err) {
		if err := handleExampleCreation(configFile); err != nil {
			fmt.Printf("❌ %v\n", err)
			os.Exit(1)
		}

	}
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

	createExample(shouldCreateExample, configFile)

	// Load and validate configuration
	conf, err := loadAndConvertConfig(configFile)
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		os.Exit(1)
	}

	configuration = conf
	captcha = newCaptcha(configuration.Database.Redis)
}

func setMiddleware(r *gin.Engine) {
	// logger
	r.Use(middlerwareLogger())
	r.Use(middlewareRecovery())

	// get blog Id
	r.Use(middlewareBlogId())

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
	r := gin.New()

	if configuration.TrustedProxies != nil {
		r.SetTrustedProxies(configuration.TrustedProxies)
	}
	if configuration.TrustedPlatform != "" {
		switch configuration.TrustedPlatform {
		case "cloudflare":
			r.TrustedPlatform = gin.PlatformGoogleAppEngine
		case "google":
			r.TrustedPlatform = gin.PlatformGoogleAppEngine
		case "flyio":
			r.TrustedPlatform = gin.PlatformFlyIO
		default:
			r.TrustedPlatform = configuration.TrustedPlatform
		}
	}

	// parser les templates
	r.SetHTMLTemplate(getTemplates())

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

	// metrics routes (port 8090)
	metrics := ginmetrics.GetMonitor()
	metrics.Use(r)

	// Route statiques
	r.Static("/static/", configuration.StaticPath)
	r.GET("/files/css/*.css", ServeMinifiedStatic(m))
	r.GET("/files/js/*.js", ServeMinifiedStatic(m))
	r.GET("/files/img/*.svg", ServeMinifiedStatic(m))

	// theme
	r.GET("/files/theme.css/:id", themeHandler)

	// Routes publiques
	r.GET("/", indexHandler)
	r.GET("/:category", indexHandler)
	r.GET("/post/:id", postHandler)
	r.GET("/files/captcha", captcha.captchaHandler)

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
		api.DELETE("/comments/:id", authRequired(), deleteCommentAPI)
		api.GET("/search", searchPostsAPI)
	}

	// Flux RSS
	r.GET("/rss.xml", rssHandler)
	r.GET("/rss.xml/:category", rssHandler)
}

func startServer(r *gin.Engine) {
	if configuration.Listen.Metrics != "" {
		LogPrintf("Metrics disponible sur http://%s/metrics", configuration.Listen.Metrics)
		go func() {
			http.Handle("/metrics", promhttp.Handler())
			http.ListenAndServe(configuration.Listen.Metrics, nil)
		}()
	}

	LogPrintf("Website démarré sur http://%s", configuration.Listen.Website)
	LogPrintf("Admin: http://%s/admin/login", configuration.Listen.Website)
	r.Run(configuration.Listen.Website)
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
		return *config, true, false, nil
	}

	if *config == "" {
		return "", false, false, fmt.Errorf("fichier de configuration requis")
	}

	return *config, false, false, nil
}

func displayConfiguration(config *Config) {
	LogPrintf("Littleblog version %s", VERSION)

	LogPrintf("Mode Production %v", config.Production)
	LogPrintf("Administrateur login %s", config.User.Login)

	LogPrintf("Database")
	if config.Database.Db == "sqlite" {
		LogPrintf("  • Type sqlite")
		LogPrintf("  • Path %s", config.Database.Path)
	}
	if config.Database.Db == "mysql" {
		LogPrintf("  • Type mysql")
		LogPrintf("  • DSN %s", config.Database.Dsn)
	}
	if config.Database.Redis != "" {
		LogPrintf("  • Cache redis %s", config.Database.Redis)
	}

	// Logger
	LogPrintf("Logger en level %s", config.Logger.Level)
	if config.Logger.File.Enable {
		LogPrintf("  Log en fichier activé")
		LogPrintf("  • Path %s", config.Logger.File.Path)
		LogPrintf("  • Max size %d", config.Logger.File.MaxSize)
		LogPrintf("  • Max age %d", config.Logger.File.MaxAge)
		LogPrintf("  • Max backup %d", config.Logger.File.MaxBackups)
		LogPrintf("  • Compression %v", config.Logger.File.Compress)
	} else {
		LogPrintf("  Log en fichier désactivé")
	}
	if config.Logger.Syslog.Enable {
		LogPrintf("  Log en syslog activé")
		LogPrintf("  • Protocol %s", config.Logger.Syslog.Protocol)
		LogPrintf("  • Address %s", config.Logger.Syslog.Address)
		LogPrintf("  • Tag %s", config.Logger.Syslog.Tag)
		LogPrintf("  • Priority %v", config.Logger.Syslog.Priority)
	} else {
		LogPrintf("  Log en syslog désactivé")
	}

	LogPrintf("Liste des blogs")
	for _, blog := range config.Blogs {
		LogPrintf("  • \"%s\" avec l'id %d et le hostname %s", blog.SiteName, blog.Id, blog.Hostname)
	}
}

func main() {
	if BuildID == "" {
		BuildID = VERSION
	}

	initConfiguration()
	initLogger(configuration.Logger, configuration.Production)
	displayConfiguration(configuration)

	initMarkdown()
	initDatabase()

	r := newServer()

	setMiddleware(r)
	setRoutes(r)

	startServer(r)
}

// ============= HANDLERS PUBLICS =============

func getConfItem(c *gin.Context, withId bool, id uint) BlogsConfig {
	if withId {
		if item, ok := BlogsId[id]; ok {
			return Blogs[item]
		}
	} else {
		host, found := c.Get("hostname")
		if found {
			return Blogs[host.(string)]
		}
	}
	if item, ok := BlogsId[0]; ok {
		return Blogs[item]
	}
	return BlogsConfig{}
}

func themeHandler(c *gin.Context) {
	idStr := c.Param("id")
	blogId, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		blogId = 0
	}
	item := getConfItem(c, true, uint(blogId))

	c.Header("Content-Type", "text/css; charset=utf-8")
	c.Header("Cache-Control", "public, max-age=3600")
	re := regexp.MustCompile("[^a-zA-Z0-9]+")
	c.Header("ETag", fmt.Sprintf("%s%s%d", BuildID, re.ReplaceAllString(item.Theme, ""), blogId))

	c.Data(http.StatusOK, "text/css", []byte(item.ThemeCSS))
}

func indexHandler(c *gin.Context) {
	session := sessions.Default(c)
	isAdmin := session.Get("user_id") != nil
	category := slugify(c.Param("category"))
	memories := ""

	if isAdmin {
		memories = getMemUsage()
	}

	item := getConfItem(c, false, 0)
	c.HTML(http.StatusOK, "index", gin.H{
		"blogId":          item.Id,
		"title":           item.SiteName,
		"siteName":        item.SiteName,
		"logo":            item.Logo,
		"icone":           item.Favicon,
		"description":     item.Description,
		"isAuthenticated": isAdmin,
		"showSearch":      true,
		"currentYear":     time.Now().Year(),
		"ogType":          "website",
		"version":         VERSION,
		"category":        category,
		"menu":            GenerateMenu(item.Menu, category),
		"rsslink":         item.LinkRSS,
		"BuildID":         BuildID,
		"memories":        memories,
		"renderTime":      getRenderTime(c),
	})
}

func pageNotFound(c *gin.Context, title string) {
	item := getConfItem(c, false, 0)
	c.HTML(http.StatusNotFound, "404_not_found", gin.H{
		"blogId":      item.Id,
		"title":       title,
		"siteName":    item.SiteName,
		"logo":        item.Logo,
		"icone":       item.Favicon,
		"description": "La page que vous recherchez n'existe pas.",
		"currentYear": time.Now().Year(),
		"version":     VERSION,
		"BuildID":     BuildID,
		"menu":        GenerateMenu(item.Menu, ""),
		"renderTime":  getRenderTime(c),
	})
}

func postHandler(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		pageNotFound(c, "Page non trouvée")
		return
	}
	item := getConfItem(c, false, 0)

	var post Post
	result := db.Where("blog_id = ? AND NOT hide", item.Id).First(&post, uint(id))
	if result.Error != nil {
		pageNotFound(c, "Article non trouvé")
		return
	}

	session := sessions.Default(c)
	isAdmin := session.Get("user_id") != nil

	c.HTML(http.StatusOK, "posts", gin.H{
		"blogId":          item.Id,
		"title":           post.Title,
		"siteName":        item.SiteName,
		"logo":            item.Logo,
		"icone":           item.Favicon,
		"description":     item.Description,
		"post":            post,
		"isAuthenticated": isAdmin,
		"showSearch":      false,
		"currentYear":     time.Now().Year(),
		"ogTitle":         post.Title,
		"ogType":          "article",
		"version":         VERSION,
		"menu":            GenerateMenu(item.Menu, post.Category),
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
	item := getConfItem(c, false, 0)

	c.HTML(http.StatusOK, "admin_login", gin.H{
		"blogId":   item.Id,
		"title":    "Connexion Admin",
		"siteName": item.SiteName,
		"logo":     item.Logo,
		"icone":    item.Favicon,
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
	err := argon2.CompareHashAndPassword([]byte(configuration.User.Hash), []byte(req.Password))
	if err != nil || req.Username != configuration.User.Login {
		LogPrintf("Tentative de connexion échouée - User: %s, IP: %s", req.Username, c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Identifiants incorrects"})
		return
	}
	LogPrintf("Connexion réussie - User: %s, IP: %s", req.Username, c.ClientIP())

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
	item := getConfItem(c, false, 0)

	var stats struct {
		TotalPosts    int64
		TotalComments int64
		RecentPosts   []Post
	}

	db.Model(&Post{}).Where("blog_id = ?", item.Id).Count(&stats.TotalPosts)
	db.Model(&Comment{}).
		Joins("JOIN posts ON posts.id = comments.post_id").
		Where("posts.blog_id = ?", item.Id).
		Count(&stats.TotalComments)

	db.Where("blog_id = ?", item.Id).Order("created_at desc").Limit(5).Find(&stats.RecentPosts)

	session := sessions.Default(c)
	username := session.Get("username")

	c.HTML(http.StatusOK, "admin_dashboard", gin.H{
		"blogId":      item.Id,
		"title":       "Dashboard Admin",
		"siteName":    item.SiteName,
		"logo":        item.Logo,
		"icone":       item.Favicon,
		"pageTitle":   "Dashboard",
		"pageIcon":    "📊",
		"currentPage": "dashboard",
		"username":    username,
		"stats":       stats,
		"currentYear": time.Now().Year(),
		"isAdmin":     true,
		"version":     VERSION,
		"BuildID":     BuildID,
		"memories":    getMemUsage(),
		"renderTime":  getRenderTime(c),
	})
}

func getMemUsage() string {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return fmt.Sprintf("Statistiques mémoire: allouée = %v Mo, total allouée = %d Mo, système = %v Mo, nombre de GC = %v\n", m.Alloc/1024/1024, m.TotalAlloc/1024/1024, m.Sys/1024/1024, m.NumGC)
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

	item := getConfItem(c, false, 0)

	// Créer le dossier uploads s'il n'existe pas
	uploadsDir := fmt.Sprintf("%s/uploads/%d", configuration.StaticPath, item.Id)
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
	imageURL := fmt.Sprintf("/static/uploads/%d/%s", item.Id, filename)
	c.JSON(http.StatusOK, gin.H{
		"url":      imageURL,
		"filename": filename,
		"size":     finalSize,
		"format":   format,
	})
}

func adminPostsHandler(c *gin.Context) {
	item := getConfItem(c, false, 0)
	var posts []Post
	db.Where("blog_id = ?", item.Id).Order("created_at desc").Find(&posts)

	session := sessions.Default(c)
	username := session.Get("username")
	c.HTML(http.StatusOK, "admin_posts", gin.H{
		"blogId":      item.Id,
		"title":       "Gestion des Articles",
		"siteName":    item.SiteName,
		"logo":        item.Logo,
		"icone":       item.Favicon,
		"pageTitle":   "Gestion des Articles",
		"pageIcon":    "📝",
		"currentPage": "posts",
		"username":    username,
		"posts":       posts,
		"currentYear": time.Now().Year(),
		"isAdmin":     true,
		"version":     VERSION,
		"BuildID":     BuildID,
		"memories":    getMemUsage(),
		"renderTime":  getRenderTime(c),
	})
}

func getOptionsCategory(item BlogsConfig) template.HTML {
	var optionsCategory string
	for _, item := range item.Menu {
		slugifiedKey := slugify(item.Key)
		if slugifiedKey != "" && item.Value != "" {
			optionsCategory += fmt.Sprintf("<option value=\"%s\">%s</option>", slugifiedKey, item.Value)
		}
	}
	return safeHtml(optionsCategory)
}

func newPostPageHandler(c *gin.Context) {
	session := sessions.Default(c)
	username := session.Get("username")
	item := getConfItem(c, false, 0)
	c.HTML(http.StatusOK, "admin_post_form", gin.H{
		"blogId":          item.Id,
		"title":           "Nouvel Article",
		"siteName":        item.SiteName,
		"logo":            item.Logo,
		"icone":           item.Favicon,
		"pageTitle":       "Nouvel Article",
		"pageIcon":        "➕",
		"currentPage":     "new_post",
		"username":        username,
		"isEdit":          false,
		"currentYear":     time.Now().Year(),
		"isAdmin":         true,
		"version":         VERSION,
		"optionsCategory": getOptionsCategory(item),
		"BuildID":         BuildID,
		"memories":        getMemUsage(),
		"renderTime":      getRenderTime(c),
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
	item := getConfItem(c, false, 0)
	c.HTML(http.StatusOK, "admin_post_form", gin.H{
		"blogId":          item.Id,
		"title":           "Éditer Article",
		"siteName":        item.SiteName,
		"logo":            item.Logo,
		"icone":           item.Favicon,
		"pageTitle":       "Éditer l'Article",
		"pageIcon":        "✏️",
		"currentPage":     "edit_post",
		"username":        username,
		"post":            post,
		"isEdit":          true,
		"currentYear":     time.Now().Year(),
		"isAdmin":         true,
		"version":         VERSION,
		"optionsCategory": getOptionsCategory(item),
		"BuildID":         BuildID,
		"memories":        getMemUsage(),
		"renderTime":      getRenderTime(c),
	})
}

func dateTimestamp(d string) time.Time {
	loc, _ := time.LoadLocation("Europe/Paris")
	if d == "" {
		return time.Now()
	}

	if matched, _ := regexp.MatchString(`^\d{8}$`, d); matched {
		d = fmt.Sprintf("%s %s %s", d[0:2], d[2:4], d[4:8])
	}

	d += " 14:01"
	t, err := time.ParseInLocation("02 01 2006 15:05", d, loc)
	if err != nil {
		return time.Now()
	}
	return t
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

	item := getConfItem(c, false, 0)

	post := Post{
		BlogID:    item.Id,
		Title:     strings.TrimSpace(req.Title),
		Content:   strings.TrimSpace(req.Content),
		Excerpt:   strings.TrimSpace(req.Excerpt),
		CreatedAt: dateTimestamp(strings.TrimSpace(req.CreatedAt)),
		Author:    author,
		TagsList:  req.Tags,
		Category:  slugify(req.Category),
		Hide:      req.Hide,
	}

	post.FillExcerpt()

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
	post.Hide = req.Hide
	post.FillExcerpt()

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

	item := getConfItem(c, false, 0)

	// chercher les images du post
	var post Post
	result := db.Where("blog_id = ?", item.Id).First(&post, uint(id))
	if result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Article non trouvé"})
		return
	}
	imagesFound, images := ExtractImages(post.Content, false, true)

	// Supprimer dans une transaction commentaires puis l'article
	tx := db.Begin()

	// Supprimer les commentaires
	if err := tx.Where("post_id = ?", uint(id)).Delete(&Comment{}).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur suppression commentaires"})
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

	LogPrintf("Suppression du post %d", id)

	if imagesFound {
		for _, img := range images {
			if strings.HasPrefix(img, fmt.Sprintf("/static/uploads/%d", item.Id)) {
				LogPrintf("- Suppression de l'image %s", img)
				os.Remove(img)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Article supprimé avec succès"})
}

// ============= API HANDLERS =============

// rssHandler génère le flux RSS des posts
func getImageInfo(imagePath string) (size int64, mimeType string, err error) {
	// Obtenir les informations du fichier
	fileInfo, err := os.Stat(imagePath)
	if err != nil {
		return 0, "", err
	}

	// Taille du fichier
	size = fileInfo.Size()

	// Type MIME basé sur l'extension
	ext := filepath.Ext(imagePath)
	mimeType = mime.TypeByExtension(ext)

	// Si le type MIME n'est pas trouvé, définir une valeur par défaut
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}

	return size, mimeType, nil
}

func rssHandler(c *gin.Context) {
	var posts []Post

	item := getConfItem(c, false, 0)

	// Récupérer les 20 derniers posts
	query := db.Order("created_at desc").Limit(20)

	category := c.Param("category")
	if category != "" {
		query = query.Where("blog_id = ? AND NOT hide AND category = ?", item.Id, slugify(category))
	} else {
		query = query.Where("blog_id = ? AND NOT hide", item.Id)
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
			Title:         item.SiteName,
			Link:          baseURL,
			Description:   stripmd.Strip(item.Description),
			Language:      "fr-FR",
			Generator:     fmt.Sprintf("Littleblog v%s", VERSION),
			LastBuildDate: time.Now().Format(time.RFC1123Z),
			Items:         make([]RSSItem, 0, len(posts)),
		},
	}

	rss.Channel.Copyright = fmt.Sprintf("© %d %s", time.Now().Year(), item.SiteName)

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
			Description: stripmd.Strip(description),
			Author:      post.Author,
			Category:    category,
			GUID:        fmt.Sprintf("%s/post/%d", baseURL, post.ID),
			PubDate:     post.CreatedAt.Format(time.RFC1123Z),
			Enclosure:   nil,
		}

		// on génère l'image dans le rss si il y en a une de présente
		if post.FirstImage != "" {
			realpath := strings.Replace(post.FirstImage, "/static", configuration.StaticPath, 1)
			size, mime, err := getImageInfo(realpath)
			if err == nil {
				item.Enclosure = &RSSEnclosure{
					URL:    post.FirstImage,
					Length: size,
					Type:   mime,
				}
			}
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

	item := getConfItem(c, false, 0)
	buildQuery := func() *gorm.DB {
		query := db.Model(&Post{}).Where("blog_id = ? AND NOT hide", item.Id)
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

	// Convertir en Markdown le résumé
	for i, post := range posts {
		posts[i].Excerpt = string(convertMarkdownToHTML(post.Excerpt))
	}

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

func deleteCommentAPI(c *gin.Context) {
	idStr := c.Param("id")
	commentID, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ID invalide"})
		return
	}

	if err := db.Where("id = ?", uint(commentID)).Delete(&Comment{}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur suppression commentaires"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Commentaire supprimé avec succès"})
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
	result := db.Where("NOT hide").First(&post, uint(postID))
	if result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Article non trouvé"})
		return
	}

	var req CreateCommentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// controle du captcha
	err = captcha.verifyCaptcha(req.CaptchaID, req.CaptchaAnswer)
	if err != nil {
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

func searchPostsAPI(c *gin.Context) {
	query := strings.ToLower(strings.TrimSpace(c.Query("q")))
	if query == "" {
		c.JSON(http.StatusOK, []Post{})
		return
	}

	var posts []Post

	item := getConfItem(c, false, 0)

	searchTerm := "%" + query + "%"
	result := db.Where(
		"blog_id = ? AND (LOWER(title) LIKE ? OR LOWER(content) LIKE ? OR LOWER(excerpt) LIKE ? OR LOWER(tags) LIKE ?)",
		item.Id, searchTerm, searchTerm, searchTerm, searchTerm,
	).Order("created_at desc").Find(&posts)

	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur recherche"})
		return
	}

	c.JSON(http.StatusOK, posts)
}
