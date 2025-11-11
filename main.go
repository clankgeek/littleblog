package main

import (
	"crypto/sha256"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"io/fs"
	"littleblog/internal/clmiddleware"
	handlers_analytics "littleblog/internal/handlers/analytics"
	handlers_rss "littleblog/internal/handlers/rss"
	"littleblog/internal/models/clanalytics"
	"littleblog/internal/models/clblog"
	"littleblog/internal/models/clconfig"
	"littleblog/internal/models/climages"
	"littleblog/internal/models/cllog"
	"littleblog/internal/models/clmarkdown"
	"littleblog/internal/models/clposts"
	mrand "math/rand"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/andskur/argon2-hashing"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"github.com/tdewolff/minify/v2"
	"github.com/tdewolff/minify/v2/css"
	"github.com/tdewolff/minify/v2/js"
	"gorm.io/gorm"
)

const VERSION string = "0.8.0"

// global instance
var (
	BuildID string
)

//go:embed templates/**/*.html
var templatesFS embed.FS

//go:embed ressources/js
//go:embed ressources/css
//go:embed ressources/img
var staticFS embed.FS

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

func loadAndConvertConfig(configFile string) (*clconfig.Config, error) {
	// Charger la configuration YAML
	yamlConfig, err := clconfig.LoadConfig(configFile)
	if err != nil {
		return nil, fmt.Errorf("erreur chargement config: %v", err)
	}

	// Convertir en config interne
	conf := clconfig.ConvertConfig(yamlConfig)

	if conf.Database.Db == "sqlite" && conf.Database.Path == "" {
		return nil, fmt.Errorf("database.path ne peut pas être vide")
	}
	if conf.Database.Db == "mysql" && conf.Database.Dsn == "" {
		return nil, fmt.Errorf("database.dsn ne peut pas être vide")
	}
	if conf.Database.Db == "" {
		return nil, fmt.Errorf("database.db ne peut pas être vide")
	}

	if conf.Analytics.Enabled {
		if conf.Analytics.Db == "sqlite" && conf.Analytics.Path == "" {
			return nil, fmt.Errorf("analytics.path ne peut pas être vide en mode sqlite")
		}
		if conf.Analytics.Db == "mysql" && conf.Analytics.Dsn == "" {
			return nil, fmt.Errorf("analytics.dsn ne peut pas être vide en mode mysql")
		}
		if conf.Analytics.Redis.Addr == "" {
			return nil, fmt.Errorf("analytics.redis.addr ne peut pas être vide")
		}
		if conf.Database.Redis.Db == conf.Analytics.Redis.Db {
			return nil, fmt.Errorf("analytics.redis.db ne peut pas etre identique a database.redis.db")
		}
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
		err = clconfig.WriteConfigYaml(configFile, conf)
		if err != nil {
			return nil, err
		}
	}

	return conf, nil
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

func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[mrand.Intn(len(charset))]
	}
	return string(b)
}

func GenerateMenu(items []clconfig.MenuItem, category string) template.HTML {
	menuStr := ""
	for _, item := range items {
		key := clblog.Slugify(item.Key)
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
			if strings.HasSuffix(path, "min.js") {
				minified = content
			} else {
				minified, err = m.Bytes("application/javascript", content)
			}
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

		// En-têtes de cache
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
	return template.Must(template.New("").Funcs(template.FuncMap{
		"safeCSS":  safeCSS,
		"escapeJS": escapeJS,
		"jsonify":  jsonify,
	}).ParseFS(templatesFS, "templates/*/*.html"))
}

func initConfiguration() *clconfig.Config {
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

	clconfig.CreateExample(shouldCreateExample, configFile)

	// Load and validate configuration
	conf, err := loadAndConvertConfig(configFile)
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		os.Exit(1)
	}

	return conf

}

func newServer() *gin.Engine {
	configuration := clblog.GetInstance().Configuration

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

func setRoutes(r *gin.Engine, analytics bool, analyticsMiddleware *clmiddleware.AnalyticsMiddleware) {
	lb := clblog.GetInstance()

	m := minify.New()
	m.AddFunc("text/css", css.Minify)
	m.AddFunc("application/javascript", js.Minify)

	// middleware rate limiter
	middlewareLimiter := clmiddleware.NewLimiter()

	// Route statiques
	r.Static("/static/", lb.Configuration.StaticPath)
	r.GET("/files/css/*.css", ServeMinifiedStatic(m))
	r.GET("/files/js/*.js", ServeMinifiedStatic(m))
	r.GET("/files/img/*.svg", ServeMinifiedStatic(m))

	// theme
	r.GET("/files/theme.css/:id", themeHandler)

	// Routes publiques
	r.GET("/", indexHandler)
	r.GET("/:category", indexHandler)
	r.GET("/post/:id", postHandler)
	r.GET("/files/captcha", func(c *gin.Context) {
		lb.Captcha.CaptchaHandler(c, lb.Configuration.Production)
	})

	// Routes d'authentification
	r.GET("/admin/login", loginPageHandler)
	r.POST("/admin/login", middlewareLimiter, loginHandler)
	r.POST("/admin/logout", logoutHandler)

	var analyticsService *clanalytics.AnalyticsService
	var analyticsHandler *handlers_analytics.AnalyticsHandler
	if analytics {
		analyticsService = clanalytics.NewAnalyticsService(analyticsMiddleware.Db, analyticsMiddleware.Redis)
		analyticsHandler = handlers_analytics.NewAnalyticsHandler(analyticsService)
	}

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

		if analytics {
			admin.GET("/stats", analyticsHandler.GetStats30Days)
			admin.GET("/realtime", analyticsHandler.GetRealtimeStats)
			admin.GET("/analytics", adminAnalyticsHandler)
		}

		moderationHandler := clposts.NewModerationHandler(lb.Db)
		admin.GET("/moderation", adminModerationPageHandler)
		moderation := admin.Group("/api/moderation")
		{
			moderation.GET("/comments", moderationHandler.GetPendingComments)
			moderation.POST("/comments/:id/approve", moderationHandler.ApproveComment)
			moderation.DELETE("/comments/:id", moderationHandler.DeleteComment)
			moderation.POST("/comments/bulk-approve", moderationHandler.BulkApprove)
			moderation.POST("/comments/bulk-delete", moderationHandler.BulkDelete)
		}
	}

	// API publiques
	api := r.Group("/api")
	{
		api.GET("/posts", getPostsAPI)
		api.GET("/posts/:id", getPostAPI)
		api.GET("/posts/:id/comments", getCommentsAPI)
		api.POST("/posts/:id/comments", addCommentAPI)
		api.GET("/search", searchPostsAPI)
	}

	// Flux RSS
	r.GET("/rss.xml", handlers_rss.RssHandler)
	r.GET("/rss.xml/:category", handlers_rss.RssHandler)
}

func startServer(r *gin.Engine) {
	configuration := clblog.GetInstance().Configuration
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

func main() {
	if BuildID == "" {
		BuildID = VERSION
	}

	configuration := initConfiguration()

	clmarkdown.InitMarkdown()
	cllog.InitLogger(configuration.Logger, configuration.Production)

	blog := clblog.Init(configuration, VERSION, BuildID)

	clconfig.DisplayConfiguration(configuration, VERSION)

	r := newServer()

	analyticsMiddleware := clmiddleware.InitMiddleware(r, blog)
	setRoutes(r, configuration.Analytics.Enabled, analyticsMiddleware)

	startServer(r)
}

// ============= HANDLERS PUBLICS =============

func themeHandler(c *gin.Context) {
	idStr := c.Param("id")
	blogId, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		blogId = 0
	}

	item := clblog.GetInstance().GetConfItem(c, true, uint(blogId))

	c.Header("Content-Type", "text/css; charset=utf-8")
	c.Header("Cache-Control", "public, max-age=3600")
	re := regexp.MustCompile("[^a-zA-Z0-9]+")
	c.Header("ETag", fmt.Sprintf("%s%s%d", BuildID, re.ReplaceAllString(item.Theme, ""), blogId))

	c.Data(http.StatusOK, "text/css", []byte(item.ThemeCSS))
}

func indexHandler(c *gin.Context) {
	session := sessions.Default(c)
	isAdmin := session.Get("user_id") != nil
	category := clblog.Slugify(c.Param("category"))
	memories := ""
	approved := ""
	item := clblog.GetInstance().GetConfItem(c, false, 0)

	if isAdmin {
		memories = getMemUsage()

		var total int64
		clblog.GetInstance().Db.Model(&clposts.Comment{}).
			Joins("JOIN posts ON posts.id = comments.post_id").
			Where("posts.blog_id = ? AND NOT comments.approved", item.Id).
			Count(&total)
		if total > 0 {
			approved = fmt.Sprintf("⚠️ Il y a %d commentaires à approuver", total)
		}
	}

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
		"approved":        approved,
		"renderTime":      clmiddleware.GetRenderTime(c),
	})
}

func pageNotFound(c *gin.Context, title string) {
	item := clblog.GetInstance().GetConfItem(c, false, 0)
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
		"renderTime":  clmiddleware.GetRenderTime(c),
	})
}

func postHandler(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		pageNotFound(c, "Page non trouvée")
		return
	}
	item := clblog.GetInstance().GetConfItem(c, false, 0)

	var post clposts.Post
	result := clblog.GetInstance().Db.Where("blog_id = ? AND NOT hide", item.Id).First(&post, uint(id))
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
		"renderTime":      clmiddleware.GetRenderTime(c),
	})
}

// ============= HANDLERS D'AUTHENTIFICATION =============

func loginPageHandler(c *gin.Context) {
	session := sessions.Default(c)
	if session.Get("user_id") != nil {
		c.Redirect(http.StatusTemporaryRedirect, "/admin")
		return
	}
	item := clblog.GetInstance().GetConfItem(c, false, 0)

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

	configuration := clblog.GetInstance().Configuration

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

// Page de modération (HTML)
func adminModerationPageHandler(c *gin.Context) {
	item := clblog.GetInstance().GetConfItem(c, false, 0)

	session := sessions.Default(c)
	username := session.Get("username")

	c.HTML(http.StatusOK, "admin_moderation", gin.H{
		"blogId":      item.Id,
		"title":       "Commentaires Admin",
		"siteName":    item.SiteName,
		"logo":        item.Logo,
		"icone":       item.Favicon,
		"pageTitle":   "Modération",
		"pageIcon":    "📊",
		"currentPage": "Modération",
		"username":    username,
		"currentYear": time.Now().Year(),
		"isAdmin":     true,
		"version":     clblog.GetInstance().Version,
		"BuildID":     clblog.GetInstance().BuildID,
		"memories":    getMemUsage(),
		"renderTime":  clmiddleware.GetRenderTime(c),
	})
}

func adminAnalyticsHandler(c *gin.Context) {
	item := clblog.GetInstance().GetConfItem(c, false, 0)

	session := sessions.Default(c)
	username := session.Get("username")

	c.HTML(http.StatusOK, "admin_analytics", gin.H{
		"blogId":      item.Id,
		"title":       "Analytics Admin",
		"siteName":    item.SiteName,
		"logo":        item.Logo,
		"icone":       item.Favicon,
		"pageTitle":   "Analytics",
		"pageIcon":    "📊",
		"currentPage": "analytics",
		"username":    username,
		"currentYear": time.Now().Year(),
		"isAdmin":     true,
		"version":     VERSION,
		"BuildID":     BuildID,
		"memories":    getMemUsage(),
		"renderTime":  clmiddleware.GetRenderTime(c),
	})
}

func adminDashboardHandler(c *gin.Context) {
	item := clblog.GetInstance().GetConfItem(c, false, 0)
	db := clblog.GetInstance().Db

	var stats struct {
		TotalPosts               int64
		TotalComments            int64
		TotalCommentsNotApproved int64
		RecentPosts              []clposts.Post
	}

	db.Model(&clposts.Post{}).Where("blog_id = ?", item.Id).Count(&stats.TotalPosts)
	db.Model(&clposts.Comment{}).
		Joins("JOIN posts ON posts.id = comments.post_id").
		Where("posts.blog_id = ?", item.Id).
		Count(&stats.TotalComments)
	db.Model(&clposts.Comment{}).
		Joins("JOIN posts ON posts.id = comments.post_id").
		Where("posts.blog_id = ? AND NOT comments.approved", item.Id).
		Count(&stats.TotalCommentsNotApproved)

	db.Where("blog_id = ?", item.Id).Order("created_at desc").Limit(5).Find(&stats.RecentPosts)

	session := sessions.Default(c)
	username := session.Get("username")

	c.HTML(http.StatusOK, "admin_dashboard", gin.H{
		"blogId":           item.Id,
		"title":            "Dashboard Admin",
		"siteName":         item.SiteName,
		"logo":             item.Logo,
		"icone":            item.Favicon,
		"pageTitle":        "Dashboard",
		"pageIcon":         "📊",
		"currentPage":      "dashboard",
		"username":         username,
		"stats":            stats,
		"currentYear":      time.Now().Year(),
		"isAdmin":          true,
		"version":          VERSION,
		"BuildID":          BuildID,
		"memories":         getMemUsage(),
		"renderTime":       clmiddleware.GetRenderTime(c),
		"analyticsEnabled": clblog.GetInstance().Configuration.Analytics.Enabled,
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
	processedImg := climages.Resize(img, 1600)

	item := clblog.GetInstance().GetConfItem(c, false, 0)

	// Créer le dossier uploads s'il n'existe pas
	uploadsDir := fmt.Sprintf("%s/uploads/%d", clblog.GetInstance().Configuration.StaticPath, item.Id)
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
	db := clblog.GetInstance().Db
	item := clblog.GetInstance().GetConfItem(c, false, 0)
	var posts []clposts.Post
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
		"renderTime":  clmiddleware.GetRenderTime(c),
	})
}

func getOptionsCategory(item clconfig.BlogsConfig) template.HTML {
	var optionsCategory string
	for _, item := range item.Menu {
		slugifiedKey := clblog.Slugify(item.Key)
		if slugifiedKey != "" && item.Value != "" {
			optionsCategory += fmt.Sprintf("<option value=\"%s\">%s</option>", slugifiedKey, item.Value)
		}
	}
	return safeHtml(optionsCategory)
}

func newPostPageHandler(c *gin.Context) {
	session := sessions.Default(c)
	username := session.Get("username")
	item := clblog.GetInstance().GetConfItem(c, false, 0)
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
		"renderTime":      clmiddleware.GetRenderTime(c),
	})
}

func editPostPageHandler(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.HTML(http.StatusNotFound, "admin_post_form", gin.H{"title": "Article non trouvé"})
		return
	}

	db := clblog.GetInstance().Db
	var post clposts.Post
	result := db.First(&post, uint(id))
	if result.Error != nil {
		c.HTML(http.StatusNotFound, "admin_post_form", gin.H{"title": "Article non trouvé"})
		return
	}

	session := sessions.Default(c)
	username := session.Get("username")
	item := clblog.GetInstance().GetConfItem(c, false, 0)
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
		"renderTime":      clmiddleware.GetRenderTime(c),
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

	item := clblog.GetInstance().GetConfItem(c, false, 0)

	post := clposts.Post{
		BlogID:    item.Id,
		Title:     strings.TrimSpace(req.Title),
		Content:   strings.TrimSpace(req.Content),
		Excerpt:   strings.TrimSpace(req.Excerpt),
		CreatedAt: dateTimestamp(strings.TrimSpace(req.CreatedAt)),
		Author:    author,
		TagsList:  req.Tags,
		Category:  clblog.Slugify(req.Category),
		Hide:      req.Hide,
	}

	post.FillExcerpt()

	if post.Title == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Le titre ne peut pas etre vide"})
		return
	}

	db := clblog.GetInstance().Db
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

	db := clblog.GetInstance().Db
	var post clposts.Post
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
	post.Category = clblog.Slugify(req.Category)
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

	item := clblog.GetInstance().GetConfItem(c, false, 0)

	// chercher les images du post
	var post clposts.Post
	db := clblog.GetInstance().Db
	result := db.Where("blog_id = ?", item.Id).First(&post, uint(id))
	if result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Article non trouvé"})
		return
	}
	imagesFound, images := clposts.ExtractImages(post.Content, false, true)

	// Supprimer dans une transaction commentaires puis l'article
	tx := db.Begin()

	// Supprimer les commentaires
	if err := tx.Where("post_id = ?", uint(id)).Delete(&clposts.Comment{}).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur suppression commentaires"})
		return
	}

	// Supprimer l'article
	if err := tx.Delete(&clposts.Post{}, uint(id)).Error; err != nil {
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

	category := clblog.Slugify(c.DefaultQuery("category", ""))

	// Calcul de l'offset
	offset := (page - 1) * limit

	db := clblog.GetInstance().Db
	item := clblog.GetInstance().GetConfItem(c, false, 0)
	buildQuery := func() *gorm.DB {
		query := db.Model(&clposts.Post{}).Where("blog_id = ? AND NOT hide", item.Id)
		if category != "" {
			query = query.Where("category = ?", category)
		}
		return query
	}

	// Compter le nombre total de posts
	var total int64
	buildQuery().Count(&total)

	// Récupérer les posts avec leurs commentaires
	var posts []clposts.Post
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
		posts[i].Excerpt = string(clmarkdown.ConvertMarkdownToHTML(post.Excerpt))
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
	post := getPost(c, c.Param("id"))
	if post == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Article non trouvé"})
		return
	}

	c.JSON(http.StatusOK, &post)
}

func getCommentsAPI(c *gin.Context) {
	idStr := c.Param("id")
	postID, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ID invalide"})
		return
	}

	db := clblog.GetInstance().Db
	var comments []clposts.Comment
	result := db.Where("post_id = ? AND approved", uint(postID)).Order("created_at asc").Find(&comments)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur serveur"})
		return
	}

	c.JSON(http.StatusOK, comments)
}

func getPost(c *gin.Context, idStr string) *clposts.Post {
	postID, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		return nil
	}

	db := clblog.GetInstance().Db
	var post clposts.Post
	item := clblog.GetInstance().GetConfItem(c, false, 0)
	result := db.Where("blog_id = ? AND NOT hide", item.Id).First(&post, uint(postID))
	if result.Error != nil {
		return nil
	}
	return &post
}

func addCommentAPI(c *gin.Context) {
	post := getPost(c, c.Param("id"))
	if post == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Article non trouvé"})
		return
	}

	var req CreateCommentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	lb := clblog.GetInstance()

	// controle du captcha
	err := lb.Captcha.VerifyCaptcha(req.CaptchaID, req.CaptchaAnswer)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	comment := clposts.Comment{
		PostID:  post.ID,
		Author:  strings.TrimSpace(req.Author),
		Content: strings.TrimSpace(req.Content),
	}

	result := lb.Db.Create(&comment)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur création commentaire"})
		return
	}

	c.JSON(http.StatusCreated, comment)
}

func searchPostsAPI(c *gin.Context) {
	query := strings.ToLower(strings.TrimSpace(c.Query("q")))
	if query == "" {
		c.JSON(http.StatusOK, []clposts.Post{})
		return
	}

	db := clblog.GetInstance().Db
	var posts []clposts.Post

	item := clblog.GetInstance().GetConfItem(c, false, 0)

	searchTerm := "%" + query + "%"
	result := db.Where(
		"blog_id = ? AND NOT hide AND (LOWER(title) LIKE ? OR LOWER(tags) LIKE ?)",
		item.Id, searchTerm, searchTerm,
	).Order("created_at desc").Find(&posts)

	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur recherche"})
		return
	}

	for i := range posts {
		posts[i].Content = "x"
		posts[i].ContentHTML = template.HTML("x")
		posts[i].Excerpt = "x"
	}

	c.JSON(http.StatusOK, posts)
}
