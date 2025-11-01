package clmiddleware

import (
	"crypto/rand"
	"fmt"
	"littleblog/internal/clconfig"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/gzip"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/ulule/limiter/v3"
	ginlimiter "github.com/ulule/limiter/v3/drivers/middleware/gin"
	"github.com/ulule/limiter/v3/drivers/store/memory"
)

func InitMiddleware(r *gin.Engine, Blogs map[string]clconfig.BlogsConfig, production bool) {
	// logger
	r.Use(Logger())
	r.Use(Recovery())

	// get blog Id
	r.Use(BlogId(Blogs))

	// use Compression, with gzip
	r.Use(gzip.Gzip(gzip.BestSpeed))

	// Configuration des sessions
	r.Use(NewSession(production))

	// Calculate time elapsed
	r.Use(RenderTime())

	// CORS
	r.Use(CORS)
}

func CORS(c *gin.Context) {
	c.Header("Access-Control-Allow-Origin", "*")
	c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")

	if c.Request.Method == "OPTIONS" {
		c.AbortWithStatus(204)
		return
	}

	c.Next()
}

func NewLimiter() gin.HandlerFunc {
	rate := limiter.Rate{
		Period: 1 * time.Minute,
		Limit:  5,
	}
	mstore := memory.NewStore()
	instance := limiter.New(mstore, rate)
	return ginlimiter.NewMiddleware(instance)
}

func NewSession(production bool) gin.HandlerFunc {
	store := cookie.NewStore(generateSecretKey())
	store.Options(sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7,
		HttpOnly: true,
		Secure:   production,
	})
	return sessions.Sessions("littleblog", store)
}

func Logger() gin.HandlerFunc {
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

func BlogId(Blogs map[string]clconfig.BlogsConfig) gin.HandlerFunc {
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

func Recovery() gin.HandlerFunc {
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

func RenderTime() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Stocker le temps de début pour utilisation dans les handlers
		c.Set("requestStart", time.Now())
		c.Next()
	}
}

func GetRenderTime(c *gin.Context) any {
	start, _ := c.Get("requestStart")
	duration := time.Since(start.(time.Time))
	return fmt.Sprintf("Page générée en %s", formatDuration(duration))
}

// Générer une clé secrète aléatoire
func generateSecretKey() []byte {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		log.Fatal().Err(err).Str("msg", "Erreur génération clé secrète")
	}
	return key
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
