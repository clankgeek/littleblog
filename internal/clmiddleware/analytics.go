package clmiddleware

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"littleblog/internal/models/clanalytics"
	"littleblog/internal/models/clblog"
	"littleblog/internal/models/gormzerologger"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
	"gorm.io/driver/mysql"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type AnalyticsMiddleware struct {
	Db    *gorm.DB
	Redis *redis.Client
}

func NewAnalyticsMiddleware(lb *clblog.Littleblog) *AnalyticsMiddleware {
	config := lb.Configuration

	level := "warn"
	if config.Logger.Level == "debug" || !config.Production {
		level = "trace"
	}

	var err error
	var db *gorm.DB
	switch config.Analytics.Db {
	case "sqlite":
		db, err = gorm.Open(sqlite.Open(config.Analytics.Path), &gorm.Config{
			Logger: gormzerologger.New(level),
		})
	case "mysql":
		db, err = gorm.Open(mysql.Open(config.Analytics.Dsn), &gorm.Config{
			Logger: gormzerologger.New(level),
		})
	default:
		db = lb.Db
	}

	if err != nil {
		log.Fatal().Err(err)
	}

	err = db.AutoMigrate(&clanalytics.PageView{}, &clanalytics.Visitor{})
	if err != nil {
		log.Fatal().Err(err)
	}

	return &AnalyticsMiddleware{
		Db: db,
		Redis: redis.NewClient(&redis.Options{
			Addr: config.Analytics.Redis.Addr,
			DB:   config.Analytics.Redis.Db,
		}),
	}
}

func (am *AnalyticsMiddleware) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Ne pas tracker les assets statiques et les endpoints API analytics
		if strings.HasPrefix(c.Request.URL.Path, "/static/") ||
			strings.HasPrefix(c.Request.URL.Path, "/admin/") ||
			strings.HasPrefix(c.Request.URL.Path, "/files/") ||
			strings.HasPrefix(c.Request.URL.Path, "/api/") {
			c.Next()
			return
		}

		var visitorID string

		// Essayer de récupérer le cookie
		visitorID, err := c.Cookie("_visitor_id")

		if err != nil || visitorID == "" {
			// Pas de cookie disponible : générer un nouvel ID aléatoire
			randomBytes := make([]byte, 16)
			rand.Read(randomBytes)
			visitorID = hex.EncodeToString(randomBytes)

			// Essayer de définir le cookie (peut échouer si désactivés)
			c.SetCookie(
				"_visitor_id",
				visitorID,
				365*24*60*60*2, // 2 ans
				"/",
				"",
				clblog.GetInstance().Configuration.Production, // secure (true si HTTPS)
				true, // httpOnly
			)
		}

		// Fallback : si les cookies sont désactivés, utiliser un hash
		// basé sur IP + User-Agent + Language pour avoir une certaine cohérence
		referrer := c.Request.Referer()
		userAgent := c.Request.UserAgent()
		language := am.extractLanguage(c)
		ipAddress := am.getClientIP(c)

		// Si le visitorID semble être celui qu'on vient de créer mais que
		// les cookies sont désactivés, on utilise le hash pour la cohérence
		// entre les requêtes de la même session
		if err != nil {
			// Générer un ID basé sur IP + lang + User-Agent comme fallback
			hash := sha256.Sum256([]byte(fmt.Sprintf("%s%s%s", ipAddress, language, userAgent)))
			visitorID = hex.EncodeToString(hash[:])[:32]
		}

		item := clblog.GetInstance().GetConfItem(c, false, 0)

		// Extraire les informations
		pagePath := c.Request.URL.Path
		if c.Request.URL.RawQuery != "" {
			pagePath += "?" + c.Request.URL.RawQuery
		}

		// Enregistrer de manière asynchrone pour ne pas bloquer la requête
		go am.recordPageView(item.Id, visitorID, pagePath, referrer, userAgent, language, ipAddress)

		c.Next()
	}
}

// getClientIP récupère l'IP réelle du client
func (am *AnalyticsMiddleware) getClientIP(c *gin.Context) string {
	// Vérifier les headers de proxy
	ip := c.GetHeader("X-Real-IP")
	if ip == "" {
		ip = c.GetHeader("X-Forwarded-For")
		if ip != "" {
			// Prendre la première IP si plusieurs
			ips := strings.Split(ip, ",")
			ip = strings.TrimSpace(ips[0])
		}
	}
	if ip == "" {
		ip = c.ClientIP()
	}
	return ip
}

// extractLanguage extrait la langue préférée du visiteur
func (am *AnalyticsMiddleware) extractLanguage(c *gin.Context) string {
	acceptLang := c.GetHeader("Accept-Language")
	if acceptLang == "" {
		return "unknown"
	}

	// Extraire la première langue (ex: "fr-FR,fr;q=0.9,en-US;q=0.8" -> "fr")
	parts := strings.Split(acceptLang, ",")
	if len(parts) > 0 {
		lang := strings.Split(parts[0], ";")[0]
		lang = strings.Split(lang, "-")[0]
		return strings.ToLower(strings.TrimSpace(lang))
	}

	return "unknown"
}

// recordPageView enregistre la vue de page dans la DB et met à jour Redis
func (am *AnalyticsMiddleware) recordPageView(blogid uint, visitorID, pagePath, referrer, userAgent, language, ipAddress string) {
	ctx := context.Background()
	now := time.Now()

	// 1. Enregistrer dans SQLite via GORM
	pageView := clanalytics.PageView{
		BlogID:    blogid,
		VisitorID: visitorID,
		PagePath:  pagePath,
		Referrer:  referrer,
		UserAgent: userAgent,
		Language:  language,
		IPAddress: ipAddress,
		CreatedAt: now,
	}

	if err := am.Db.Create(&pageView).Error; err != nil {
		// Log l'erreur mais ne pas faire échouer la requête
		fmt.Printf("Error recording page view: %v\n", err)
		return
	}

	// 2. Mettre à jour ou créer le visiteur
	var visitor clanalytics.Visitor
	result := am.Db.Where("visitor_id = ?", visitorID).First(&visitor)

	if result.Error == gorm.ErrRecordNotFound {
		// Nouveau visiteur
		visitor = clanalytics.Visitor{
			VisitorID:      visitorID,
			BlogID:         blogid,
			FirstSeen:      now,
			LastSeen:       now,
			PageViewsCount: 1,
		}
		am.Db.Create(&visitor)
	} else {
		// Visiteur existant, mettre à jour
		am.Db.Model(&visitor).Updates(map[string]interface{}{
			"last_seen":        now,
			"page_views_count": gorm.Expr("page_views_count + 1"),
		})
	}

	// 3. Mettre à jour les compteurs Redis pour un accès rapide
	// Utiliser un cache de 30 jours
	cacheKey := fmt.Sprintf("analytics:daily:%d:%s", blogid, now.Format("2006-01-02"))
	am.Redis.HIncrBy(ctx, cacheKey, "page_views", 1)
	am.Redis.Expire(ctx, cacheKey, 31*24*time.Hour)

	// Marquer le visiteur comme vu aujourd'hui
	visitorKey := fmt.Sprintf("analytics:visitors:%d:%s", blogid, now.Format("2006-01-02"))
	am.Redis.SAdd(ctx, visitorKey, visitorID)
	am.Redis.Expire(ctx, visitorKey, 31*24*time.Hour)
}
