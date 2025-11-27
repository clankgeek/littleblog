package clmiddleware

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"littleblog/internal/models/clanalytics"
	"littleblog/internal/models/clblog"
	"littleblog/internal/models/gormzerologger"
	"net/netip"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oschwald/geoip2-golang/v2"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
	"gorm.io/driver/mysql"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type AnalyticsMiddleware struct {
	Db    *gorm.DB
	Redis *redis.Client
	GeoDB *geoip2.Reader
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

	var geodb *geoip2.Reader
	if config.Analytics.GeoIpPath != "" {
		geodb, err = geoip2.Open(config.Analytics.GeoIpPath)
		if err != nil {
			log.Fatal().Err(err)
		}
	}

	return &AnalyticsMiddleware{
		Db: db,
		Redis: redis.NewClient(&redis.Options{
			Addr: config.Analytics.Redis.Addr,
			DB:   config.Analytics.Redis.Db,
		}),
		GeoDB: geodb,
	}
}

func (am *AnalyticsMiddleware) Close() {
	if am.GeoDB != nil {
		err := am.GeoDB.Close()
		if err != nil {
			log.Error().Err(err).Msg("Error closing GeoIP database")
		}
	}
}

func (am *AnalyticsMiddleware) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Ne pas tracker les assets statiques et les endpoints API analytics
		if strings.HasPrefix(c.Request.URL.Path, "/static/") ||
			strings.HasPrefix(c.Request.URL.Path, "/admin/") ||
			strings.HasPrefix(c.Request.URL.Path, "/files/") ||
			strings.HasPrefix(c.Request.URL.Path, "/robot.txt") ||
			strings.HasPrefix(c.Request.URL.Path, "/api/") {
			c.Next()
			return
		}

		referrer := c.Request.Referer()
		userAgent := c.Request.UserAgent()
		ipAddress := am.getClientIP(c)
		country := am.getCountry(c, ipAddress)

		var visitorID string

		// Essayer de récupérer le cookie
		visitorID, err := c.Cookie("_visitor_id")

		if err != nil || visitorID == "" {
			// Pas de cookie disponible : générer un nouvel ID
			hash := sha256.Sum256([]byte(fmt.Sprintf("%s%s%s", ipAddress, country, userAgent)))
			visitorID = hex.EncodeToString(hash[:])[:32]

			// Essayer de définir le cookie (peut échouer si désactivés)
			c.SetCookie(
				"_visitor_id",
				visitorID,
				365*24*60*60, // 1an
				"/",
				"",
				clblog.GetInstance().Configuration.Production, // secure (true si HTTPS)
				true, // httpOnly
			)
		}

		item := clblog.GetInstance().GetConfItem(c, false, 0)

		// Extraire les informations
		pagePath := c.Request.URL.Path
		if c.Request.URL.RawQuery != "" {
			pagePath += "?" + c.Request.URL.RawQuery
		}

		// Enregistrer de manière asynchrone pour ne pas bloquer la requête
		go am.recordPageView(item.Id, visitorID, pagePath, referrer, userAgent, country, ipAddress)

		c.Next()
	}
}

// getClientIP récupère l'IP réelle du client
func (am *AnalyticsMiddleware) getClientIP(c *gin.Context) string {
	// 1. Cloudflare
	if ip := c.GetHeader("CF-Connecting-IP"); ip != "" {
		return ip
	}

	// 2. Cloudflare Enterprise / Akamai
	if ip := c.GetHeader("True-Client-IP"); ip != "" {
		return ip
	}

	// 3. X-Real-IP (Nginx, load balancers)
	if ip := c.GetHeader("X-Real-IP"); ip != "" {
		return ip
	}

	// 4. X-Forwarded-For
	if xff := c.GetHeader("X-Forwarded-For"); xff != "" {
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	// 5. Fallback Gin (utilise RemoteAddr intelligemment)
	return c.ClientIP()
}

func (am *AnalyticsMiddleware) extractCountryFromLanguage(c *gin.Context) string {
	acceptLang := c.GetHeader("Accept-Language")
	if acceptLang == "" {
		return ""
	}

	// Parcourir toutes les langues pour trouver un code pays
	parts := strings.Split(acceptLang, ",")
	for _, part := range parts {
		lang := strings.Split(part, ";")[0]
		lang = strings.TrimSpace(lang)

		// Si format "xx-YY", extraire YY
		if idx := strings.Index(lang, "-"); idx != -1 {
			return strings.ToUpper(lang[idx+1:])
		}
	}

	return ""
}

func (am *AnalyticsMiddleware) getCountry(c *gin.Context, ipAddress string) string {
	// 1. Essayer d'abord avec GeoIP (plus fiable)
	if country := am.getCountryFromIP(c, ipAddress); country != "" {
		return country
	}

	// 2. Fallback sur Accept-Language
	if country := am.extractCountryFromLanguage(c); country != "" {
		return country
	}

	return "Unknown"
}

func (am *AnalyticsMiddleware) getCountryFromIP(ctx *gin.Context, ip string) string {
	if am.GeoDB == nil || ip == "" {
		return ""
	}

	parsedIP, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}

	ipKey := fmt.Sprintf("analytics:ip:%s", parsedIP)
	country := am.Redis.Get(ctx, ipKey).Val()
	if country != "" {
		return country
	}

	record, err := am.GeoDB.Country(parsedIP)
	if err != nil {
		return ""
	}

	am.Redis.Set(ctx, ipKey, record.Country.ISOCode, 1*time.Hour)

	return record.Country.ISOCode
}

// recordPageView enregistre la vue de page dans la DB et met à jour Redis
func (am *AnalyticsMiddleware) recordPageView(blogid uint, visitorID, pagePath, referrer, userAgent, country, ipAddress string) {
	now := time.Now()

	// 1. Enregistrer dans SQLite via GORM
	pageView := clanalytics.PageView{
		BlogID:    blogid,
		VisitorID: visitorID,
		PagePath:  pagePath,
		Referrer:  referrer,
		UserAgent: userAgent,
		Country:   country,
		IPAddress: ipAddress,
		CreatedAt: now,
	}

	if err := am.Db.Create(&pageView).Error; err != nil {
		// Log l'erreur mais ne pas faire échouer la requête
		log.Error().Err(err).Str("visitor", visitorID).Msg("Error recording page view")
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
}
