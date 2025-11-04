package clanalytics

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/robfig/cron/v3"
	"gorm.io/gorm"
)

type AnalyticsService struct {
	db    *gorm.DB
	redis *redis.Client
	cron  *cron.Cron
}

func NewAnalyticsService(db *gorm.DB, redisClient *redis.Client) *AnalyticsService {
	return &AnalyticsService{
		db:    db,
		redis: redisClient,
		cron:  setupCleanupCron(db),
	}
}

// Stats30Days représente les statistiques sur 30 jours
type Stats30Days struct {
	TotalPageViews         int64          `json:"total_page_views"`
	UniqueVisitors         int64          `json:"unique_visitors"`
	AvgPageViewsPerVisitor float64        `json:"avg_page_views_per_visitor"`
	TopPages               []PageStat     `json:"top_pages"`
	TopReferrers           []ReferrerStat `json:"top_referrers"`
	TopLanguages           []LanguageStat `json:"top_languages"`
	DailyStats             []DailyStat    `json:"daily_stats"`
}

type PageStat struct {
	Path  string `json:"path"`
	Views int64  `json:"views"`
}

type ReferrerStat struct {
	Referrer string `json:"referrer"`
	Count    int64  `json:"count"`
}

type LanguageStat struct {
	Language string `json:"language"`
	Count    int64  `json:"count"`
}

type DailyStat struct {
	Date           string `json:"date"`
	PageViews      int64  `json:"page_views"`
	UniqueVisitors int64  `json:"unique_visitors"`
}

// GetStats30Days récupère toutes les statistiques des 30 derniers jours
func (as *AnalyticsService) GetStats30Days(blogid uint) (*Stats30Days, error) {
	thirtyDaysAgo := time.Now().AddDate(0, 0, -30)

	stats := &Stats30Days{}

	// 1. Total des pages vues sur 30 jours
	var totalPageViews int64
	err := as.db.Model(&PageView{}).
		Where("created_at >= ? AND blog_id = ?", thirtyDaysAgo, blogid).
		Count(&totalPageViews).Error
	if err != nil {
		return nil, fmt.Errorf("error counting page views: %w", err)
	}
	stats.TotalPageViews = totalPageViews

	// 2. Nombre de visiteurs uniques
	var uniqueVisitors int64
	err = as.db.Model(&PageView{}).
		Where("created_at >= ? AND blog_id = ?", thirtyDaysAgo, blogid).
		Distinct("visitor_id").
		Count(&uniqueVisitors).Error
	if err != nil {
		return nil, fmt.Errorf("error counting unique visitors: %w", err)
	}
	stats.UniqueVisitors = uniqueVisitors

	// 3. Moyenne de pages vues par visiteur
	if uniqueVisitors > 0 {
		stats.AvgPageViewsPerVisitor = float64(totalPageViews) / float64(uniqueVisitors)
	}

	// 4. Top des pages (10 pages les plus vues)
	var topPages []PageStat
	err = as.db.Model(&PageView{}).
		Select("page_path as path, COUNT(*) as views").
		Where("created_at >= ? AND blog_id = ?", thirtyDaysAgo, blogid).
		Group("page_path").
		Order("views DESC").
		Limit(10).
		Scan(&topPages).Error
	if err != nil {
		return nil, fmt.Errorf("error getting top pages: %w", err)
	}
	stats.TopPages = topPages

	// 5. Top des referrers (10 referrers les plus fréquents)
	var topReferrers []ReferrerStat
	err = as.db.Model(&PageView{}).
		Select("referrer, COUNT(*) as count").
		Where("created_at >= ?  AND blog_id = ? AND referrer != ''", thirtyDaysAgo, blogid).
		Group("referrer").
		Order("count DESC").
		Limit(10).
		Scan(&topReferrers).Error
	if err != nil {
		return nil, fmt.Errorf("error getting top referrers: %w", err)
	}
	stats.TopReferrers = topReferrers

	// 6. Top des langues
	var topLanguages []LanguageStat
	err = as.db.Model(&PageView{}).
		Select("language, COUNT(*) as count").
		Where("created_at >= ? AND blog_id = ?", thirtyDaysAgo, blogid).
		Group("language").
		Order("count DESC").
		Limit(10).
		Scan(&topLanguages).Error
	if err != nil {
		return nil, fmt.Errorf("error getting top languages: %w", err)
	}
	stats.TopLanguages = topLanguages

	// 7. Statistiques journalières (30 derniers jours)
	dailyStats, err := as.getDailyStats(thirtyDaysAgo, blogid)
	if err != nil {
		return nil, fmt.Errorf("error getting daily stats: %w", err)
	}
	stats.DailyStats = dailyStats

	return stats, nil
}

// getDailyStats récupère les statistiques jour par jour
func (as *AnalyticsService) getDailyStats(since time.Time, blogid uint) ([]DailyStat, error) {
	// Récupérer les pages vues par jour
	type DailyPageViews struct {
		Date  string `json:"date"`
		Count int64  `json:"count"`
	}

	var dailyPageViews []DailyPageViews
	err := as.db.Model(&PageView{}).
		Select("DATE(created_at) as date, COUNT(*) as count").
		Where("created_at >= ? AND blog_id = ?", since, blogid).
		Group("DATE(created_at)").
		Order("date ASC").
		Scan(&dailyPageViews).Error
	if err != nil {
		return nil, err
	}

	// Créer une map pour faciliter la fusion des données
	statsMap := make(map[string]*DailyStat)
	for _, dpv := range dailyPageViews {
		statsMap[dpv.Date] = &DailyStat{
			Date:      dpv.Date,
			PageViews: dpv.Count,
		}
	}

	// Récupérer les visiteurs uniques par jour
	type DailyVisitors struct {
		Date  string `json:"date"`
		Count int64  `json:"count"`
	}

	var dailyVisitors []DailyVisitors
	err = as.db.Model(&PageView{}).
		Select("DATE(created_at) as date, COUNT(DISTINCT visitor_id) as count").
		Where("created_at >= ? AND blog_id = ?", since, blogid).
		Group("DATE(created_at)").
		Order("date ASC").
		Scan(&dailyVisitors).Error
	if err != nil {
		return nil, err
	}

	// Fusionner les visiteurs uniques
	for _, dv := range dailyVisitors {
		if stat, exists := statsMap[dv.Date]; exists {
			stat.UniqueVisitors = dv.Count
		}
	}

	// Convertir la map en slice
	var result []DailyStat
	for _, stat := range statsMap {
		result = append(result, *stat)
	}

	// Trier par date (devrait déjà être trié mais on s'assure)
	return result, nil
}

// GetRealtimeStats récupère les stats en temps réel depuis Redis (optionnel)
func (as *AnalyticsService) GetRealtimeStats(blogid uint) (map[string]interface{}, error) {
	ctx := context.Background()
	today := time.Now().Format("2006-01-02")

	// Compteur de pages vues aujourd'hui
	cacheKey := fmt.Sprintf("analytics:daily:%d:%s", blogid, today)
	pageViews, err := as.redis.HGet(ctx, cacheKey, "page_views").Int64()
	if err != nil && err != redis.Nil {
		return nil, err
	}

	// Visiteurs uniques aujourd'hui
	visitorKey := fmt.Sprintf("analytics:visitors:%d:%s", blogid, today)
	uniqueVisitors, err := as.redis.SCard(ctx, visitorKey).Result()
	if err != nil && err != redis.Nil {
		return nil, err
	}

	return map[string]interface{}{
		"today_page_views":      pageViews,
		"today_unique_visitors": uniqueVisitors,
	}, nil
}

func cleanupOldPageViews(db *gorm.DB) error {
	thirtyDaysAgo := time.Now().AddDate(0, 0, -30)

	result := db.Where("created_at < ?", thirtyDaysAgo).Delete(&PageView{})
	if result.Error != nil {
		return result.Error
	}

	log.Printf("Deleted %d old page views", result.RowsAffected)

	result = db.Where("last_seen < ?", thirtyDaysAgo).Delete(&Visitor{})
	if result.Error != nil {
		return result.Error
	}

	log.Printf("Deleted %d old visitor views", result.RowsAffected)

	return nil
}

func setupCleanupCron(db *gorm.DB) *cron.Cron {
	c := cron.New()

	// Exécuter tous les jours à 2h du matin
	c.AddFunc("0 2 * * *", func() {
		if err := cleanupOldPageViews(db); err != nil {
			log.Printf("Cleanup failed: %v", err)
		} else {
			log.Println("Cleanup completed successfully")
		}
	})

	c.Start()
	return c
}
