package handlers_analytics

import (
	"littleblog/internal/models/clanalytics"
	"littleblog/internal/models/clblog"
	"net/http"

	"github.com/gin-gonic/gin"
)

type AnalyticsHandler struct {
	service *clanalytics.AnalyticsService
}

func NewAnalyticsHandler(service *clanalytics.AnalyticsService) *AnalyticsHandler {
	return &AnalyticsHandler{
		service: service,
	}
}

// GetStats30Days retourne les statistiques des 30 derniers jours
func (ah *AnalyticsHandler) GetStats30Days(c *gin.Context) {
	item := clblog.GetInstance().GetConfItem(c, false, 0)
	stats, err := ah.service.GetStats30Days(item.Id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve analytics",
		})
		return
	}

	c.JSON(http.StatusOK, stats)
}

// GetRealtimeStats retourne les statistiques en temps réel
func (ah *AnalyticsHandler) GetRealtimeStats(c *gin.Context) {
	item := clblog.GetInstance().GetConfItem(c, false, 0)
	stats, err := ah.service.GetRealtimeStats(item.Id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve realtime stats",
		})
		return
	}

	c.JSON(http.StatusOK, stats)
}
