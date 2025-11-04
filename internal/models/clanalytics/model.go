package clanalytics

import "time"

// PageView représente une vue de page
type PageView struct {
	ID        uint64    `gorm:"primaryKey" json:"id"`
	BlogID    uint      `json:"blog_id" gorm:"index"`
	VisitorID string    `gorm:"index;not null" json:"visitor_id"`
	PagePath  string    `gorm:"index;not null" json:"page_path"`
	Referrer  string    `json:"referrer"`
	UserAgent string    `json:"user_agent"`
	Language  string    `gorm:"index" json:"language"`
	IPAddress string    `json:"ip_address"`
	CreatedAt time.Time `gorm:"index" json:"created_at"`
}

// Visitor représente un visiteur unique
type Visitor struct {
	ID             uint      `gorm:"primaryKey" json:"id"`
	BlogID         uint      `json:"blog_id" gorm:"index"`
	VisitorID      string    `gorm:"uniqueIndex;not null" json:"visitor_id"`
	FirstSeen      time.Time `json:"first_seen"`
	LastSeen       time.Time `json:"last_seen"`
	PageViewsCount int       `json:"page_views_count"`
}

// TableName spécifie le nom de la table pour PageView
func (PageView) TableName() string {
	return "page_views"
}

// TableName spécifie le nom de la table pour Visitor
func (Visitor) TableName() string {
	return "visitors"
}
