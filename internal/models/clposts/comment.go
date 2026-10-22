package clposts

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type Comment struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	PostID    uint      `json:"post_id" gorm:"not null;index"`
	ParentID  *uint     `json:"parent_id" gorm:"index"`
	Author    string    `json:"author" gorm:"not null"`
	Email     string    `json:"email" gorm:"type:varchar(255)"`
	Content   string    `json:"content" gorm:"type:text;not null"`
	Approved  bool      `json:"approved" gorm:"default:false;index"`
	CreatedAt time.Time `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt time.Time `json:"updated_at" gorm:"autoUpdateTime"`
	Post      Post      `json:"post" gorm:"foreignKey:PostID"`
}

type ModerationHandler struct {
	DB     *gorm.DB
	blogID func(c *gin.Context) uint
}

// blogID retourne l'id du blog de la requête : la modération ne voit que les
// commentaires des articles de ce blog.
func NewModerationHandler(db *gorm.DB, blogID func(c *gin.Context) uint) *ModerationHandler {
	return &ModerationHandler{
		DB:     db,
		blogID: blogID,
	}
}

// scope restreint une requête sur Comment aux articles du blog courant
func (h *ModerationHandler) scope(db *gorm.DB, c *gin.Context) *gorm.DB {
	return db.Where("post_id IN (?)", h.DB.Model(&Post{}).Select("id").Where("blog_id = ?", h.blogID(c)))
}

// API : Liste des commentaires à modérer
func (h *ModerationHandler) GetPendingComments(c *gin.Context) {
	var comments []Comment

	// Paramètres de pagination
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	if limit < 1 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	offset := (page - 1) * limit

	// Filtre : all, pending, approved
	status := c.DefaultQuery("status", "pending")

	query := h.scope(h.DB, c).Preload("Post")

	switch status {
	case "pending":
		query = query.Where("approved = ?", false)
	case "approved":
		query = query.Where("approved = ?", true)
		// "all" ne filtre pas
	}

	// Comptage total
	var total int64
	query.Model(&Comment{}).Count(&total)

	// Récupération des commentaires
	if err := query.Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&comments).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur serveur"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"comments": comments,
		"total":    total,
		"page":     page,
		"limit":    limit,
	})
}

// API : Approuver un commentaire
func (h *ModerationHandler) ApproveComment(c *gin.Context) {
	id := c.Param("id")

	var comment Comment
	if err := h.scope(h.DB, c).First(&comment, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Commentaire non trouvé"})
		return
	}

	comment.Approved = true
	if err := h.DB.Save(&comment).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur serveur"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Commentaire approuvé", "comment": comment})
}

// API : Rejeter/Supprimer un commentaire (et ses réponses)
func (h *ModerationHandler) DeleteComment(c *gin.Context) {
	id := c.Param("id")

	err := h.DB.Transaction(func(tx *gorm.DB) error {
		if err := h.scope(tx, c).Where("parent_id = ?", id).Delete(&Comment{}).Error; err != nil {
			return err
		}
		return h.scope(tx, c).Delete(&Comment{}, id).Error
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur serveur"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Commentaire supprimé"})
}

// API : Approuver plusieurs commentaires
func (h *ModerationHandler) BulkApprove(c *gin.Context) {
	var req struct {
		IDs []uint `json:"ids" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Données invalides"})
		return
	}

	if err := h.scope(h.DB.Model(&Comment{}), c).Where("id IN ?", req.IDs).Update("approved", true).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur serveur"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Commentaires approuvés", "count": len(req.IDs)})
}

// API : Supprimer plusieurs commentaires
func (h *ModerationHandler) BulkDelete(c *gin.Context) {
	var req struct {
		IDs []uint `json:"ids" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Données invalides"})
		return
	}

	err := h.DB.Transaction(func(tx *gorm.DB) error {
		if err := h.scope(tx, c).Where("parent_id IN ?", req.IDs).Delete(&Comment{}).Error; err != nil {
			return err
		}
		return h.scope(tx, c).Delete(&Comment{}, req.IDs).Error
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur serveur"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Commentaires supprimés", "count": len(req.IDs)})
}
