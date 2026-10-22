package clposts

import (
	"littleblog/internal/models/clmarkdown"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// deux blogs (0 et 1) avec un article et un commentaire en attente chacun
func setupModeration(t *testing.T) (*gin.Engine, *gorm.DB) {
	gin.SetMode(gin.TestMode)
	clmarkdown.InitMarkdown() // requis par Post.AfterFind
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	assert.NoError(t, err)
	assert.NoError(t, db.AutoMigrate(&Post{}, &Comment{}))

	for blog := uint(0); blog <= 1; blog++ {
		post := Post{BlogID: blog, Title: "t", Content: "c", Author: "a"}
		assert.NoError(t, db.Create(&post).Error)
		assert.NoError(t, db.Create(&Comment{PostID: post.ID, Author: "x", Content: "y"}).Error)
	}

	h := NewModerationHandler(db, func(c *gin.Context) uint { return 0 })
	r := gin.New()
	r.GET("/comments", h.GetPendingComments)
	r.POST("/comments/:id/approve", h.ApproveComment)
	r.DELETE("/comments/:id", h.DeleteComment)
	r.POST("/bulk-approve", h.BulkApprove)
	r.POST("/bulk-delete", h.BulkDelete)
	return r, db
}

func do(r *gin.Engine, method, url, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	return w
}

func TestModerationScopedToBlog(t *testing.T) {
	r, db := setupModeration(t)

	var own, other Comment
	db.Joins("JOIN posts ON posts.id = comments.post_id").Where("posts.blog_id = 0").First(&own)
	db.Joins("JOIN posts ON posts.id = comments.post_id").Where("posts.blog_id = 1").First(&other)

	// liste : seulement le blog courant
	w := do(r, "GET", "/comments?status=all", "")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"total":1`)

	// approbation / suppression d'un commentaire d'un autre blog : refus ou sans effet
	assert.Equal(t, http.StatusNotFound, do(r, "POST", "/comments/"+itoa(other.ID)+"/approve", "").Code)
	do(r, "DELETE", "/comments/"+itoa(other.ID), "")
	do(r, "POST", "/bulk-approve", `{"ids":[`+itoa(other.ID)+`]}`)
	do(r, "POST", "/bulk-delete", `{"ids":[`+itoa(other.ID)+`]}`)

	var check Comment
	assert.NoError(t, db.First(&check, other.ID).Error, "le commentaire de l'autre blog doit exister")
	assert.False(t, check.Approved, "le commentaire de l'autre blog ne doit pas être approuvé")

	// le commentaire du blog courant reste modérable
	assert.Equal(t, http.StatusOK, do(r, "POST", "/comments/"+itoa(own.ID)+"/approve", "").Code)
	do(r, "DELETE", "/comments/"+itoa(own.ID), "")
	assert.Error(t, db.First(&check, own.ID).Error)
}

func itoa(n uint) string { return strconv.FormatUint(uint64(n), 10) }
