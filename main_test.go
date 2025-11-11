package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html/template"
	handlers_rss "littleblog/internal/handlers/rss"
	"littleblog/internal/models/clblog"
	"littleblog/internal/models/clcaptchas"
	"littleblog/internal/models/clconfig"
	"littleblog/internal/models/cllog"
	"littleblog/internal/models/clmarkdown"
	"littleblog/internal/models/clposts"
	"littleblog/internal/models/clrss"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/andskur/argon2-hashing"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// ============= Setup et Teardown =============

func HashPassword(pass string) (string, error) {
	hash, err := argon2.GenerateFromPassword([]byte(pass), argon2.DefaultParams)
	return string(hash), err
}

func setupTestDB(t *testing.T) *gorm.DB {
	testDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	require.NoError(t, err)

	err = testDB.AutoMigrate(&clposts.Post{}, &clposts.Comment{})
	require.NoError(t, err)

	return testDB
}

func setupTestDBBench(t *testing.B) *gorm.DB {
	testDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	require.NoError(t, err)

	err = testDB.AutoMigrate(&clposts.Post{}, &clposts.Comment{})
	require.NoError(t, err)

	return testDB
}

func setupTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	// Setup sessions
	store := cookie.NewStore([]byte("test-secret"))
	r.Use(sessions.Sessions("test-session", store))

	return r
}

func setupTestConfig() *clconfig.Config {
	c := &clconfig.Config{
		Database: clconfig.DatabaseConfig{
			Db:   "sqlite",
			Path: ":memory:",
		},
		User: clconfig.UserConfig{
			Login: "admin",
			Hash:  "$argon2id$v=19$m=65536,t=3,p=2$abcdefghijklmnop$0123456789abcdef0123456789abcdef",
		},
		Production: false,
		Logger:     clconfig.LoggerConfig{},
		Blogs: []clconfig.BlogsConfig{
			{
				SiteName:    "Test Blog",
				Description: "Test Description",
			},
		},
	}
	lb := clblog.GetInstance()
	lb.BlogsId = make(map[uint]string, len(c.Blogs))
	lb.Blogs = make(map[string]clconfig.BlogsConfig, len(c.Blogs))
	for _, item := range c.Blogs {
		item.ThemeCSS = clblog.GenerateThemeCSS(item.Theme)
		lb.Blogs[item.Hostname] = item
		lb.BlogsId[item.Id] = item.Hostname
	}
	cllog.InitLogger(c.Logger, false)

	return c
}

func createTestPost(db *gorm.DB) *clposts.Post {
	post := &clposts.Post{
		BlogID:   0,
		Title:    "Test Post",
		Content:  "Test Content",
		Excerpt:  "Test Excerpt",
		Author:   "Test Author",
		TagsList: []string{"test", "golang"},
		Hide:     false,
	}
	db.Create(post)
	return post
}

// ============= Tests pour les modèles =============

func TestDateTimestamp(t *testing.T) {
	loc, _ := time.LoadLocation("Europe/Paris")
	assert.WithinDuration(t, time.Time(time.Date(2025, time.October, 20, 14, 0, 1, 0, loc)), dateTimestamp("20 10 2025"), time.Minute)
	assert.WithinDuration(t, time.Now(), dateTimestamp(""), time.Minute)
}

func TestExtractImages(t *testing.T) {
	s := "yoyo ![monimage.jpg](/static/uploads/1759683627_d4hhlyrc.jpg) oyoyo ![monimage2.jpg](/static/uploads/1759683627_d4hhlxxx.jpg) x"
	found, images := clposts.ExtractImages(s, true, false)
	assert.True(t, found)
	assert.True(t, len(images) == 1)
	assert.Equal(t, "![monimage.jpg](/static/uploads/1759683627_d4hhlyrc.jpg)", images[0])

	found, images = clposts.ExtractImages(s, false, true)
	assert.True(t, found)
	assert.Equal(t, 2, len(images))
	assert.Equal(t, "/static/uploads/1759683627_d4hhlyrc.jpg", images[0])
	assert.Equal(t, "/static/uploads/1759683627_d4hhlxxx.jpg", images[1])

	found, _ = clposts.ExtractImages("xxx", true, false)
	assert.False(t, found)
}

func TestGenerateMenu(t *testing.T) {
	menu := []clconfig.MenuItem{
		{
			Key:   "aaa",
			Value: "AAA",
			Img:   "/static/test.png",
		},
	}
	assert.Equal(t, template.HTML("<a href=\"/aaa\" class=\"nav-link\"><img src=\"/static/test.png\" class=\"icon\"> AAA</a>&nbsp;"), GenerateMenu(menu, ""))
	assert.Equal(t, template.HTML("<a href=\"/aaa\" class=\"nav-link active\"><img src=\"/static/test.png\" class=\"icon\"> AAA</a>&nbsp;"), GenerateMenu(menu, "aaa"))
	menu = []clconfig.MenuItem{
		{
			Key:   "aaa",
			Value: "AAA",
			Link:  "http://test.com",
		},
	}
	assert.Equal(t, template.HTML("<a href=\"http://test.com\" class=\"nav-link\" target=\"_blank\">AAA</a>&nbsp;"), GenerateMenu(menu, "aaa"))
}

func TestPost_BeforeSave(t *testing.T) {
	testDB := setupTestDB(t)

	post := &clposts.Post{
		BlogID:   0,
		Title:    "Test Post",
		Content:  "Test Content",
		TagsList: []string{"go", "test", "blog"},
	}

	err := testDB.Create(post).Error
	assert.NoError(t, err)
	assert.Equal(t, "go,test,blog", post.Tags)
}

func TestPost_AfterFind(t *testing.T) {
	clmarkdown.InitMarkdown()
	testDB := setupTestDB(t)

	post := &clposts.Post{
		BlogID:  0,
		Title:   "Test Post",
		Content: "**Bold Text**",
		Tags:    "tag1,tag2,tag3",
	}
	testDB.Create(post)

	var foundPost clposts.Post
	testDB.First(&foundPost, post.ID)

	assert.Equal(t, []string{"tag1", "tag2", "tag3"}, foundPost.TagsList)
	assert.Contains(t, string(foundPost.ContentHTML), "<strong>Bold Text</strong>")
}

// ============= Tests pour la configuration =============

func TestCreateExampleConfig(t *testing.T) {
	tempFile := "test_config.yaml"
	defer os.Remove(tempFile)

	_, err := clconfig.CreateExampleConfig(tempFile)
	assert.NoError(t, err)

	// Vérifier que le fichier existe
	_, err = os.Stat(tempFile)
	assert.NoError(t, err)

	// Vérifier le contenu
	data, err := os.ReadFile(tempFile)
	assert.NoError(t, err)

	var config clconfig.Config
	err = yaml.Unmarshal(data, &config)
	assert.NoError(t, err)
	assert.Equal(t, "Mon Blog Tech", config.Blogs[0].SiteName)
	assert.Equal(t, "admin", config.User.Login)
}

func TestLoadConfig(t *testing.T) {
	// Créer un fichier de config temporaire
	tempFile := "test_load_config.yaml"
	config := &clconfig.Config{
		Database: clconfig.DatabaseConfig{
			Db:   "sqlite",
			Path: "test.db",
		},
		User: clconfig.UserConfig{
			Login: "testadmin",
		},
		Blogs: []clconfig.BlogsConfig{
			{
				SiteName:    "Test Site",
				Description: "Test Desc",
			},
		},
	}

	data, err := yaml.Marshal(config)
	require.NoError(t, err)
	err = os.WriteFile(tempFile, data, 0644)
	require.NoError(t, err)
	defer os.Remove(tempFile)

	// Tester le chargement
	loaded, err := clconfig.LoadConfig(tempFile)
	assert.NoError(t, err)
	assert.Equal(t, config.Blogs[0].SiteName, loaded.Blogs[0].SiteName)
	assert.Equal(t, config.User.Login, loaded.User.Login)

	// Tester avec un fichier inexistant
	_, err = clconfig.LoadConfig("nonexistent.yaml")
	assert.Error(t, err)
}

// ============= Tests pour les handlers d'API =============

func TestGetPostsAPI(t *testing.T) {
	testDB := setupTestDB(t)
	clblog.GetInstance().Db = testDB
	r := setupTestRouter()

	// Créer des posts de test
	testDB.Create(&clposts.Post{BlogID: 0, Title: "Post 1", Content: "Content 1"})
	testDB.Create(&clposts.Post{BlogID: 0, Title: "Post 2", Content: "Content 2"})

	r.GET("/api/posts", getPostsAPI)

	req := httptest.NewRequest("GET", "/api/posts?page=0&limit=5", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]any
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Len(t, response["posts"], 2)
}

func TestGetPostAPI(t *testing.T) {
	testDB := setupTestDB(t)
	clblog.GetInstance().Db = testDB
	r := setupTestRouter()

	post := createTestPost(testDB)

	r.GET("/api/posts/:id", getPostAPI)

	tests := []struct {
		name       string
		postID     string
		wantStatus int
	}{
		{"Valid ID", fmt.Sprintf("%d", post.ID), http.StatusOK},
		{"Invalid ID", "invalid", http.StatusNotFound},
		{"Non-existent ID", "9999", http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/posts/"+tt.postID, nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			assert.Equal(t, tt.wantStatus, w.Code)
		})
	}
}

func TestAddCommentAPI(t *testing.T) {
	testDB := setupTestDB(t)
	clblog.GetInstance().Db = testDB
	r := setupTestRouter()

	post := createTestPost(testDB)

	r.POST("/api/posts/:id/comments", addCommentAPI)

	clblog.GetInstance().Captcha = clcaptchas.New("", 0)
	data, err := clblog.GetInstance().Captcha.GenerateCaptcha(false)
	assert.Equal(t, nil, err)

	comment := CreateCommentRequest{
		Author:        "Test User",
		Content:       "Great post!",
		CaptchaID:     data["captcha_id"].(string),
		CaptchaAnswer: data["answer"].(string),
	}

	body, _ := json.Marshal(comment)
	req := httptest.NewRequest("POST", fmt.Sprintf("/api/posts/%d/comments", post.ID), bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var createdComment clposts.Comment
	err = json.Unmarshal(w.Body.Bytes(), &createdComment)
	assert.NoError(t, err)
	assert.Equal(t, comment.Author, createdComment.Author)
	assert.Equal(t, comment.Content, createdComment.Content)
	assert.Equal(t, post.ID, createdComment.PostID)
}

func TestSearchPostsAPI(t *testing.T) {
	testDB := setupTestDB(t)
	clblog.GetInstance().Db = testDB
	r := setupTestRouter()

	// Créer des posts avec différents contenus
	testDB.Create(&clposts.Post{
		BlogID:  0,
		Title:   "Go Programming",
		Content: "Learn Go programming language",
		Excerpt: "Introduction to Go",
		Tags:    "golang,programming",
	})
	testDB.Create(&clposts.Post{
		BlogID:  0,
		Title:   "Python Tutorial",
		Content: "Learn Python basics",
		Excerpt: "Python for beginners",
		Tags:    "python,tutorial",
	})
	testDB.Create(&clposts.Post{
		BlogID:  0,
		Title:   "JavaScript Guide",
		Content: "Modern JavaScript features",
		Excerpt: "ES6 and beyond",
		Tags:    "javascript,web",
	})

	r.GET("/api/search", searchPostsAPI)

	tests := []struct {
		name        string
		query       string
		wantResults int
	}{
		{"Search for Go", "go", 1},
		{"Search for programming", "programming", 1},
		{"Search for tutorial", "tutorial", 1},
		{"Search with no results", "rust", 0},
		{"Empty query", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/search?q="+tt.query, nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)

			var posts []clposts.Post
			json.Unmarshal(w.Body.Bytes(), &posts)
			assert.Len(t, posts, tt.wantResults)
		})
	}
}

// ============= Tests pour les handlers d'authentification =============

func TestLoginHandler(t *testing.T) {
	testDB := setupTestDB(t)
	clblog.GetInstance().Db = testDB
	r := setupTestRouter()
	clblog.GetInstance().Configuration = setupTestConfig()

	// Créer un hash valide pour le test
	hash, _ := HashPassword("testpassword")
	clblog.GetInstance().Configuration.User.Hash = hash

	r.POST("/admin/login", loginHandler)

	tests := []struct {
		name       string
		username   string
		password   string
		wantStatus int
	}{
		{"Valid credentials", "admin", "testpassword", http.StatusOK},
		{"Wrong password", "admin", "wrongpass", http.StatusUnauthorized},
		{"Wrong username", "wronguser", "testpassword", http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loginReq := LoginRequest{
				Username: tt.username,
				Password: tt.password,
			}
			body, _ := json.Marshal(loginReq)
			req := httptest.NewRequest("POST", "/admin/login", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)
		})
	}
}

func TestAuthRequiredMiddleware(t *testing.T) {
	r := setupTestRouter()

	// Route protégée
	r.GET("/protected", authRequired(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Test sans authentification
	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// Test avec authentification (simuler une session)
	store := cookie.NewStore([]byte("test-secret"))
	r2 := gin.New()
	r2.Use(sessions.Sessions("test-session", store))

	r2.GET("/login", func(c *gin.Context) {
		session := sessions.Default(c)
		session.Set("user_id", "admin")
		session.Save()
		c.JSON(http.StatusOK, gin.H{"message": "logged in"})
	})

	r2.GET("/protected", authRequired(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// D'abord se connecter
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/login", nil)
	r2.ServeHTTP(w2, req2)

	// Ensuite accéder à la route protégée avec le cookie de session
	w3 := httptest.NewRecorder()
	req3 := httptest.NewRequest("GET", "/protected", nil)
	req3.Header.Set("Cookie", w2.Header().Get("Set-Cookie"))
	r2.ServeHTTP(w3, req3)
	assert.Equal(t, http.StatusOK, w3.Code)
}

// ============= Tests pour les handlers d'administration =============

func TestCreatePostHandler(t *testing.T) {
	testDB := setupTestDB(t)
	clblog.GetInstance().Db = testDB
	r := setupTestRouter()

	// Simuler une session admin
	r.Use(func(c *gin.Context) {
		session := sessions.Default(c)
		session.Set("user_id", "admin")
		session.Set("username", "admin")
		session.Save()
		c.Next()
	})

	r.POST("/admin/posts", createPostHandler)

	createReq := CreatePostRequest{
		Title:   "New Post",
		Content: "New Content",
		Excerpt: "New Excerpt",
		Tags:    []string{"new", "test"},
	}

	body, _ := json.Marshal(createReq)
	req := httptest.NewRequest("POST", "/admin/posts", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Contains(t, response, "post_id")
	assert.Contains(t, response, "message")

	// Vérifier que le post a été créé
	var post clposts.Post
	testDB.First(&post, response["post_id"])
	assert.Equal(t, createReq.Title, post.Title)
	assert.Equal(t, createReq.Content, post.Content)
}

func TestUpdatePostHandler(t *testing.T) {
	testDB := setupTestDB(t)
	clblog.GetInstance().Db = testDB
	r := setupTestRouter()

	post := createTestPost(testDB)

	r.PUT("/admin/posts/:id", updatePostHandler)

	updateReq := UpdatePostRequest{
		Title:   "Updated Title",
		Content: "Updated Content",
		Excerpt: "Updated Excerpt",
		Tags:    []string{"updated", "modified"},
	}

	body, _ := json.Marshal(updateReq)
	req := httptest.NewRequest("PUT", fmt.Sprintf("/admin/posts/%d", post.ID), bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Vérifier la mise à jour
	var updatedPost clposts.Post
	testDB.First(&updatedPost, post.ID)
	assert.Equal(t, updateReq.Title, updatedPost.Title)
	assert.Equal(t, updateReq.Content, updatedPost.Content)
	assert.Equal(t, "updated,modified", updatedPost.Tags)
}

func TestDeletePostHandler(t *testing.T) {
	testDB := setupTestDB(t)
	clblog.GetInstance().Db = testDB
	r := setupTestRouter()

	post := createTestPost(testDB)

	// Ajouter des commentaires
	testDB.Create(&clposts.Comment{PostID: post.ID, Author: "User", Content: "Comment"})

	r.DELETE("/admin/posts/:id", deletePostHandler)

	req := httptest.NewRequest("DELETE", fmt.Sprintf("/admin/posts/%d", post.ID), nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Vérifier que le post et ses dépendances ont été supprimés
	var count int64
	testDB.Model(&clposts.Post{}).Where("id = ?", post.ID).Count(&count)
	assert.Equal(t, int64(0), count)

	testDB.Model(&clposts.Comment{}).Where("post_id = ?", post.ID).Count(&count)
	assert.Equal(t, int64(0), count)
}

// ============= Tests pour les fonctions utilitaires =============

func TestConvertMarkdownToHTML(t *testing.T) {

	tests := []struct {
		name     string
		markdown string
		expected string
	}{
		{
			"Bold text",
			"**Bold**",
			"<strong>Bold</strong>",
		},
		{
			"Italic text",
			"*Italic*",
			"<em>Italic</em>",
		},
		{
			"Code block",
			"`code`",
			"<code>code</code>",
		},
		{
			"Heading",
			"# Heading",
			"<h1",
		},
		{
			"Link",
			"[Link](http://example.com)",
			`<a href="http://example.com" target="_blank" rel="noopener noreferrer">Link</a>`,
		},
	}
	clmarkdown.InitMarkdown()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			html := clmarkdown.ConvertMarkdownToHTML(tt.markdown)
			assert.Contains(t, string(html), tt.expected)
		})
	}
}

func TestGenerateRandomString(t *testing.T) {
	tests := []struct {
		length int
	}{
		{5},
		{10},
		{20},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("Length %d", tt.length), func(t *testing.T) {
			str := generateRandomString(tt.length)
			assert.Len(t, str, tt.length)
			// Vérifier que la chaîne ne contient que des caractères valides
			for _, c := range str {
				assert.True(t, (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))
			}
		})
	}

	// Vérifier que deux appels génèrent des chaînes différentes
	str1 := generateRandomString(10)
	str2 := generateRandomString(10)
	assert.NotEqual(t, str1, str2)
}

// ============= Tests pour les routes de commentaires =============

func TestGetCommentsAPI(t *testing.T) {
	testDB := setupTestDB(t)
	clblog.GetInstance().Db = testDB
	r := setupTestRouter()

	post := createTestPost(testDB)

	// Créer des commentaires
	testDB.Create(&clposts.Comment{PostID: post.ID, Author: "User1", Content: "Comment 1", Approved: true})
	testDB.Create(&clposts.Comment{PostID: post.ID, Author: "User2", Content: "Comment 2", Approved: true})

	r.GET("/api/posts/:id/comments", getCommentsAPI)

	req := httptest.NewRequest("GET", fmt.Sprintf("/api/posts/%d/comments", post.ID), nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var comments []clposts.Comment
	json.Unmarshal(w.Body.Bytes(), &comments)
	assert.Len(t, comments, 2)
	assert.Equal(t, "User1", comments[0].Author)
	assert.Equal(t, "User2", comments[1].Author)
}

// ============= Tests d'intégration =============

func TestPostWorkflow(t *testing.T) {
	testDB := setupTestDB(t)
	clblog.GetInstance().Db = testDB
	r := setupTestRouter()
	clblog.GetInstance().Configuration = setupTestConfig()

	// Setup routes
	r.POST("/admin/posts", createPostHandler)
	r.PUT("/admin/posts/:id", updatePostHandler)
	r.POST("/api/posts/:id/comments", addCommentAPI)
	r.DELETE("/admin/posts/:id", deletePostHandler)

	// 1. Créer un post
	createReq := CreatePostRequest{
		Title:   "Integration Test Post",
		Content: "Integration test content",
		Author:  "Test Author",
		Tags:    []string{"integration", "test"},
	}

	body, _ := json.Marshal(createReq)
	req := httptest.NewRequest("POST", "/admin/posts", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var createResp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &createResp)
	postID := uint(createResp["post_id"].(float64))

	// 2. Mettre à jour le post
	updateReq := UpdatePostRequest{
		Title:   "Updated Integration Test",
		Content: "Updated content",
		Tags:    []string{"updated"},
	}

	body, _ = json.Marshal(updateReq)
	req = httptest.NewRequest("PUT", fmt.Sprintf("/admin/posts/%d", postID), bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	clblog.GetInstance().Captcha = clcaptchas.New("", 0)
	data, err := clblog.GetInstance().Captcha.GenerateCaptcha(false)
	assert.Equal(t, nil, err)

	// 3. Ajouter un commentaire
	commentReq := CreateCommentRequest{
		Author:        "Commenter",
		Content:       "Great post!",
		CaptchaID:     data["captcha_id"].(string),
		CaptchaAnswer: data["answer"].(string),
	}

	body, _ = json.Marshal(commentReq)
	req = httptest.NewRequest("POST", fmt.Sprintf("/api/posts/%d/comments", postID), bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	// 5. Vérifier l'état final
	var post clposts.Post
	testDB.Preload("Comments").First(&post, postID)
	assert.Equal(t, "Updated Integration Test", post.Title)
	assert.Len(t, post.Comments, 1)

	// 6. Supprimer le post
	req = httptest.NewRequest("DELETE", fmt.Sprintf("/admin/posts/%d", postID), nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Vérifier la suppression
	var count int64
	testDB.Model(&clposts.Post{}).Where("id = ?", postID).Count(&count)
	assert.Equal(t, int64(0), count)
}

func BenchmarkConvertMarkdownToHTML(b *testing.B) {

	markdown := `# Benchmark Test

This is a **benchmark** test with *various* markdown elements.

- List item 1
- List item 2
- List item 3

[Link](http://example.com)

` + "```go" + `
func main() {
    fmt.Println("Hello, World!")
}
` + "```" + `
`
	b.ResetTimer()
	clmarkdown.InitMarkdown()
	for i := 0; i < b.N; i++ {
		clmarkdown.ConvertMarkdownToHTML(markdown)
	}
}

func BenchmarkSearchPosts(b *testing.B) {
	testDB := setupTestDBBench(b)
	clblog.GetInstance().Db = testDB

	// Créer de nombreux posts pour le benchmark
	for i := 0; i < 100; i++ {
		testDB.Create(&clposts.Post{
			BlogID:  0,
			Title:   fmt.Sprintf("Post %d", i),
			Content: fmt.Sprintf("Content for post %d with various keywords", i),
			Tags:    fmt.Sprintf("tag%d,benchmark", i),
		})
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		var posts []clposts.Post
		searchTerm := "%keyword%"
		clblog.GetInstance().Db.Where(
			"LOWER(title) LIKE ? OR LOWER(content) LIKE ? OR LOWER(tags) LIKE ?",
			searchTerm, searchTerm, searchTerm,
		).Find(&posts)
	}
}

// ============= Tests pour la gestion des erreurs =============

func TestErrorHandling(t *testing.T) {
	testDB := setupTestDB(t)
	clblog.GetInstance().Db = testDB

	t.Run("Invalid JSON in create post", func(t *testing.T) {
		r := setupTestRouter()
		r.POST("/admin/posts", createPostHandler)

		req := httptest.NewRequest("POST", "/admin/posts", bytes.NewBufferString("invalid json"))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]string
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Contains(t, response["error"], "Données invalides")
	})

	t.Run("Missing required fields", func(t *testing.T) {
		r := setupTestRouter()
		r.POST("/admin/posts", createPostHandler)

		// Post sans titre
		createReq := CreatePostRequest{
			Content: "Content without title",
		}

		body, _ := json.Marshal(createReq)
		req := httptest.NewRequest("POST", "/admin/posts", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("Database error simulation", func(t *testing.T) {
		r := setupTestRouter()
		// Fermer la DB pour simuler une erreur
		sqlDB, _ := testDB.DB()
		sqlDB.Close()

		r.GET("/api/posts", getPostsAPI)

		req := httptest.NewRequest("GET", "/api/posts", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		// Réouvrir pour les tests suivants
		clblog.GetInstance().Db = setupTestDB(t)
	})
}

// ============= Tests pour les fonctionnalités de pagination (si ajoutées) =============

func TestPaginationLogic(t *testing.T) {
	testDB := setupTestDB(t)

	// Créer 25 posts
	for i := 1; i <= 25; i++ {
		testDB.Create(&clposts.Post{
			BlogID:  0,
			Title:   fmt.Sprintf("Post %d", i),
			Content: fmt.Sprintf("Content %d", i),
		})
	}

	tests := []struct {
		name      string
		page      int
		limit     int
		wantLen   int
		wantFirst string
		wantLast  string
	}{
		{"First page", 1, 10, 10, "Post 25", "Post 16"},
		{"Second page", 2, 10, 10, "Post 15", "Post 6"},
		{"Third page", 3, 10, 5, "Post 5", "Post 1"},
		{"Large limit", 1, 30, 25, "Post 25", "Post 1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var posts []clposts.Post
			offset := (tt.page - 1) * tt.limit
			testDB.Order("created_at desc, id desc").Limit(tt.limit).Offset(offset).Find(&posts)

			assert.Len(t, posts, tt.wantLen)
			if tt.wantLen > 0 {
				assert.Equal(t, tt.wantFirst, posts[0].Title)
				assert.Equal(t, tt.wantLast, posts[len(posts)-1].Title)
			}
		})
	}
}

// ============= Tests pour la validation des entrées =============

func TestInputValidation(t *testing.T) {
	testDB := setupTestDB(t)
	clblog.GetInstance().Db = testDB
	r := setupTestRouter()

	t.Run("XSS Prevention in Comments", func(t *testing.T) {
		post := createTestPost(testDB)

		r.POST("/api/posts/:id/comments", addCommentAPI)

		clblog.GetInstance().Captcha = clcaptchas.New("", 0)
		data, err := clblog.GetInstance().Captcha.GenerateCaptcha(false)
		assert.Equal(t, nil, err)

		comment := CreateCommentRequest{
			Author:        "<script>alert('XSS')</script>",
			Content:       "<img src=x onerror=alert('XSS')>",
			CaptchaID:     data["captcha_id"].(string),
			CaptchaAnswer: data["answer"].(string),
		}

		body, _ := json.Marshal(comment)
		req := httptest.NewRequest("POST", fmt.Sprintf("/api/posts/%d/comments", post.ID), bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		// Vérifier que le contenu est stocké tel quel (l'échappement se fait à l'affichage)
		var createdComment clposts.Comment
		json.Unmarshal(w.Body.Bytes(), &createdComment)
		assert.Contains(t, createdComment.Author, "<script>")
	})

	t.Run("SQL Injection Prevention", func(t *testing.T) {
		r.GET("/api/search", searchPostsAPI)

		// Tentative d'injection SQL
		req := httptest.NewRequest("GET", "/api/search?q='+OR+1=1--", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var posts []clposts.Post
		json.Unmarshal(w.Body.Bytes(), &posts)
		// Devrait retourner 0 résultats car GORM échappe les paramètres
		assert.Len(t, posts, 0)
	})

	t.Run("Empty strings handling", func(t *testing.T) {
		r.POST("/admin/posts", createPostHandler)

		createReq := CreatePostRequest{
			Title:   "   ", // Espaces uniquement
			Content: "Valid content",
		}

		body, _ := json.Marshal(createReq)
		req := httptest.NewRequest("POST", "/admin/posts", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		// Un titre vide après TrimSpace devrait échouer la validation
		if w.Code == http.StatusBadRequest {
			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Contains(t, response, "error")
		} else {
			t.Errorf("Unexpected status code: %d", w.Code)
		}
	})
}

// ============= Tests pour les sessions =============

func TestSessionManagement(t *testing.T) {
	r := setupTestRouter()
	clblog.GetInstance().Configuration = setupTestConfig()

	// Créer un hash valide
	hash, _ := HashPassword("testpass")
	clblog.GetInstance().Configuration.User.Hash = hash

	r.POST("/admin/login", loginHandler)
	r.POST("/admin/logout", logoutHandler)
	r.GET("/admin/check", authRequired(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"authenticated": true})
	})

	t.Run("Login creates session", func(t *testing.T) {
		loginReq := LoginRequest{
			Username: "admin",
			Password: "testpass",
		}

		body, _ := json.Marshal(loginReq)
		req := httptest.NewRequest("POST", "/admin/login", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.NotEmpty(t, w.Header().Get("Set-Cookie"))

		// Vérifier l'accès avec le cookie
		req2 := httptest.NewRequest("GET", "/admin/check", nil)
		req2.Header.Set("Cookie", w.Header().Get("Set-Cookie"))
		w2 := httptest.NewRecorder()
		r.ServeHTTP(w2, req2)

		assert.Equal(t, http.StatusOK, w2.Code)
	})

	t.Run("Logout destroys session", func(t *testing.T) {
		// D'abord se connecter
		loginReq := LoginRequest{
			Username: "admin",
			Password: "testpass",
		}

		body, _ := json.Marshal(loginReq)
		req := httptest.NewRequest("POST", "/admin/login", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		cookie := w.Header().Get("Set-Cookie")

		// Ensuite se déconnecter
		req2 := httptest.NewRequest("POST", "/admin/logout", nil)
		req2.Header.Set("Cookie", cookie)
		w2 := httptest.NewRecorder()
		r.ServeHTTP(w2, req2)

		assert.Equal(t, http.StatusOK, w2.Code)

		// Vérifier que l'accès est refusé
		req3 := httptest.NewRequest("GET", "/admin/check", nil)
		req3.Header.Set("Cookie", w2.Header().Get("Set-Cookie"))
		req3.Header.Set("Content-Type", "application/json")
		w3 := httptest.NewRecorder()
		r.ServeHTTP(w3, req3)

		assert.Equal(t, http.StatusUnauthorized, w3.Code)
	})
}

// ============= Tests pour les fichiers statiques et uploads =============

func TestStaticFileHandling(t *testing.T) {
	// Créer un dossier temporaire pour les tests
	tempDir := "./test_static"
	os.MkdirAll(tempDir, 0755)
	defer os.RemoveAll(tempDir)

	// Créer un fichier test
	testFile := filepath.Join(tempDir, "test.css")
	os.WriteFile(testFile, []byte("body { color: red; }"), 0644)

	r := setupTestRouter()
	r.Static("/static", tempDir)

	req := httptest.NewRequest("GET", "/static/test.css", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "color: red")
}

// ============= Tests pour les limites et performances =============

// ============= Tests pour les limites et performances =============

func TestRateLimiting(t *testing.T) {
	t.Skip("Rate limiting test - requires limiter middleware setup")
	// Ce test nécessiterait une configuration complète du middleware de limitation
}

// ============= Tests de régression =============

func TestRegressionEmptyTags(t *testing.T) {
	testDB := setupTestDB(t)

	// Test qu'un post sans tags fonctionne correctement
	post := &clposts.Post{
		BlogID:   0,
		Title:    "Post without tags",
		Content:  "Content",
		TagsList: []string{},
	}

	err := testDB.Create(post).Error
	assert.NoError(t, err)
	assert.Empty(t, post.Tags)

	// Récupérer et vérifier
	var retrieved clposts.Post
	testDB.First(&retrieved, post.ID)
	assert.Empty(t, retrieved.TagsList)
}

func TestRegressionLongContent(t *testing.T) {
	testDB := setupTestDB(t)

	// Créer un contenu très long
	longContent := strings.Repeat("This is a very long content. ", 1000)

	post := &clposts.Post{
		BlogID:  0,
		Title:   "Long post",
		Content: longContent,
	}

	err := testDB.Create(post).Error
	assert.NoError(t, err)

	var retrieved clposts.Post
	testDB.First(&retrieved, post.ID)
	assert.Equal(t, longContent, retrieved.Content)
}

// ============= Tests de migration de base de données =============

func TestDatabaseMigration(t *testing.T) {
	// Test que les migrations créent les bonnes tables
	testDB := setupTestDB(t)

	// Vérifier que les tables existent avec la bonne requête SQLite
	tables := []string{"posts", "comments"}

	for _, tableName := range tables {
		var name string
		err := testDB.Raw("SELECT name FROM sqlite_master WHERE type='table' AND name=?", tableName).Scan(&name).Error

		if err != nil {
			t.Errorf("Table %s does not exist: %v", tableName, err)
		} else {
			assert.Equal(t, tableName, name, "Table name mismatch")
		}
	}

	// Vérifier aussi avec une approche alternative
	var tableCount int64
	testDB.Raw("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('posts', 'comments')").Scan(&tableCount)
	assert.Equal(t, int64(2), tableCount, "Should have exactly 3 tables")

	// Vérifier que les colonnes importantes existent
	// Pour SQLite, on peut utiliser PRAGMA
	var columns []struct {
		CID  int
		Name string
		Type string
	}

	// Vérifier les colonnes de la table posts
	testDB.Raw("PRAGMA table_info(posts)").Scan(&columns)
	columnNames := make([]string, 0)
	for _, col := range columns {
		columnNames = append(columnNames, col.Name)
	}

	// Vérifier que les colonnes essentielles existent
	assert.Contains(t, columnNames, "id")
	assert.Contains(t, columnNames, "title")
	assert.Contains(t, columnNames, "content")
	assert.Contains(t, columnNames, "author")
}

// ============= Tests pour les flux RSS =============
func TestRSSHandler(t *testing.T) {
	testDB := setupTestDB(t)
	clblog.GetInstance().Db = testDB
	r := setupTestRouter()
	clblog.GetInstance().Configuration = setupTestConfig()

	// Créer quelques posts de test
	for i := 1; i <= 3; i++ {
		post := &clposts.Post{
			BlogID:   0,
			Title:    fmt.Sprintf("Post %d", i),
			Content:  fmt.Sprintf("Content for post %d", i),
			Excerpt:  fmt.Sprintf("Excerpt %d", i),
			Author:   "Test Author",
			TagsList: []string{fmt.Sprintf("tag%d", i)},
		}
		testDB.Create(post)
	}

	r.GET("/feed/rss", handlers_rss.RssHandler)

	req := httptest.NewRequest("GET", "/feed/rss", nil)
	req.Host = "localhost:8080"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/rss+xml")

	// Vérifier que le XML est valide
	var rss clrss.RSS
	err := xml.Unmarshal(w.Body.Bytes(), &rss)
	assert.NoError(t, err)
	assert.Equal(t, "2.0", rss.Version)
	assert.Equal(t, clblog.GetInstance().Configuration.Blogs[0].SiteName, rss.Channel.Title)
	assert.Len(t, rss.Channel.Items, 3)

	// Vérifier le contenu du premier item
	firstItem := rss.Channel.Items[0]
	assert.Equal(t, "Post 3", firstItem.Title) // Le plus récent
	assert.Equal(t, "http://localhost:8080/post/3", firstItem.Link)
	assert.Equal(t, "Excerpt 3", firstItem.Description)
}
