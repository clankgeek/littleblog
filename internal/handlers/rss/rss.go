package handlers_rss

import (
	"encoding/xml"
	"fmt"
	"littleblog/internal/models/clblog"
	"littleblog/internal/models/clposts"
	"littleblog/internal/models/clrss"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	stripmd "github.com/writeas/go-strip-markdown"
)

// rssHandler génère le flux RSS des posts
func getImageInfo(imagePath string) (size int64, mimeType string, err error) {
	// Obtenir les informations du fichier
	fileInfo, err := os.Stat(imagePath)
	if err != nil {
		return 0, "", err
	}

	// Taille du fichier
	size = fileInfo.Size()

	// Type MIME basé sur l'extension
	ext := filepath.Ext(imagePath)
	mimeType = mime.TypeByExtension(ext)

	// Si le type MIME n'est pas trouvé, définir une valeur par défaut
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}

	return size, mimeType, nil
}

func RssHandler(c *gin.Context) {
	var posts []clposts.Post

	item := clblog.GetInstance().GetConfItem(c, false, 0)
	db := clblog.GetInstance().Db

	// Récupérer les 20 derniers posts
	query := db.Order("created_at desc").Limit(20)

	category := c.Param("category")
	if category != "" {
		query = query.Where("blog_id = ? AND NOT hide AND category = ?", item.Id, clblog.Slugify(category))
	} else {
		query = query.Where("blog_id = ? AND NOT hide", item.Id)
	}

	result := query.Find(&posts)
	if result.Error != nil {
		c.XML(http.StatusInternalServerError, gin.H{"error": "Erreur récupération posts"})
		return
	}

	// Obtenir l'URL de base depuis la requête
	scheme := "http"
	if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	baseURL := fmt.Sprintf("%s://%s", scheme, c.Request.Host)

	// Construire le flux RSS
	rss := clrss.RSS{
		Version: "2.0",
		Channel: clrss.Channel{
			Title:         item.SiteName,
			Link:          baseURL,
			Description:   stripmd.Strip(item.Description),
			Language:      "fr-FR",
			Generator:     fmt.Sprintf("Littleblog v%s", clblog.GetInstance().Version),
			LastBuildDate: time.Now().Format(time.RFC1123Z),
			Items:         make([]clrss.RSSItem, 0, len(posts)),
		},
	}

	rss.Channel.Copyright = fmt.Sprintf("© %d %s", time.Now().Year(), item.SiteName)

	// Convertir les posts en items RSS
	for _, post := range posts {
		// Préparer la description (excerpt ou début du contenu)
		description := post.Excerpt
		if description == "" {
			// Prendre les 200 premiers caractères du contenu si pas d'excerpt
			if len(post.Content) > 200 {
				description = post.Content[:200] + "..."
			} else {
				description = post.Content
			}
		}

		// Category, si aucune catégorie, on prend le 1er tag
		category := ""
		if post.Category != "" {
			category = post.Category
		} else if len(post.TagsList) > 0 {
			category = post.TagsList[0] // RSS 2.0 ne supporte qu'une catégorie par item
		}

		item := clrss.RSSItem{
			Title:       post.Title,
			Link:        fmt.Sprintf("%s/post/%d", baseURL, post.ID),
			Description: stripmd.Strip(description),
			Author:      post.Author,
			Category:    category,
			GUID:        fmt.Sprintf("%s/post/%d", baseURL, post.ID),
			PubDate:     post.CreatedAt.Format(time.RFC1123Z),
			Enclosure:   nil,
		}

		// on génère l'image dans le rss si il y en a une de présente
		if post.FirstImage != "" {
			realpath := strings.Replace(post.FirstImage, "/static", clblog.GetInstance().Configuration.StaticPath, 1)
			size, mime, err := getImageInfo(realpath)
			if err == nil {
				item.Enclosure = &clrss.RSSEnclosure{
					URL:    post.FirstImage,
					Length: size,
					Type:   mime,
				}
			}
		}

		rss.Channel.Items = append(rss.Channel.Items, item)
	}

	// Définir le content-type approprié
	c.Header("Content-Type", "application/rss+xml; charset=utf-8")

	output, err := xml.MarshalIndent(rss, "", "  ")
	if err != nil {
		c.XML(http.StatusInternalServerError, gin.H{"error": "Erreur génération RSS"})
		return
	}

	// Ajouter le header XML au début
	xmlWithHeader := []byte(xml.Header + string(output))

	c.Data(http.StatusOK, "application/rss+xml; charset=utf-8", xmlWithHeader)
}
