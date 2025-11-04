package clposts

import (
	"html/template"
	"littleblog/internal/models/clmarkdown"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"gorm.io/gorm"
)

// Models avec tags GORM
type Post struct {
	ID          uint          `json:"id" gorm:"primaryKey"`
	BlogID      uint          `json:"blog_id" gorm:"index:idx_blog_hide"`
	Title       string        `json:"title" gorm:"not null"`
	Content     string        `json:"content" gorm:"type:text;not null"`
	ContentHTML template.HTML `json:"content_html" gorm:"-"`
	Excerpt     string        `json:"excerpt"`
	FirstImage  string        `json:"image" gorm:"type:text"`
	Author      string        `json:"author" gorm:"not null"`
	CreatedAt   time.Time     `json:"created_at" gorm:"autoCreateTime;index"`
	UpdatedAt   time.Time     `json:"updated_at" gorm:"autoUpdateTime"`
	Tags        string        `json:"-" gorm:"type:text"`
	Category    string        `json:"category" gorm:"type:text"`
	TagsList    []string      `json:"tags" gorm:"-"`
	Comments    []Comment     `json:"comments,omitempty" gorm:"foreignKey:PostID"`
	Hide        bool          `json:"hide" gorm:"type:bool;index:idx_blog_hide"`
}

type Comment struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	PostID    uint      `json:"post_id" gorm:"not null;index"`
	Author    string    `json:"author" gorm:"not null"`
	Content   string    `json:"content" gorm:"type:text;not null"`
	CreatedAt time.Time `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt time.Time `json:"updated_at" gorm:"autoUpdateTime"`
	Post      Post      `json:"-" gorm:"foreignKey:PostID"`
}

// Remplir Excerpt calculé a partir de content
func (p *Post) FillExcerpt() error {
	// Générer l'excerpt texte si vide
	if p.Content != "" {
		if p.Excerpt == "" {
			p.Excerpt = CleanMarkdownForExcerpt(p.Content)
			p.Excerpt = ExtractExcerpt(p.Excerpt, 500)
		} else {
			p.Excerpt = CleanMarkdownForExcerpt(p.Excerpt)
		}
		p.FirstImage = ""

		found, l := ExtractImages(p.Content, true, true)
		if found {
			p.FirstImage = l[0]
		}
	}
	return nil
}

func (p *Post) AfterFind(tx *gorm.DB) error {
	if p.Tags != "" {
		p.TagsList = strings.Split(p.Tags, ",")
	}
	p.ContentHTML = clmarkdown.ConvertMarkdownToHTML(p.Content)
	return nil
}

// Hooks GORM
func (p *Post) BeforeSave(tx *gorm.DB) error {
	if len(p.TagsList) > 0 {
		p.Tags = strings.Join(p.TagsList, ",")
	}
	return nil
}

func CleanMarkdownForExcerpt(content string) string {
	// supprimer les images
	reImage := regexp.MustCompile(`!\[.*?\]\(.*?\)`)
	return reImage.ReplaceAllString(content, "")
}

// ExtractExcerpt génère automatiquement un résumé depuis le contenu Markdown
func ExtractExcerpt(text string, maxLength int) string {
	// Si le texte est déjà assez court
	if utf8.RuneCountInString(text) <= maxLength {
		return text
	}

	runes := []rune(text)

	// D'abord, chercher une fin de phrase (. ! ?)
	cutPoint := maxLength
	for i := maxLength - 1; i >= maxLength-100 && i >= 0; i-- {
		if runes[i] == '.' || runes[i] == '!' || runes[i] == '?' {
			// Inclure le point/ponctuation et avancer d'un caractère
			cutPoint = i + 1
			break
		}
	}

	// Si aucune fin de phrase trouvée, chercher un espace
	if cutPoint == maxLength {
		for i := maxLength - 1; i >= maxLength-50 && i >= 0; i-- {
			if runes[i] == ' ' {
				cutPoint = i
				break
			}
		}
	}

	result := strings.TrimSpace(string(runes[:cutPoint]))

	// Ajouter "..." seulement si on n'a pas terminé sur une ponctuation
	lastChar := runes[cutPoint-1]
	if lastChar != '.' && lastChar != '!' && lastChar != '?' {
		result += "..."
	}

	return result
}

// ExtractImages extrait l'URL des images du Markdown
// Exemple: ![monimage.jpg](/static/uploads/1759683627_d4hhlyrc.jpg)
func ExtractImages(markdown string, firstOnly bool, fileOnly bool) (bool, []string) {
	if markdown == "" {
		return false, nil
	}

	// Pattern pour les images markdown: ![alt](url)
	reImage := regexp.MustCompile(`!\[[^\]]*\]\(([^)]+)\)`)

	var l []string
	found := false

	// Utiliser FindAllStringSubmatch au lieu de FindStringSubmatch
	matches := reImage.FindAllStringSubmatch(markdown, -1)

	for _, match := range matches {
		if len(match) > 1 {
			if fileOnly {
				// match[1] contient déjà le chemin capturé par le groupe ()
				imageURL := strings.TrimSpace(match[1])
				imageURL = strings.Trim(imageURL, `"' `)
				l = append(l, imageURL)
			} else {
				// match[0] contient toute la correspondance ![alt](url)
				imageURL := strings.TrimSpace(match[0])
				l = append(l, imageURL)
			}
			found = true

			if firstOnly {
				break
			}
		}
	}

	return found, l
}
