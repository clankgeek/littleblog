package clcaptchas

import (
	"fmt"
	"littleblog/internal/models/clredis"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/mojocn/base64Captcha"
	"github.com/redis/go-redis/v9"
)

type Captchas struct {
	store  base64Captcha.Store
	driver base64Captcha.Driver
}

func New(host string, db int) *Captchas {
	var store base64Captcha.Store
	if host != "" {
		redisClient := redis.NewClient(&redis.Options{
			Addr: host,
			DB:   db,
		})
		store = clredis.New(redisClient)
	} else {
		store = base64Captcha.DefaultMemStore
	}

	driver := base64Captcha.NewDriverMath(
		80,  // hauteur
		240, // largeur
		6,   // nombre d'opérations à afficher
		base64Captcha.OptionShowHollowLine,
		nil, // couleur de fond
		nil, // police
		nil, // couleurs
	)

	return &Captchas{
		store:  store,
		driver: driver,
	}
}

func (cap *Captchas) GenerateCaptcha(production bool) (map[string]any, error) {
	captcha := base64Captcha.NewCaptcha(cap.driver, cap.store)

	id, b64s, answer, err := captcha.Generate()
	if err != nil {
		return nil, fmt.Errorf("erreur lors de la génération du CAPTCHA")
	}

	data := gin.H{
		"captcha_id": id,
		"image":      b64s,
		"answer":     "",
	}

	if !production {
		fmt.Printf("CAPTCHA généré - ID: %s, Réponse: %s", id, answer)
		data["answer"] = answer
	}

	return data, nil
}

func (cap *Captchas) VerifyCaptcha(captchaID string, captchaAnswer string) error {
	captchaID = strings.TrimSpace(captchaID)
	captchaAnswer = strings.TrimSpace(captchaAnswer)

	if captchaID == "" || captchaAnswer == "" {
		return fmt.Errorf("CAPTCHA manquant")
	}

	if !cap.store.Verify(captchaID, captchaAnswer, true) {
		return fmt.Errorf("CAPTCHA incorrect")
	}
	return nil
}

func (cap *Captchas) CaptchaHandler(c *gin.Context, production bool) {
	data, err := cap.GenerateCaptcha(production)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, data)
}
