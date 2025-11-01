package clmiddleware

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateSecretKey(t *testing.T) {
	key := generateSecretKey()
	assert.Len(t, key, 32)

	// Vérifier que deux appels génèrent des clés différentes
	key2 := generateSecretKey()
	assert.NotEqual(t, key, key2)
}
