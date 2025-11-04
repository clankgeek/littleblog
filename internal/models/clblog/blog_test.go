package clblog

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSlugify(t *testing.T) {
	assert.Equal(t, "", Slugify(""))
	assert.Equal(t, "abcd01234--", Slugify("abcd01234--"))
	assert.Equal(t, "abc-d01234--", Slugify("%#abc d01234--"))
}

func TestTheme(t *testing.T) {
	assert.Equal(t, GenerateThemeCSS(""), GenerateThemeCSS("#007bff"))
	assert.Equal(t, GenerateThemeCSS("blue"), GenerateThemeCSS("#007bff"))
	assert.Equal(t, GenerateThemeCSS("red"), GenerateThemeCSS("#dc3545"))
}
