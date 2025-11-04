package clmarkdown

import (
	"bytes"
	"html/template"

	"github.com/rs/zerolog/log"
	"github.com/yuin/goldmark"
	emoji "github.com/yuin/goldmark-emoji"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer/html"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
)

type externalLinkTransformer struct{}

var MD goldmark.Markdown

// Initialiser le convertisseur Markdown
func InitMarkdown() {
	MD = goldmark.New(
		goldmark.WithExtensions(
			extension.GFM,
			extension.Table,
			extension.Strikethrough,
			extension.TaskList,
			emoji.Emoji,
		),
		goldmark.WithParserOptions(
			parser.WithAutoHeadingID(),
			parser.WithASTTransformers(
				util.Prioritized(&externalLinkTransformer{}, 100),
			),
		),
		goldmark.WithRendererOptions(
			html.WithHardWraps(),
			html.WithXHTML(),
			html.WithUnsafe(),
		),
	)
}

func ConvertMarkdownToHTML(markdown string) template.HTML {
	var buf bytes.Buffer
	if err := MD.Convert([]byte(markdown), &buf); err != nil {
		log.Error().Err(err).Msg("Erreur conversion Markdown")
		return template.HTML("<pre>" + template.HTMLEscapeString(markdown) + "</pre>")
	}
	return template.HTML(buf.String())
}

func (t *externalLinkTransformer) Transform(node *ast.Document, reader text.Reader, pc parser.Context) {
	ast.Walk(node, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}

		if link, ok := n.(*ast.Link); ok {
			link.SetAttributeString("target", []byte("_blank"))
			link.SetAttributeString("rel", []byte("noopener noreferrer"))
		}

		return ast.WalkContinue, nil
	})
}
