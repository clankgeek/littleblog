package clrss

import "encoding/xml"

// RSS représente le flux RSS complet
type RSS struct {
	XMLName xml.Name `xml:"rss"`
	Version string   `xml:"version,attr"`
	Channel Channel  `xml:"channel"`
}

// Channel représente le canal RSS
type Channel struct {
	Title         string    `xml:"title"`
	Link          string    `xml:"link"`
	Description   string    `xml:"description"`
	Language      string    `xml:"language"`
	Copyright     string    `xml:"copyright,omitempty"`
	Generator     string    `xml:"generator"`
	LastBuildDate string    `xml:"lastBuildDate"`
	Items         []RSSItem `xml:"item"`
}

// RSSItem représente un article dans le flux RSS
type RSSItem struct {
	Title       string        `xml:"title"`
	Link        string        `xml:"link"`
	Description string        `xml:"description"`
	Author      string        `xml:"author,omitempty"`
	Category    string        `xml:"category,omitempty"`
	GUID        string        `xml:"guid"`
	PubDate     string        `xml:"pubDate"`
	Enclosure   *RSSEnclosure `xml:"enclosure"`
}

type RSSEnclosure struct {
	URL    string `xml:"url,attr"`
	Length int64  `xml:"length,attr"`
	Type   string `xml:"type,attr"`
}
