package clconfig

import (
	"fmt"
	"html/template"
	"log/syslog"
	"os"

	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

type Config struct {
	TrustedProxies  []string        `yaml:"trustedproxies"`
	TrustedPlatform string          `yaml:"trustedplatform"`
	Database        DatabaseConfig  `yaml:"database"`
	StaticPath      string          `yaml:"staticpath"`
	User            UserConfig      `yaml:"user"`
	Production      bool            `yaml:"production"`
	Listen          ListenConfig    `yaml:"listen"`
	Logger          LoggerConfig    `yaml:"logger"`
	Blogs           []BlogsConfig   `yaml:"blogs"`
	Analytics       AnalyticsConfig `yaml:"analytics"`
}

type AnalyticsConfig struct {
	Enabled bool        `yaml:"enabled"`
	Db      string      `yaml:"db"`
	Path    string      `yaml:"path"`
	Dsn     string      `yaml:"dsn"`
	Redis   RedisConfig `yaml:"redis"`
}

type RedisConfig struct {
	Addr string `yaml:"addr"`
	Db   int    `yaml:"db"`
}

type BlogsConfig struct {
	Id          uint       `yaml:"id"`
	Hostname    string     `yaml:"hostname"`
	SiteName    string     `yaml:"sitename"`
	Logo        string     `yaml:"logoimg"`
	Favicon     string     `yaml:"favicon"`
	Description string     `yaml:"description"`
	Theme       string     `yaml:"theme"`
	Menu        []MenuItem `yaml:"menu"`

	ThemeCSS string        `yaml:"-"`
	LinkRSS  template.HTML `yaml:"-"`
}

type LoggerConfig struct {
	Level  string             `yaml:"level"`
	File   LoggerFileConfig   `yaml:"file"`
	Syslog LoggerSyslogConfig `yaml:"syslog"`
}

type LoggerFileConfig struct {
	Enable     bool   `yaml:"enable"`
	Path       string `yaml:"path"`
	MaxSize    int    `yaml:"maxsize"`
	MaxBackups int    `yaml:"maxbackups"`
	MaxAge     int    `yaml:"maxage"`
	Compress   bool   `yaml:"compress"`
}

type LoggerSyslogConfig struct {
	Enable   bool            `yaml:"enable"`
	Protocol string          `yaml:"protocol"`
	Address  string          `yaml:"address"`
	Tag      string          `yaml:"tag"`
	Priority syslog.Priority `yaml:"priority"`
}

type ListenConfig struct {
	Website string `yaml:"website"`
}

type UserConfig struct {
	Login string `yaml:"login"`
	Pass  string `yaml:"pass"`
	Hash  string `yaml:"hash"`
}

type DatabaseConfig struct {
	Redis RedisConfig `yaml:"redis"`
	Db    string      `yaml:"db"`
	Path  string      `yaml:"path"`
	Dsn   string      `yaml:"dsn"`
}

type MenuItem struct {
	Key   string `yaml:"key"`
	Value string `yaml:"value"`
	Link  string `yaml:"link"`
	Img   string `yaml:"img"`
}

func CreateExampleConfig(filename string) (string, error) {
	example := &Config{
		Database: DatabaseConfig{
			Db:   "sqlite",
			Path: "./test.db",
		},
		Analytics: AnalyticsConfig{
			Enabled: false,
		},
		User: UserConfig{
			Login: "admin",
			Pass:  "admin1234",
		},
		StaticPath: "./static",
		Production: false,
		Logger: LoggerConfig{
			Level: "info",
			File: LoggerFileConfig{
				Enable: false,
			},
			Syslog: LoggerSyslogConfig{
				Enable: false,
			},
		},
		Listen: ListenConfig{
			Website: "0.0.0.0:8080",
		},
		Blogs: []BlogsConfig{
			{
				Id:          0,
				SiteName:    "Mon Blog Tech",
				Description: "Blog qui utilise littleblog",
				Logo:        "/static/linux.png",
				Favicon:     "/files/img/linux.png",
				Theme:       "blue",
				Menu: []MenuItem{
					{Key: "menu1", Value: "Menu 1"},
					{Key: "menu2", Value: "Menu 2", Img: "/static/linux.png"},
					{Link: "https://github.com/clankgeek/littleblog", Value: "Sur github"},
				},
			},
		},
	}

	if filename == "/etc/" {
		example.Listen.Website = "127.0.0.1:8000"
		example.Production = true
		example.Database.Path = "/var/lib/littleblog/sqlite.db"
		example.StaticPath = "/var/lib/littleblog/static"
		example.Logger.File = LoggerFileConfig{
			Enable:     true,
			Path:       "/var/log/littleblog/littleblog.log",
			MaxSize:    100,
			MaxBackups: 30,
			MaxAge:     7,
			Compress:   true,
		}
		filename = "/etc/littleblog/config.yaml"
	}

	return filename, WriteConfigYaml(filename, example)
}

func WriteConfigYaml(filename string, conf *Config) error {
	data, err := yaml.Marshal(conf)
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

// Convertir la config YAML en config interne
func ConvertConfig(yamlConfig *Config) *Config {
	conf := &Config{
		Database:        yamlConfig.Database,
		User:            yamlConfig.User,
		StaticPath:      yamlConfig.StaticPath,
		Production:      yamlConfig.Production,
		Listen:          yamlConfig.Listen,
		TrustedProxies:  yamlConfig.TrustedProxies,
		TrustedPlatform: yamlConfig.TrustedPlatform,
		Logger:          yamlConfig.Logger,
		Blogs:           yamlConfig.Blogs,
		Analytics:       yamlConfig.Analytics,
	}

	return conf
}

// Charger la configuration YAML
func LoadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("impossible de lire le fichier %s: %v", filename, err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("erreur de parsing YAML: %v", err)
	}

	return &config, nil
}

func CreateExample(shouldCreateExample bool, configFile string) {
	// Handle example creation
	if shouldCreateExample {
		if err := handleExampleCreation(configFile); err != nil {
			fmt.Printf("❌ %v\n", err)
		}
		os.Exit(1)
	}

	_, err := os.Stat(configFile)
	if err != nil && os.IsNotExist(err) {
		if err := handleExampleCreation(configFile); err != nil {
			fmt.Printf("❌ %v\n", err)
			os.Exit(1)
		}

	}
}

func handleExampleCreation(filename string) error {
	if filename == "" {
		filename = "littleblog.yaml"
	}
	filename, err := CreateExampleConfig(filename)
	if err != nil {
		return fmt.Errorf("erreur création exemple: %v", err)
	}

	fmt.Printf("✅ Fichier exemple créé: %s", filename)
	fmt.Println("⚠️  Admin_pass sera automatiquement hash en argon2 dans Admin_hash au premier lancement")
	return nil
}

func DisplayConfiguration(config *Config, version string) {
	logPrintf("Littleblog version %s", version)

	logPrintf("Mode Production %v", config.Production)
	logPrintf("Administrateur login %s", config.User.Login)

	logPrintf("Database")
	if config.Database.Db == "sqlite" {
		logPrintf("  • Type sqlite")
		logPrintf("  • Path %s", config.Database.Path)
	}
	if config.Database.Db == "mysql" {
		logPrintf("  • Type mysql")
		logPrintf("  • DSN %s", config.Database.Dsn)
	}
	if config.Database.Redis.Addr != "" {
		logPrintf("  • Cache redis %s", config.Database.Redis.Addr)
	}

	if config.Analytics.Enabled {
		logPrintf("  • Analytics activé")
		if config.Analytics.Db == "sqlite" && config.Analytics.Path != "" {
			logPrintf("  	• Sqlite path %s", config.Analytics.Path)
		} else if config.Analytics.Db == "mysql" && config.Analytics.Dsn != "" {
			logPrintf("  	• mysql dsn %s", config.Analytics.Dsn)
		} else {
			logPrintf("  	• La base est la même que la principale")
		}
		logPrintf("  	• Redis addr %s", config.Analytics.Redis.Addr)
	} else {
		logPrintf("  • Analytics désactivé")
	}

	// Logger
	logPrintf("Logger en level %s", config.Logger.Level)
	if config.Logger.File.Enable {
		logPrintf("  Log en fichier activé")
		logPrintf("  • Path %s", config.Logger.File.Path)
		logPrintf("  • Max size %d", config.Logger.File.MaxSize)
		logPrintf("  • Max age %d", config.Logger.File.MaxAge)
		logPrintf("  • Max backup %d", config.Logger.File.MaxBackups)
		logPrintf("  • Compression %v", config.Logger.File.Compress)
	} else {
		logPrintf("  Log en fichier désactivé")
	}
	if config.Logger.Syslog.Enable {
		logPrintf("  Log en syslog activé")
		logPrintf("  • Protocol %s", config.Logger.Syslog.Protocol)
		logPrintf("  • Address %s", config.Logger.Syslog.Address)
		logPrintf("  • Tag %s", config.Logger.Syslog.Tag)
		logPrintf("  • Priority %v", config.Logger.Syslog.Priority)
	} else {
		logPrintf("  Log en syslog désactivé")
	}

	logPrintf("Liste des blogs")
	for _, blog := range config.Blogs {
		logPrintf("  • \"%s\" avec l'id %d et le hostname %s", blog.SiteName, blog.Id, blog.Hostname)
	}
}

// Info logue avec printf
func logPrintf(format string, a ...any) {
	log.Info().Msg(fmt.Sprintf(format, a...))
}
