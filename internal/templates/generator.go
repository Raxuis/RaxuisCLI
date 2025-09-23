package templates

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

//go:embed files/*
var filesFS embed.FS

type ProjectType string

type ListOption struct {
	TemplateName string
	ProjectType  string
}

const (
	NextJS ProjectType = "nextjs"
	NodeJS ProjectType = "node"
	Golang ProjectType = "go"
	Rust   ProjectType = "rust"
)

type GenerateConfig struct {
	ProjectType string
	OutputDir   string
	Files       []string
	Force       bool
	ProjectName string
}

type TemplateData struct {
	ProjectName string
	ProjectType string
}

type Generator struct {
	availableTemplates map[ProjectType][]string
}

func NewGenerator() *Generator {
	g := &Generator{
		availableTemplates: make(map[ProjectType][]string),
	}
	g.loadAvailableTemplates()
	return g
}

func (g *Generator) loadAvailableTemplates() {
	projectTypes := []ProjectType{NextJS, NodeJS, Golang, Rust}

	for _, projectType := range projectTypes {
		templateDir := fmt.Sprintf("files/%s", string(projectType))
		entries, err := filesFS.ReadDir(templateDir)
		if err != nil {
			continue
		}

		var files []string
		for _, entry := range entries {
			if !entry.IsDir() {
				// Enlever l'extension .tmpl pour le nom du template
				name := strings.TrimSuffix(entry.Name(), ".tmpl")
				files = append(files, name)
			}
		}
		g.availableTemplates[projectType] = files
	}
}

func (g *Generator) Generate(config GenerateConfig) error {
	projectType := ProjectType(config.ProjectType)

	// Vérifier si le type de projet existe
	templates, exists := g.availableTemplates[projectType]
	if !exists {
		var available []string
		for pt := range g.availableTemplates {
			available = append(available, string(pt))
		}
		return fmt.Errorf("unsupported project type: %s (available: %s)", config.ProjectType, strings.Join(available, ", "))
	}

	// Créer le répertoire de sortie si nécessaire
	if err := os.MkdirAll(config.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Déterminer quels fichiers générer
	filesToGenerate := config.Files
	if len(filesToGenerate) == 0 {
		filesToGenerate = templates
	}

	// Préparer les données du template
	templateData := TemplateData{
		ProjectName: config.ProjectName,
		ProjectType: config.ProjectType,
	}

	// Si pas de nom de projet spécifié, utiliser le nom du répertoire
	if templateData.ProjectName == "" {
		if absPath, err := filepath.Abs(config.OutputDir); err == nil {
			templateData.ProjectName = filepath.Base(absPath)
		} else {
			templateData.ProjectName = "my-project"
		}
	}

	// Générer chaque fichier
	for _, filename := range filesToGenerate {
		if !g.templateExists(projectType, filename) {
			fmt.Printf("Warning: template '%s' not found for project type '%s'\n", filename, config.ProjectType)
			continue
		}

		if err := g.generateFile(projectType, filename, config.OutputDir, templateData, config.Force); err != nil {
			return fmt.Errorf("failed to generate %s: %v", filename, err)
		}

		fmt.Printf("Generated: %s\n", g.getOutputFilename(filename))
	}

	return nil
}

func (g *Generator) templateExists(projectType ProjectType, filename string) bool {
	templates := g.availableTemplates[projectType]
	for _, t := range templates {
		if t == filename {
			return true
		}
	}
	return false
}

func (g *Generator) generateFile(projectType ProjectType, templateName, outputDir string, data TemplateData, force bool) error {
	// Lire le template
	templatePath := fmt.Sprintf("files/%s/%s.tmpl", string(projectType), templateName)
	templateContent, err := filesFS.ReadFile(templatePath)
	if err != nil {
		return fmt.Errorf("failed to read template: %v", err)
	}

	// Parser et exécuter le template
	tmpl, err := template.New(templateName).Parse(string(templateContent))
	if err != nil {
		return fmt.Errorf("failed to parse template: %v", err)
	}

	var result strings.Builder
	if err := tmpl.Execute(&result, data); err != nil {
		return fmt.Errorf("failed to execute template: %v", err)
	}

	// Écrire le fichier
	outputPath := filepath.Join(outputDir, g.getOutputFilename(templateName))

	// Vérifier si le fichier existe déjà
	if _, err := os.Stat(outputPath); err == nil && !force {
		return fmt.Errorf("file %s already exists (use --force to overwrite)", outputPath)
	}

	return os.WriteFile(outputPath, []byte(result.String()), 0644)
}

func (g *Generator) getOutputFilename(templateName string) string {
	switch templateName {
	case "gitignore":
		return ".gitignore"
	case "dockerignore":
		return ".dockerignore"
	case "readme":
		return "README.md"
	case "dockerfile":
		return "Dockerfile"
	case "packagejson":
		return "package.json"
	case "cargo":
		return "Cargo.toml"
	case "gomod":
		return "go.mod"
	default:
		return templateName
	}
}

func (g *Generator) ListAvailableTemplatesByProject(option ListOption) {
	if option.TemplateName != "" {
		found := false
		for projectType, templates := range g.availableTemplates {
			for _, t := range templates {
				if t == option.TemplateName {
					if !found {
						fmt.Printf("Template '%s' is available for:\n", option.TemplateName)
						found = true
					}
					fmt.Printf(" - %s\n", projectType)
				}
			}
		}
		if !found {
			// Construire une vue d'ensemble rapide des templates disponibles
			fmt.Printf("Template '%s' is not available for any project type.\n", option.TemplateName)
			fmt.Println()
			fmt.Println("Available templates by project type:")
			for projectType, templates := range g.availableTemplates {
				fmt.Printf("📁 %s:\n", string(projectType))
				for _, templateName := range templates {
					fmt.Printf("   • %s (%s)\n", templateName, g.getOutputFilename(templateName))
				}
				fmt.Println()
			}
		}
		return
	}
	fmt.Println("Available project types and templates:")
	fmt.Println()

	// Optional filter by project type
	if option.ProjectType != "" {
		pt := ProjectType(option.ProjectType)
		templates, ok := g.availableTemplates[pt]
		if !ok {
			fmt.Printf("Project type '%s' not found. Available: nextjs, node, go, rust\n", option.ProjectType)
			return
		}
		fmt.Printf("📁 %s:\n", string(pt))
		for _, templateName := range templates {
			fmt.Printf("   • %s (%s)\n", templateName, g.getOutputFilename(templateName))
		}
		fmt.Println()
		return
	}

	for projectType, templates := range g.availableTemplates {
		fmt.Printf("📁 %s:\n", string(projectType))
		for _, templateName := range templates {
			fmt.Printf("   • %s (%s)\n", templateName, g.getOutputFilename(templateName))
		}
		fmt.Println()
	}

	fmt.Println("Usage examples:")
	fmt.Println("  Generate all files for Next.js: templates generate nextjs --name my-app")
	fmt.Println("  Generate specific files: templates generate go --files gitignore,readme")
	fmt.Println("  Generate to specific directory: templates generate rust --output ./my-project --name awesome-rust-app")
}
