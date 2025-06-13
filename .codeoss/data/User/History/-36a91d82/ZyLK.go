package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

// Album representa os dados de um álbum de música.
type Album struct {
	ID     string  `json:"id"`
	Title  string  `json:"title"`
	Artist string  `json:"artist"`
	Price  float64 `json:"price"`
}

// User representa os dados de um usuário.
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// albums é um slice para armazenar os dados dos álbuns.
var albums = []Album{
	{ID: "1", Title: "Blue Train", Artist: "John Coltrane", Price: 56.99},
	{ID: "2", Title: "Jeru", Artist: "Gerry Mulligan", Price: 17.99},
	{ID: "3", Title: "Sarah Vaughan and Clifford Brown", Artist: "Sarah Vaughan", Price: 39.99},
}

// users é um slice para armazenar os dados dos usuários (em um cenário real, isso estaria em um banco de dados).
var users = []User{
	{Username: "admin", Password: hashPassword("password")}, // Senha "password" hasheada
}

// Secret key for signing JWTs.  In a real application, this should be
// a long, randomly-generated string, stored securely (e.g., environment variable).
var jwtKey = []byte("your_secret_key") // Change this!

// Claims represents the JWT claims (data).
type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"` // Adiciona o papel
	jwt.StandardClaims
}

func main() {
	router := gin.Default()

	// Create the logs directory if it doesn't exist
	if _, err := os.Stat("logs"); os.IsNotExist(err) {
		os.Mkdir("logs", 0755)
	}

	// Use the logging middleware
	router.Use(loggingMiddleware())

	// Rotas
	router.GET("/albums", getAlbums)
	router.GET("/albums/:id", getAlbumByID)

	adminRoutes := router.Group("/albums")
	adminRoutes.Use(authMiddleware("ADMIN")) // Passa o papel "ADMIN"
	{
		adminRoutes.POST("", postAlbums)
		adminRoutes.PUT("/:id", updateAlbum)
		adminRoutes.DELETE("/:id", deleteAlbum)
	}

	router.GET("/logs", getLogs)
	router.POST("/auth", authenticate)

	// Example of a protected route (requires authentication)
	protected := router.Group("/protected")
	protected.Use(authMiddleware("USER")) // Passa o papel "USER" ou "" para qualquer autenticado
	{
		protected.GET("/data", getProtectedData)
	}

	router.Run("0.0.0.0:8080")
}

// loggingMiddleware cria um middleware para registrar informações das requisições.
func loggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		latency := time.Since(start)

		logMessage := fmt.Sprintf("[%s] %s %s %d %s",
			time.Now().Format("2006-01-02 15:04:05"),
			c.Request.Method,
			c.Request.RequestURI,
			c.Writer.Status(),
			latency,
		)

		logFilePath := "my-data/logs.txt"
		if _, err := os.Stat(filepath.Dir(logFilePath)); os.IsNotExist(err) {
			os.MkdirAll(filepath.Dir(logFilePath), 0755)
		}

		file, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Println("Erro ao abrir o arquivo de log:", err)
			return
		}
		defer file.Close()

		if _, err := file.WriteString(logMessage + "\n"); err != nil {
			log.Println("Erro ao escrever no arquivo de log:", err)
		}
	}
}

// getAlbums retorna a lista de todos os álbuns como JSON.
func getAlbums(c *gin.Context) {
	c.IndentedJSON(http.StatusOK, albums)
}

// getLogs retorna o conteúdo do arquivo de log como texto plano.
func getLogs(c *gin.Context) {
	logFilePath := "my-data/logs.txt"
	content, err := os.ReadFile(logFilePath) // Alteração aqui
	if err != nil {
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"error": "Não foi possível ler o arquivo de log"})
		return
	}
	c.Data(http.StatusOK, "text/plain; charset=utf-8", content)
}

// postAlbums adiciona um álbum a partir do JSON recebido no corpo da requisição.
func postAlbums(c *gin.Context) {
	var newAlbum Album
	if err := c.BindJSON(&newAlbum); err != nil {
		return
	}
	albums = append(albums, newAlbum)
	c.IndentedJSON(http.StatusCreated, newAlbum)
}

// getAlbumByID localiza o álbum cujo ID corresponde ao parâmetro "id".
func getAlbumByID(c *gin.Context) {
	id := c.Param("id")
	for _, a := range albums {
		if a.ID == id {
			c.IndentedJSON(http.StatusOK, a)
			return
		}
	}
	c.IndentedJSON(http.StatusNotFound, gin.H{"message": "álbum não encontrado"})
}

// updateAlbum atualiza um álbum existente.
func updateAlbum(c *gin.Context) {
	id := c.Param("id")
	var updatedAlbum Album
	if err := c.BindJSON(&updatedAlbum); err != nil {
		return
	}
	for i, a := range albums {
		if a.ID == id {
			updatedAlbum.ID = id // Garante que o ID permaneça o mesmo
			albums[i] = updatedAlbum
			c.IndentedJSON(http.StatusOK, updatedAlbum)
			return
		}
	}
	c.IndentedJSON(http.StatusNotFound, gin.H{"message": "álbum não encontrado"})
}

// deleteAlbum exclui um álbum.
func deleteAlbum(c *gin.Context) {
	id := c.Param("id")
	for i, a := range albums {
		if a.ID == id {
			albums = append(albums[:i], albums[i+1:]...)
			c.IndentedJSON(http.StatusOK, gin.H{"message": "álbum excluído"})
			return
		}
	}
	c.IndentedJSON(http.StatusNotFound, gin.H{"message": "álbum não encontrado"})
}

// authenticate autentica um usuário e retorna um token JWT.
func authenticate(c *gin.Context) {
	var creds User
	if err := c.BindJSON(&creds); err != nil {
		c.IndentedJSON(http.StatusBadRequest, gin.H{"error": "Formato de credenciais inválido"})
		return
	}

	for _, u := range users {
		if u.Username == creds.Username && checkPasswordHash(creds.Password, u.Password) {
			role := "USER" // Papel padrão
			if u.Username == "admin" {
				role = "ADMIN" // Atribui papel "ADMIN" ao usuário "admin"
			}
			token, err := generateToken(creds.Username, role)
			if err != nil {
				c.IndentedJSON(http.StatusInternalServerError, gin.H{"error": "Erro ao gerar o token"})
				return
			}
			c.IndentedJSON(http.StatusOK, gin.H{"token": token})
			return
		}
	}

	c.IndentedJSON(http.StatusUnauthorized, gin.H{"error": "Nome de usuário ou senha inválidos"})
}

// generateToken gera um token JWT para o nome de usuário fornecido.
func generateToken(username, role string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: username,
		Role:     role, // Inclui o papel nos claims
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// authMiddleware creates a middleware to protect routes.
func authMiddleware(requiredRole string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr := c.GetHeader("Authorization")
		if tokenStr == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header missing"})
			return
		}

		// Extract the token from the "Bearer <token>" format
		splitToken := strings.Split(tokenStr, " ")
		if len(splitToken) != 2 || splitToken[0] != "Bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format"})
			return
		}
		tokenStr = splitToken[1]

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		// Verify user role
		if claims.Role != requiredRole {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
			return
		}

		c.Set("username", claims.Username) // Store username in context
		c.Next()
	}
}

// getProtectedData is an example of a protected route.
func getProtectedData(c *gin.Context) {
	username := c.GetString("username")
	c.IndentedJSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Hello, %s! This is protected data.", username)})
}

// hashPassword gera um hash seguro para a senha.
func hashPassword(password string) string {
	hashed, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hashed)
}

// checkPasswordHash compara uma senha com seu hash.
func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// TestAlbumEndpoints tests the album-related endpoints.
func TestAlbumEndpoints(t *testing.T) {
	router := gin.Default()
	router.Use(loggingMiddleware())
	router.GET("/albums", getAlbums)
	router.GET("/albums/:id", getAlbumByID)
	router.POST("/albums", postAlbums)
	router.PUT("/albums/:id", updateAlbum)
	router.DELETE("/albums/:id", deleteAlbum)

	// Test POST
	newAlbum := `{"id": "4", "title": "Kind of Blue", "artist": "Miles Davis", "price": 49.99}`
	req, _ := http.NewRequest("POST", "/albums", strings.NewReader(newAlbum))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusCreated {
		t.Errorf("POST /albums failed, expected %d, got %d", http.StatusCreated, resp.Code)
	}

	// Test GET all
	req, _ = http.NewRequest("GET", "/albums", nil)
	resp = httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Errorf("GET /albums failed, expected %d, got %d", http.StatusOK, resp.Code)
	}

	// Test GET by ID
	req, _ = http.NewRequest("GET", "/albums/4", nil)
	resp = httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Errorf("GET /albums/4 failed, expected %d, got %d", http.StatusOK, resp.Code)
	}

	// Test PUT
	updatedAlbum := `{"title": "Kind of Blue (Deluxe)", "artist": "Miles Davis", "price": 59.99}`
	req, _ = http.NewRequest("PUT", "/albums/4", strings.NewReader(updatedAlbum))
	req.Header.Set("Content-Type", "application/json")
	resp = httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Errorf("PUT /albums/4 failed, expected %d, got %d", http.StatusOK, resp.Code)
	}

	// Test DELETE
	req, _ = http.NewRequest("DELETE", "/albums/4", nil)
	resp = httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Errorf("DELETE /albums/4 failed, expected %d, got %d", http.StatusOK, resp.Code)
	}

	// Test GET by ID after DELETE (should not be found)
	req, _ = http.NewRequest("GET", "/albums/4", nil)
	resp = httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusNotFound {
		t.Errorf("GET /albums/4 after DELETE failed, expected %d, got %d", http.StatusNotFound, resp.Code)
	}
}

func TestLoggingMiddleware(t *testing.T) {
	// Create a new Gin router
	router := gin.New()

	// Use the logging middleware
	router.Use(loggingMiddleware())

	// Define a dummy route for testing
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	// Create a test request and response recorder
	req, _ := http.NewRequest("GET", "/test", nil)
	resp := httptest.NewRecorder()

	// Perform the request
	router.ServeHTTP(resp, req)

	// Check the response status code
	if resp.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, resp.Code)
	}

	// Verify the log file content
	logDir := "logs"
	files, err := os.ReadDir(logDir)
	if err != nil {
		t.Fatalf("Error reading log directory: %v", err)
	}

	if len(files) != 1 {
		t.Fatalf("Expected 1 log file, got %d", len(files))
	}

	logFileName := filepath.Join(logDir, files[0].Name())
	logFileContent, err := os.ReadFile(logFileName)
	if err != nil {
		t.Fatalf("Error reading log file: %v", err)
	}

	expectedLogMessage := "[20" // Check for the beginning of the timestamp
	if !strings.Contains(string(logFileContent), expectedLogMessage) {
		t.Errorf("Log file does not contain expected message: %s", expectedLogMessage)
	}
}
