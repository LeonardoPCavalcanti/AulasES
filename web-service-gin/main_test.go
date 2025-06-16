package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// setupRouter configura o roteador Gin para os testes.
func setupRouter() *gin.Engine {
	router := gin.Default()
	router.Use(loggingMiddleware())

	adminRoutes := router.Group("/albums")
	adminRoutes.Use(authMiddleware("ADMIN"))
	{
		adminRoutes.POST("", postAlbums)
		adminRoutes.PUT("/:id", updateAlbum)
		adminRoutes.DELETE("/:id", deleteAlbum)
	}
	router.GET("/albums", getAlbums)
	router.GET("/albums/:id", getAlbumByID)
	router.POST("/auth", authenticate)
	router.GET("/logs", getLogs)

	return router
}

// TestMain executa antes e depois de todos os testes.
func TestMain(m *testing.M) {
	// Setup antes de qualquer teste
	cleanupLogs()

	// Executa os testes
	code := m.Run()

	// Teardown depois dos testes
	cleanupLogs()

	// Encerra com o código de saída correto
	os.Exit(code)
}

// cleanupLogs remove os arquivos de log antes e depois dos testes.
func cleanupLogs() {
	logDir := "my-data"
	os.RemoveAll(logDir) // Remove o diretório e tudo dentro dele
}

// TestAlbumEndpoints testa os endpoints relacionados aos álbuns.
func TestAlbumEndpoints(t *testing.T) {
	router := setupRouter()

	// Função auxiliar para obter o token de autenticação
	getAuthToken := func(username, password string) string {
		credentials := User{Username: username, Password: password}
		jsonValue, _ := json.Marshal(credentials)
		req, _ := http.NewRequest("POST", "/auth", bytes.NewBuffer(jsonValue))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "Falha na autenticação para o usuário %s", username)
		var response map[string]string
		json.Unmarshal(w.Body.Bytes(), &response)
		return response["token"]
	}

	// Teste POST /albums (com autenticação)
	t.Run("POST /albums (com autenticação)", func(t *testing.T) {
		adminToken := getAuthToken("admin", "password")
		newAlbum := `{"id": "4", "title": "Kind of Blue", "artist": "Miles Davis", "price": 49.99}`
		req, _ := http.NewRequest("POST", "/albums", strings.NewReader(newAlbum))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+adminToken)
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		assert.Equal(t, http.StatusCreated, resp.Code, "POST /albums falhou")
	})

	// Teste GET /albums (sem autenticação)
	t.Run("GET /albums (sem autenticação)", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/albums", nil)
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		assert.Equal(t, http.StatusOK, resp.Code, "GET /albums falhou")
	})

	// Teste GET /albums/:id (sem autenticação)
	t.Run("GET /albums/:id (sem autenticação)", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/albums/4", nil)
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		assert.Equal(t, http.StatusOK, resp.Code, "GET /albums/4 falhou")
	})

	// Teste PUT /albums/:id (com autenticação)
	t.Run("PUT /albums/:id (com autenticação)", func(t *testing.T) {
		adminToken := getAuthToken("admin", "password")
		updatedAlbum := `{"title": "Kind of Blue (Deluxe)", "artist": "Miles Davis", "price": 59.99}`
		req, _ := http.NewRequest("PUT", "/albums/4", strings.NewReader(updatedAlbum))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+adminToken)
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		assert.Equal(t, http.StatusOK, resp.Code, "PUT /albums/4 falhou")
	})

	// Teste DELETE /albums/:id (com autenticação)
	t.Run("DELETE /albums/:id (com autenticação)", func(t *testing.T) {
		adminToken := getAuthToken("admin", "password")
		req, _ := http.NewRequest("DELETE", "/albums/4", nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		assert.Equal(t, http.StatusOK, resp.Code, "DELETE /albums/4 falhou")
	})

	// Teste GET /albums/:id após DELETE (sem autenticação, deve retornar 404)
	t.Run("GET /albums/:id após DELETE (sem autenticação)", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/albums/4", nil)
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		assert.Equal(t, http.StatusNotFound, resp.Code, "GET /albums/4 após DELETE falhou")
	})

	// Teste de acesso negado (sem a role ADMIN)
	t.Run("POST /albums (sem permissão)", func(t *testing.T) {
		userToken := getAuthToken("testuser", "password") // Token de usuário sem a role ADMIN
		newAlbum := `{"id": "5", "title": "In Rainbows", "artist": "Radiohead", "price": 25.99}`
		req, _ := http.NewRequest("POST", "/albums", strings.NewReader(newAlbum))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+userToken)
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		assert.Equal(t, http.StatusForbidden, resp.Code, "POST /albums com role de usuário deveria ter falhado")
	})
}

// TestLoggingMiddleware testa o middleware de logging.
func TestLoggingMiddleware(t *testing.T) {
	// Cria um novo roteador Gin
	router := gin.New()

	// Usa o middleware de logging
	router.Use(loggingMiddleware())

	// Define uma rota de teste
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	// Cria uma requisição de teste e um gravador de resposta
	req, _ := http.NewRequest("GET", "/test", nil)
	resp := httptest.NewRecorder()

	// Executa a requisição
	router.ServeHTTP(resp, req)

	// Verifica o código de status da resposta
	if resp.Code != http.StatusOK {
		t.Errorf("Código de status esperado %d, recebido %d", http.StatusOK, resp.Code)
	}

	// Verifica o conteúdo do arquivo de log
	logDir := "logs"
	files, err := os.ReadDir(logDir)
	if err != nil {
		t.Fatalf("Erro ao ler o diretório de logs: %v", err)
	}

	if len(files) != 1 {
		t.Fatalf("Esperado 1 arquivo de log, recebido %d", len(files))
	}

	logFileName := filepath.Join(logDir, files[0].Name())
	logFileContent, err := os.ReadFile(logFileName)
	if err != nil {
		t.Fatalf("Erro ao ler o arquivo de log: %v", err)
	}

	expectedLogMessage := "[20" // Verifica o início do timestamp
	if !strings.Contains(string(logFileContent), expectedLogMessage) {
		t.Errorf("Arquivo de log não contém a mensagem esperada: %s", expectedLogMessage)
	}
}
