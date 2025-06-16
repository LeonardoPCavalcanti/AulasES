package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

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
	t.Run("DELETE e GET depois (garante 404)", func(t *testing.T) {
		adminToken := getAuthToken("admin", "password")

		// Cria primeiro
		newAlbum := `{"id": "99", "title": "Teste", "artist": "Artista", "price": 10.99}`
		reqCreate, _ := http.NewRequest("POST", "/albums", strings.NewReader(newAlbum))
		reqCreate.Header.Set("Content-Type", "application/json")
		reqCreate.Header.Set("Authorization", "Bearer "+adminToken)
		respCreate := httptest.NewRecorder()
		router.ServeHTTP(respCreate, reqCreate)
		assert.Equal(t, http.StatusCreated, respCreate.Code)

		// Deleta
		reqDelete, _ := http.NewRequest("DELETE", "/albums/99", nil)
		reqDelete.Header.Set("Authorization", "Bearer "+adminToken)
		respDelete := httptest.NewRecorder()
		router.ServeHTTP(respDelete, reqDelete)
		assert.Equal(t, http.StatusOK, respDelete.Code)

		// Tenta buscar e espera 404
		reqGet, _ := http.NewRequest("GET", "/albums/99", nil)
		respGet := httptest.NewRecorder()
		router.ServeHTTP(respGet, reqGet)
		assert.Equal(t, http.StatusNotFound, respGet.Code, "GET após DELETE deveria retornar 404")
	})

	// Teste de acesso negado (sem a role ADMIN)
	t.Run("POST /albums (acesso negado para USER)", func(t *testing.T) {
		userToken := getAuthToken("testuser", "password") // Role USER

		newAlbum := `{"id": "5", "title": "In Rainbows", "artist": "Radiohead", "price": 25.99}`
		req, _ := http.NewRequest("POST", "/albums", strings.NewReader(newAlbum))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+userToken)

		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)

		assert.Equal(t, http.StatusForbidden, resp.Code, "Usuário sem permissão deveria receber 403 Forbidden")

		// (Opcional) Validar mensagem de erro no corpo:
		var response map[string]string
		json.Unmarshal(resp.Body.Bytes(), &response)
		assert.Equal(t, "Permissões insuficientes", response["error"])
	})
}

// TestLoggingMiddleware testa o middleware de logging.
func TestLoggingMiddleware(t *testing.T) {
	// Cria o roteador com o middleware de logging
	router := gin.New()
	router.Use(loggingMiddleware())

	// Define uma rota simples para teste
	router.GET("/health", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	// Garante que o diretório de log existe
	logDir := "my-data"
	logFilePath := logDir + "/logs.txt"
	_ = os.MkdirAll(logDir, os.ModePerm)
	_ = os.Remove(logFilePath)

	// Faz uma requisição para gerar o log
	req, _ := http.NewRequest("GET", "/health", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	// Verifica se a resposta foi OK
	if resp.Code != http.StatusOK {
		t.Fatalf("Código de status esperado 200, recebido %d", resp.Code)
	}

	// Aguarda brevemente para garantir que o log seja gravado
	time.Sleep(100 * time.Millisecond)

	// Lê o arquivo de log
	logContent, err := os.ReadFile(logFilePath)
	if err != nil {
		t.Fatalf("Erro ao ler o arquivo de log: %v", err)
	}

	// Verifica se o log contém elementos esperados
	if !strings.Contains(string(logContent), "GET") ||
		!strings.Contains(string(logContent), "200") {
		t.Errorf("Log não contém os dados esperados. Conteúdo atual: %s", string(logContent))
	}
}
