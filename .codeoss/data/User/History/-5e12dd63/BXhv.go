package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func setupRouter() *gin.Engine {
	router := gin.Default()
	router.Use(loggingMiddleware()) // Assuming you want to test the middleware as well

	// Define as rotas de álbum com o middleware de autenticação
	adminRoutes := router.Group("/albums")
	adminRoutes.Use(authMiddleware("ADMIN"))
	{
		adminRoutes.POST("", postAlbums)
		adminRoutes.PUT("/:id", updateAlbum)
		adminRoutes.DELETE("/:id", deleteAlbum)
	}
	router.GET("/albums", getAlbums)
	router.GET("/albums/:id", getAlbumByID)
	router.POST("/auth", authenticate) // Include the auth endpoint for testing

	return router
}

func TestAlbumEndpoints(t *testing.T) {
	router := setupRouter()

	// Função auxiliar para obter token de autenticação
	getAuthToken := func(username, password string) string {
		credentials := User{Username: username, Password: password}
		jsonValue, _ := json.Marshal(credentials)
		req, _ := http.NewRequest("POST", "/auth", bytes.NewBuffer(jsonValue))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "Authentication failed for user %s", username)
		var response map[string]string
		json.Unmarshal(w.Body.Bytes(), &response)
		return response["token"]
	}

	// Teste POST com autenticação
	t.Run("POST /albums (com autenticação)", func(t *testing.T) {
		adminToken := getAuthToken("admin", "password")
		newAlbum := `{"id": "4", "title": "Kind of Blue", "artist": "Miles Davis", "price": 49.99}`
		req, _ := http.NewRequest("POST", "/albums", strings.NewReader(newAlbum))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+adminToken)
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		assert.Equal(t, http.StatusCreated, resp.Code, "POST /albums failed")
	})

	// Teste GET all (sem autenticação)
	t.Run("GET /albums (sem autenticação)", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/albums", nil)
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		assert.Equal(t, http.StatusOK, resp.Code, "GET /albums failed")
	})

	// Teste GET by ID (sem autenticação)
	t.Run("GET /albums/:id (sem autenticação)", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/albums/4", nil)
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		assert.Equal(t, http.StatusOK, resp.Code, "GET /albums/4 failed")
	})

	// Teste PUT com autenticação
	t.Run("PUT /albums/:id (com autenticação)", func(t *testing.T) {
		adminToken := getAuthToken("admin", "password")
		updatedAlbum := `{"title": "Kind of Blue (Deluxe)", "artist": "Miles Davis", "price": 59.99}`
		req, _ := http.NewRequest("PUT", "/albums/4", strings.NewReader(updatedAlbum))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+adminToken)
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		assert.Equal(t, http.StatusOK, resp.Code, "PUT /albums/4 failed")
	})

	// Teste DELETE com autenticação
	t.Run("DELETE /albums/:id (com autenticação)", func(t *testing.T) {
		adminToken := getAuthToken("admin", "password")
		req, _ := http.NewRequest("DELETE", "/albums/4", nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		assert.Equal(t, http.StatusOK, resp.Code, "DELETE /albums/4 failed")
	})

	// Teste GET by ID após DELETE (sem autenticação, deve retornar 404)
	t.Run("GET /albums/:id após DELETE (sem autenticação)", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/albums/4", nil)
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		assert.Equal(t, http.StatusNotFound, resp.Code, "GET /albums/4 after DELETE failed")
	})

	// Teste de acesso negado (sem a role ADMIN)
	t.Run("POST /albums (sem permissão)", func(t *testing.T) {
		userToken := getAuthToken("testuser", "password") // Token de usuário sem role ADMIN
		newAlbum := `{"id": "5", "title": "In Rainbows", "artist": "Radiohead", "price": 25.99}`
		req, _ := http.NewRequest("POST", "/albums", strings.NewReader(newAlbum))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+userToken)
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		assert.Equal(t, http.StatusForbidden, resp.Code, "POST /albums with user role should have failed")
	})

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
}
