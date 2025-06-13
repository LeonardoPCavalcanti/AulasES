package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestAlbumEndpoints(t *testing.T) {
	router := gin.Default()
	router.Use(loggingMiddleware())

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

	// Função auxiliar para obter token de autenticação
	getAuthToken := func(username, password string) string {
		credentials := User{Username: username, Password: password}
		jsonValue, _ := json.Marshal(credentials)
		req, _ := http.NewRequest("POST", "/auth", bytes.NewBuffer(jsonValue))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
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
		if resp.Code != http.StatusCreated {
			t.Errorf("POST /albums failed, expected %d, got %d", http.StatusCreated, resp.Code)
		}
	})

	// Teste GET all (sem autenticação)
	t.Run("GET /albums (sem autenticação)", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/albums", nil)
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		if resp.Code != http.StatusOK {
			t.Errorf("GET /albums failed, expected %d, got %d", http.StatusOK, resp.Code)
		}
	})

	// Teste GET by ID (sem autenticação)
	t.Run("GET /albums/:id (sem autenticação)", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/albums/4", nil)
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		if resp.Code != http.StatusOK {
			t.Errorf("GET /albums/4 failed, expected %d, got %d", http.StatusOK, resp.Code)
		}
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
		if resp.Code != http.StatusOK {
			t.Errorf("PUT /albums/4 failed, expected %d, got %d", http.StatusOK, resp.Code)
		}
	})

	// Teste DELETE com autenticação
	t.Run("DELETE /albums/:id (com autenticação)", func(t *testing.T) {
		adminToken := getAuthToken("admin", "password")
		req, _ := http.NewRequest("DELETE", "/albums/4", nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		if resp.Code != http.StatusOK {
			t.Errorf("DELETE /albums/4 failed, expected %d, got %d", http.StatusOK, resp.Code)
		}
	})

	// Teste GET by ID após DELETE (sem autenticação, deve retornar 404)
	t.Run("GET /albums/:id após DELETE (sem autenticação)", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/albums/4", nil)
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		if resp.Code != http.StatusNotFound {
			t.Errorf("GET /albums/4 after DELETE failed, expected %d, got %d", http.StatusNotFound, resp.Code)
		}
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
		if resp.Code != http.StatusForbidden {
			t.Errorf("POST /albums with user role should have failed with %d, got %d", http.StatusForbidden, resp.Code)
		}
	})
}
