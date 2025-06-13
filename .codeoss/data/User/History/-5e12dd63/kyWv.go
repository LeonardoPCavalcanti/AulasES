package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

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
