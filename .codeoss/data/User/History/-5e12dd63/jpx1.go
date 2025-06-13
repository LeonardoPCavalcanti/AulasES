package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert" // Use testify for assertions
)

func setupRouter() *gin.Engine {
	router := gin.Default()
	router.POST("/auth", authenticate)
	return router
}

func TestAuthEndpoint(t *testing.T) {
	router := setupRouter()

	// Teste de autenticação bem-sucedida (substitua pelas suas credenciais de teste)
	credentials := User{Username: "admin", Password: "password"}
	jsonValue, _ := json.Marshal(credentials)
	req, _ := http.NewRequest("POST", "/auth", bytes.NewBuffer(jsonValue))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]string
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.NotEmpty(t, response["token"])

	// Teste de autenticação falhada (credenciais incorretas)
	invalidCredentials := User{Username: "wrong", Password: "wrongpassword"}
	jsonValue, _ = json.Marshal(invalidCredentials)
	req, _ = http.NewRequest("POST", "/auth", bytes.NewBuffer(jsonValue))
	req.Header.Set("Content-Type", "application/json")

	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
