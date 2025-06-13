package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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

// albums é um slice para armazenar os dados dos álbuns (simula um banco de dados).
var albums = []Album{
	{ID: "1", Title: "Blue Train", Artist: "John Coltrane", Price: 56.99},
	{ID: "2", Title: "Jeru", Artist: "Gerry Mulligan", Price: 17.99},
	{ID: "3", Title: "Sarah Vaughan and Clifford Brown", Artist: "Sarah Vaughan", Price: 39.99},
}

// users é um slice para armazenar os dados dos usuários (simula um banco de dados).
var users = []User{
	{Username: "admin", Password: hashPassword("password")},
	{Username: "testuser", Password: hashPassword("password")},
}

// jwtKey é a chave secreta para assinar os tokens JWT.
// Em uma aplicação real, isso deve ser uma string longa e aleatória,
// armazenada de forma segura (por exemplo, em uma variável de ambiente).
var jwtKey = []byte("your_secret_key") // **IMPORTANTE: Mude isso em produção!**

// Claims representa as "claims" (informações) contidas no token JWT.
type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"` // Papel do usuário (ex: "ADMIN", "USER")
	jwt.StandardClaims
}

func main() {
	router := gin.Default()

	// Cria o diretório de logs se ele não existir.
	if _, err := os.Stat("logs"); os.IsNotExist(err) {
		os.Mkdir("logs", 0755)
	}

	// Usa o middleware para registrar informações das requisições.
	router.Use(loggingMiddleware())

	// Define as rotas da API.
	router.GET("/albums", getAlbums)           // Listar todos os álbuns
	router.GET("/albums/:id", getAlbumByID)     // Obter um álbum por ID
	router.GET("/logs", getLogs)               // Visualizar os logs do servidor
	router.POST("/auth", authenticate)         // Autenticar um usuário

	// Rotas protegidas que exigem autenticação e o papel "ADMIN".
	adminRoutes := router.Group("/albums")
	adminRoutes.Use(authMiddleware("ADMIN"))
	{
		adminRoutes.POST("", postAlbums)       // Criar um novo álbum
		adminRoutes.PUT("/:id", updateAlbum)    // Atualizar um álbum existente
		adminRoutes.DELETE("/:id", deleteAlbum) // Excluir um álbum
	}

	// Rota protegida que exige autenticação com o papel "USER" (ou qualquer usuário autenticado).
	protected := router.Group("/protected")
	protected.Use(authMiddleware("USER"))
	{
		protected.GET("/data", getProtectedData) // Obter dados protegidos
	}

	// Inicia o servidor na porta 8080.
	router.Run("0.0.0.0:8080")
}

// loggingMiddleware cria um middleware para registrar informações sobre cada requisição.
func loggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next() // Processa a requisição

		// Calcula a latência da requisição.
		latency := time.Since(start)

		// Formata a mensagem de log.
		logMessage := fmt.Sprintf("[%s] %s %s %d %s",
			time.Now().Format("2006-01-02 15:04:05"), // Formato da data/hora
			c.Request.Method,                        // Método HTTP (GET, POST, etc.)
			c.Request.RequestURI,                    // URI da requisição
			c.Writer.Status(),                       // Código de status da resposta
			latency,                                 // Tempo de resposta
		)

		// Define o caminho do arquivo de log.
		logFilePath := "my-data/logs.txt"

		// Cria o diretório se não existir.
		if _, err := os.Stat(filepath.Dir(logFilePath)); os.IsNotExist(err) {
			os.MkdirAll(filepath.Dir(logFilePath), 0755)
		}

		// Abre o arquivo de log para adicionar a mensagem.
		file, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Println("Erro ao abrir o arquivo de log:", err)
			return
		}
		defer file.Close() // Garante que o arquivo seja fechado ao final

		// Escreve a mensagem no arquivo.
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
	content, err := os.ReadFile(logFilePath)
	if err != nil {
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"error": "Não foi possível ler o arquivo de log"})
		return
	}
	c.Data(http.StatusOK, "text/plain; charset=utf-8", content)
}

// postAlbums adiciona um álbum a partir dos dados JSON recebidos no corpo da requisição.
func postAlbums(c *gin.Context) {
	var newAlbum Album
	// Tenta vincular o JSON recebido à estrutura Album.
	if err := c.BindJSON(&newAlbum); err != nil {
		return // Retorna um erro se a vinculação falhar.
	}
	// Adiciona o novo álbum à lista.
	albums = append(albums, newAlbum)
	// Retorna o álbum criado com o código de status 201 (Created).
	c.IndentedJSON(http.StatusCreated, newAlbum)
}

// getAlbumByID localiza o álbum cujo ID corresponde ao parâmetro "id" na URL.
func getAlbumByID(c *gin.Context) {
	id := c.Param("id") // Obtém o valor do parâmetro "id".
	// Itera sobre a lista de álbuns.
	for _, a := range albums {
		// Se o ID do álbum corresponder, retorna o álbum.
		if a.ID == id {
			c.IndentedJSON(http.StatusOK, a)
			return
		}
	}
	// Se o álbum não for encontrado, retorna um erro 404 (Not Found).
	c.IndentedJSON(http.StatusNotFound, gin.H{"message": "álbum não encontrado"})
}

// updateAlbum atualiza um álbum existente com base no ID fornecido.
func updateAlbum(c *gin.Context) {
	id := c.Param("id") // Obtém o ID do álbum a ser atualizado.
	var updatedAlbum Album
	// Tenta vincular o JSON recebido à estrutura Album.
	if err := c.BindJSON(&updatedAlbum); err != nil {
		return // Retorna um erro se a vinculação falhar.
	}
	// Itera sobre a lista de álbuns.
	for i, a := range albums {
		// Se o ID do álbum corresponder, atualiza o álbum.
		if a.ID == id {
			updatedAlbum.ID = id // Garante que o ID não seja alterado.
			albums[i] = updatedAlbum
			c.IndentedJSON(http.StatusOK, updatedAlbum)
			return
		}
	}
	// Se o álbum não for encontrado, retorna um erro 404.
	c.IndentedJSON(http.StatusNotFound, gin.H{"message": "álbum não encontrado"})
}

// deleteAlbum exclui um álbum da lista.
func deleteAlbum(c *gin.Context) {
	id := c.Param("id") // Obtém o ID do álbum a ser excluído.
	// Itera sobre a lista de álbuns.
	for i, a := range albums {
		// Se o ID do álbum corresponder, exclui o álbum.
		if a.ID == id {
			// Remove o álbum do slice.
			albums = append(albums[:i], albums[i+1:]...)
			c.IndentedJSON(http.StatusOK, gin.H{"message": "álbum excluído"})
			return
		}
	}
	// Se o álbum não for encontrado, retorna um erro 404.
	c.IndentedJSON(http.StatusNotFound, gin.H{"message": "álbum não encontrado"})
}

// authenticate autentica um usuário e retorna um token JWT em caso de sucesso.
func authenticate(c *gin.Context) {
	var creds User
	// Tenta vincular o JSON recebido (credenciais) à estrutura User.
	if err := c.BindJSON(&creds); err != nil {
		c.IndentedJSON(http.StatusBadRequest, gin.H{"error": "Formato de credenciais inválido"})
		return
	}

	// Procura o usuário nas credenciais armazenadas.
	for _, u := range users {
		// Verifica se o nome de usuário e a senha correspondem.
		if u.Username == creds.Username && checkPasswordHash(creds.Password, u.Password) {
			// Determina o papel do usuário (ADMIN ou USER).
			role := "USER"
			if u.Username == "admin" {
				role = "ADMIN"
			}
			// Gera um token JWT para o usuário.
			token, err := generateToken(creds.Username, role)
			if err != nil {
				c.IndentedJSON(http.StatusInternalServerError, gin.H{"error": "Erro ao gerar o token"})
				return
			}
			// Retorna o token JWT.
			c.IndentedJSON(http.StatusOK, gin.H{"token": token})
			return
		}
	}

	// Se as credenciais forem inválidas, retorna um erro 401 (Unauthorized).
	c.IndentedJSON(http.StatusUnauthorized, gin.H{"error": "Nome de usuário ou senha inválidos"})
}

// generateToken gera um token JWT para o nome de usuário e papel fornecidos.
func generateToken(username, role string) (string, error) {
	// Define o tempo de expiração do token (24 horas).
	expirationTime := time.Now().Add(24 * time.Hour)
	// Cria as "claims" (informações) que serão incluídas no token.
	claims := &Claims{
		Username: username,
		Role:     role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	// Cria o token com as claims e o método de assinatura.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Assina o token com a chave secreta.
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// authMiddleware cria um middleware para proteger rotas, exigindo autenticação e um papel específico.
func authMiddleware(requiredRole string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Obtém o token do cabeçalho "Authorization".
		tokenStr := c.GetHeader("Authorization")
		if tokenStr == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Cabeçalho de autorização ausente"})
			return
		}

		// Extrai o token do formato "Bearer <token>".
		splitToken := strings.Split(tokenStr, " ")
		if len(splitToken) != 2 || splitToken[0] != "Bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Formato de token inválido"})
			return
		}
		tokenStr = splitToken[1] // Obtém apenas a string do token.

		// Analisa o token e extrai as claims.
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil // Retorna a chave secreta para verificação.
		})

		// Se houver um erro na análise ou o token for inválido.
		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token inválido"})
			return
		}

		// Verifica se o papel do usuário corresponde ao papel exigido.
		if claims.Role != requiredRole {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Permissões insuficientes"})
			return
		}

		// Armazena o nome de usuário no contexto para uso posterior.
		c.Set("username", claims.Username)
		c.Next() // Permite que a requisição continue para o próximo handler.
	}
}

// getProtectedData é um exemplo de rota protegida que retorna dados específicos do usuário autenticado.
func getProtectedData(c *gin.Context) {
	// Obtém o nome de usuário do contexto.
	username := c.GetString("username")
	// Retorna uma mensagem personalizada.
	c.IndentedJSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Olá, %s! Estes são dados protegidos.", username)})
}

// hashPassword gera um hash seguro para a senha do usuário.
func hashPassword(password string) string {
	// Gera o hash usando bcrypt.
	hashed, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hashed)
}

// checkPasswordHash compara uma senha fornecida com o hash armazenado.
func checkPasswordHash(password, hash string) bool {
	// Compara a senha com o hash usando bcrypt.
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil // Retorna true se a senha corresponder ao hash.
}