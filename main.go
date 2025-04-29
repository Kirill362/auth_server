package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"log"
	"os"
)

var accessTokenID int = 0
var secretKey = []byte(os.Getenv("JWT_SECRET"))

func main() {
	godotenv.Load()

	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		"localhost", 5432, "postgres", os.Getenv("PASSWORD"), "auth_db")
	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	r := gin.Default()
	r.GET("/auth", func(c *gin.Context) { GenerateTokens(c, db) })
	r.POST("/refresh", func(c *gin.Context) { RefreshTokens(c, db) })
	r.Run(":8080")
}

func GenerateTokens(c *gin.Context, db *sql.DB) {
	userID := c.Query("user_id")
	if userID == "" {
		c.JSON(400, gin.H{"error": "user_id is required"})
		return
	}

	accessToken, err := GenerateAccessToken(userID, c.ClientIP())
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	refreshToken := GenerateRefreshToken()
	refreshHash, _ := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)

	_, err = db.Exec(`INSERT INTO refresh_tokens (token_hash, access_token_id, ip_address)
        VALUES ($1, $2, $3)`,
		refreshHash, accessTokenID, c.ClientIP())
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
	accessTokenID++
}

func GenerateAccessToken(userID, ip string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"user_id": userID,
		"ip":      ip,
		"id":      accessTokenID,
	})
	return token.SignedString(secretKey)
}

func GenerateRefreshToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func RefreshTokens(c *gin.Context, db *sql.DB) {
	var body struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	err := c.BindJSON(&body)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	token, err := jwt.Parse(body.AccessToken, func(t *jwt.Token) (interface{}, error) {
		_, ok := t.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return secretKey, nil
	})
	if err != nil || !token.Valid {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	claims := token.Claims.(jwt.MapClaims)
	userID := claims["user_id"].(string)
	oldIP := claims["ip"].(string)
	tokenIDFloat := claims["id"].(float64)
	tokenID := int(tokenIDFloat)

	refreshToken := []byte(body.RefreshToken)
	var storedHash string
	err = db.QueryRow(`
        SELECT token_hash FROM refresh_tokens 
        WHERE ip_address = $1 AND access_token_id = $2`,
		oldIP, tokenID,
	).Scan(&storedHash)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedHash), refreshToken)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// 3. Проверка IP
	currentIP := c.ClientIP()
	if oldIP != currentIP {
		log.Printf("Warning: IP changed from %s to %s for user %s", oldIP, currentIP, userID)
		log.Printf("[Sending email warning to user]")
	}

	newAccessToken, err := GenerateAccessToken(userID, currentIP)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	newRefreshToken := GenerateRefreshToken()
	newRefreshHash, _ := bcrypt.GenerateFromPassword([]byte(newRefreshToken), bcrypt.DefaultCost)

	_, err = db.Exec(`DELETE FROM refresh_tokens  WHERE token_hash = $1`,
		storedHash)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	_, err = db.Exec(`INSERT INTO refresh_tokens (token_hash, access_token_id, ip_address)
        VALUES ($1, $2, $3)`,
		newRefreshHash, accessTokenID, currentIP)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{
		"access_token":  newAccessToken,
		"refresh_token": newRefreshToken,
	})
	accessTokenID++
}
