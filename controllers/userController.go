package controllers

import (
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/viviyee/go-jwt/app"
	"github.com/viviyee/go-jwt/models"
	"golang.org/x/crypto/bcrypt"
)

type req struct {
	Email    string
	Password string
}

func Signup(c *gin.Context) {
	var data req
	c.Bind(&data)

	// hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(data.Password), 10)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to hash password",
		})
		return
	}

	// create user
	user := models.User{
		Email:    data.Email,
		Password: string(hash),
	}
	result := app.DB.Create(&user) // pass pointer of data to Create

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create user",
		})
		return
	}

	c.JSON(http.StatusCreated, user)
}

func Login(c *gin.Context) {
	var data req
	c.Bind(&data)

	// find user
	var user models.User
	app.DB.First(&user, "email = ?", data.Email)

	if user.ID == 0 {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "User not found",
		})
		return
	}

	// compare hash and password
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(data.Password))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Wrong password",
		})
		return
	}

	// Create a new token object, specifying signing method and the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(os.Getenv("HMAC_SECRET")))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Error creating token",
		})
		// panic(err)
		return
	}

	// send tokenString
	// c.JSON(http.StatusAccepted, gin.H{
	// 	"token": tokenString,
	// })

	// set cookie
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization", tokenString, 3600, "", "", false, true)
	c.JSON(http.StatusOK, gin.H{
		"loggedIn": true,
		"now":      time.Now(),
	})
}

func Validate(c *gin.Context) {
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"loggedIn": true,
		"user":     user,
	})
}
