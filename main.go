package main

import (
	"github.com/gin-gonic/gin"
	"github.com/viviyee/go-jwt/app"
	"github.com/viviyee/go-jwt/controllers"
	"github.com/viviyee/go-jwt/middleware"
)

func init() {
	app.LoadEnv()
	app.Database()
	app.SyncDatabase()
}

func main() {
	r := gin.Default()

	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})
	r.POST("/signup", controllers.Signup)
	r.POST("/login", controllers.Login)

	r.GET("/validate", middleware.Auth, controllers.Validate)

	r.Run() // listen and serve on 0.0.0.0:8080
}
