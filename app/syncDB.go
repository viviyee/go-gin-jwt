package app

import "github.com/viviyee/go-jwt/models"

func SyncDatabase() {
	DB.AutoMigrate(&models.User{})
}
