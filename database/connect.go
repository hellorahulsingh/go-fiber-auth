package database

import (
	"go-auth/models"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func Connect() {
	dsn := "host=localhost user=apple password=iamrahul dbname=postgres port=5432 sslmode=disable TimeZone=Asia/Kolkata"
	connection, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})

	if err != nil {
		panic("failed to connect database")
	}

	DB = connection

	connection.AutoMigrate(models.User{}, models.PasswordReset{})
}
