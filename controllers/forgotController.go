package controllers

import (
	"go-auth/database"
	"go-auth/models"
	"go-auth/services"
	"net/http"
	"net/smtp"

	"github.com/gofiber/fiber/v2"
	"golang.org/x/crypto/bcrypt"
)

func Forgot(c *fiber.Ctx) error {
	var data map[string]string

	if err := c.BodyParser(&data); err != nil {
		return err
	}

	token := services.RandStringRunes(12)

	passwordReset := models.PasswordReset{
		Email: data["email"],
		Token: token,
	}

	database.DB.Create(&passwordReset)

	from := "admin@email.com"
	to := []string{
		data["email"],
	}
	url := "http://localhost:8000/reset/" + token
	message := []byte("click <a href=\"" + url + "\">here</a> to reset your password")

	err := smtp.SendMail("0.0.0.0:1025", nil, from, to, message)

	if err != nil {
		c.SendStatus(http.StatusInternalServerError)
	}

	return c.JSON(fiber.Map{
		"message": "Email sent to reset password",
	})

}

func Reset(c *fiber.Ctx) error {
	var data map[string]string

	if err := c.BodyParser(&data); err != nil {
		return err
	}

	if data["password"] != data["confirm_password"] {
		c.Status(http.StatusBadRequest)
		return c.JSON(fiber.Map{
			"message": "Passwords did not match",
		})
	}

	var passwordReset = models.PasswordReset{}

	if err := database.DB.Where("token = ?", data["token"]).Last(&passwordReset); err.Error != nil {
		c.Status(http.StatusBadRequest)
		return c.JSON(fiber.Map{
			"message": "Invalid Token",
		})
	}

	password, _ := bcrypt.GenerateFromPassword([]byte(data["password"]), 14)

	database.DB.Model(&models.User{}).Where("email = ?", passwordReset.Email).Update("password", password)

	return c.JSON(fiber.Map{
		"message": "Password reset successful",
	})
}
