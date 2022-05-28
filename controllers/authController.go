package controllers

import (
	"go-auth/database"
	"go-auth/models"
	"net/http"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/crypto/bcrypt"
)

var jwtKey = []byte("my_secret_key")

type Claims struct {
	jwt.StandardClaims
}

func Register(c *fiber.Ctx) error {
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

	password, _ := bcrypt.GenerateFromPassword([]byte(data["password"]), 14)

	user := models.User{
		FirstName: data["first_name"],
		LastName:  data["last_name"],
		Email:     data["email"],
		Password:  password,
	}

	database.DB.Create(&user)

	return c.JSON(user)
}

func Login(c *fiber.Ctx) error {
	var data map[string]string

	if err := c.BodyParser(&data); err != nil {
		return err
	}

	var user models.User

	database.DB.Where("email = ?", data["email"]).First(&user)

	if user.Id == 0 {
		c.Status(http.StatusNotFound)
		return c.JSON(fiber.Map{
			"message": "User not found",
		})
	}

	if err := bcrypt.CompareHashAndPassword(user.Password, []byte(data["password"])); err != nil {
		c.Status(http.StatusBadRequest)
		return c.JSON(fiber.Map{
			"message": "Password did not match",
		})
	}

	claims := jwt.StandardClaims{
		Issuer:    strconv.Itoa(int(user.Id)),
		ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenstring, err := jwtToken.SignedString(jwtKey)

	if err != nil {
		return c.SendStatus(http.StatusInternalServerError)
	}

	cookie := fiber.Cookie{
		Name:     "jwt",
		Value:    tokenstring,
		Expires:  time.Now().Add(time.Hour * 24),
		HTTPOnly: true,
	}

	c.Cookie(&cookie)

	return c.JSON(fiber.Map{
		"token": tokenstring,
	})
}

func User(c *fiber.Ctx) error {
	cookie := c.Cookies("jwt")

	token, err := jwt.ParseWithClaims(cookie, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		c.Status(http.StatusUnauthorized)
		return c.JSON(fiber.Map{
			"message": "Unauthorized",
		})
	}

	claims := token.Claims.(*Claims)

	id := claims.Issuer

	var user models.User

	database.DB.Where("id = ?", id).First(&user)

	if user.Id == 0 {
		c.Status(http.StatusNotFound)
		return c.JSON(fiber.Map{
			"message": "User not found",
		})
	}

	return c.JSON(user)
}

func Logout(c *fiber.Ctx) error {
	cookie := fiber.Cookie{
		Name:     "jwt",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HTTPOnly: true,
	}

	c.Cookie(&cookie)

	return c.JSON(fiber.Map{
		"message": "Logged out successfully",
	})
}
