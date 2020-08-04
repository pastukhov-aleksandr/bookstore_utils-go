package oauth

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/pastukhov-aleksandr/bookstore_utils-go/rest_errors"
	"github.com/pastukhov-aleksandr/bookstore_utils-go/secret_code"
)

const (
	paramAccessToken = "access_token"
)

type AccessDetails struct {
	UserID   int64
	ClientID int64
}

func TokenAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		err := tokenValid(c.Request, secret_code.Get_ACCESS_SECRET())
		if err != nil {
			c.JSON(http.StatusUnauthorized, err.Error())
			c.Abort()
			return
		}
		c.Next()
	}
}

func TokenRefreshMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		err := tokenValid(c.Request, secret_code.Get_REFRESH_SECRET())
		if err != nil {
			c.JSON(http.StatusUnauthorized, err.Error())
			c.Abort()
			return
		}
		c.Next()
	}
}

func AuthenticateRequest(request *http.Request, secretCode string) (*AccessDetails, rest_errors.RestErr) {
	if request == nil {
		return nil, rest_errors.NewUnauthorizedError("unauthorized")
	}

	tokenString := extractToken(request)
	tokenAuth, err := ExtractTokenMetadata(tokenString, secretCode)
	if err != nil {
		return nil, rest_errors.NewUnauthorizedError("unauthorized")
	}

	return tokenAuth, nil
}

func extractToken(r *http.Request) string {
	bearToken := r.Header.Get("Authorization")
	//normally Authorization the_token_xxx
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}
	return ""
}

func verifyToken(tokenString string, secretCode string) (*jwt.Token, error) {
	if secretCode == "" {
		return nil, fmt.Errorf("invalid env file")
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secretCode), nil
	})

	if err != nil {
		return nil, err
	}
	return token, nil
}

func tokenValid(r *http.Request, secretCode string) error {
	tokenString := extractToken(r)
	token, err := verifyToken(tokenString, secretCode)

	if err != nil {
		return err
	}
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		return err
	}
	return nil
}

func ExtractTokenMetadata(tokenString string, secretCode string) (*AccessDetails, error) {
	token, err := verifyToken(tokenString, secretCode)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)

	if ok && token.Valid {
		userId, err := strconv.ParseInt(fmt.Sprintf("%.f", claims["user_id"]), 10, 64)
		if err != nil {
			return nil, err
		}
		clientId, err := strconv.ParseInt(fmt.Sprintf("%.f", claims["client_id"]), 10, 64)
		if err != nil {
			return nil, err
		}
		return &AccessDetails{
			UserID:   userId,
			ClientID: clientId,
		}, nil
	}
	return nil, fmt.Errorf("token not valid")
}
