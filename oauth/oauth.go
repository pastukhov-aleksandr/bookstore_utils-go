package oauth

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/pastukhov-aleksandr/bookstore_utils-go/rest_errors"
	"github.com/pastukhov-aleksandr/bookstore_utils-go/secret_code"
)

const (
	paramAccessToken = "access_token"
)

type AccessDetails struct {
	UserID   uint64
	ClientID uint64
}

func AuthenticateRequest(request *http.Request) (*AccessDetails, rest_errors.RestErr) {
	if request == nil {
		return nil, rest_errors.NewUnauthorizedError("unauthorized")
	}

	tokenAuth, err := extractTokenMetadata(request)
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

func verifyToken(r *http.Request) (*jwt.Token, error) {
	tokenString := extractToken(r)
	accessSicret := secret_code.Get_ACCESS_SECRET()
	if accessSicret == "" {
		return nil, fmt.Errorf("invalid env file")
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(accessSicret), nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

func tokenValid(r *http.Request) error {
	token, err := verifyToken(r)
	if err != nil {
		return err
	}
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		return err
	}
	return nil
}

func extractTokenMetadata(r *http.Request) (*AccessDetails, error) {
	token, err := verifyToken(r)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		userId, err := strconv.ParseUint(fmt.Sprintf("%.f", claims["user_id"]), 10, 64)
		if err != nil {
			return nil, err
		}
		clientId, err := strconv.ParseUint(fmt.Sprintf("%.f", claims["client_id"]), 10, 64)
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
