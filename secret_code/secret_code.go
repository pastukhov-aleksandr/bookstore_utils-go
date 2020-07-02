package secret_code

import (
	"github.com/joho/godotenv"
	"github.com/pastukhov-aleksandr/bookstore_utils-go/getenv"
)

const (
	ACCESS_SECRET  = "ACCESS_SECRET"
	REFRESH_SECRET = "REFRESH_SECRET"
)

func init() {
	if err := godotenv.Load(); err != nil {
		panic("invalid env file load")
	}
}

func Get_ACCESS_SECRET() string {
	return getenv.GetEnv(ACCESS_SECRET, "")
}

func Get_REFRESH_SECRET() string {
	return getenv.GetEnv(REFRESH_SECRET, "")
}
