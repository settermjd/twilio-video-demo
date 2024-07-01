package helper

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func GenerateToken(roomName string) (string, string) {
	zoomKey := os.Getenv("ZOOM_VIDEO_SDK_KEY")
	zoomSecret := os.Getenv("ZOOM_VIDEO_SDK_SECRET")
	currentTime := time.Now().Unix()
	tokenTTL, _ := strconv.ParseInt(os.Getenv("TOKEN_TTL"), 10, 0)
	expiry := currentTime + tokenTTL
	userIdentity := identity()

	token := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		jwt.MapClaims{
			"app_key":       zoomKey,
			"role_type":     1,
			"version":       1,
			"tpc":           roomName,
			"user_identity": userIdentity,
			"iat":           currentTime,
			"nbf":           currentTime,
			"exp":           expiry,
		},
	)

	jwtToken, err := token.SignedString([]byte(zoomSecret))
	if err != nil {
		fmt.Println(err)
	}

	return jwtToken, userIdentity
}

func identity() string {
	input, _ := rand.Prime(rand.Reader, 128)
	hash := md5.Sum([]byte(input.String()))
	return hex.EncodeToString(hash[:])
}
