package auth

import (
	"errors"
	"net/url"
)

var validTokens = map[string]bool{
	"25tnt3446h": true,
}

func IsTokenValid(token string) bool {
	return validTokens[token]
}

func ExtractTokenFromURL(urlStr string) (string, error) {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return "", err
	}
	token := parsed.Query().Get("token")
	if token == "" {
		return "", errors.New("no token found in URL")
	}
	return token, nil
}
