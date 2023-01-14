package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

type ValidateResult struct {
	Valid  bool `json:"success"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

func sanitize(expression string) string {
	return strings.ReplaceAll(expression, " ", "")
}

func Validate(expression string) error {
	expression = sanitize(expression)
	req, err := http.NewRequest("GET", fmt.Sprintf("https://api.cloudflare.com/client/v4/filters/validate-expr?expression=%s", expression), nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", os.Getenv("CLOUDFLARE_API_TOKEN")))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()
	var v ValidateResult
	b, _ := io.ReadAll(resp.Body)
	json.Unmarshal(b, &v)
	if v.Valid {
		return nil
	}

	out := make([]string, 0, 0)
	for _, e := range v.Errors {
		out = append(out, e.Message)
	}

	return errors.New(strings.Join(out, "\n"))
}

func main() {
	if len(os.Args) > 1 {
		err := Validate(os.Args[1])
		if err != nil {
			log.Fatal(err)
		}
		os.Exit(0)
	}
	log.Fatal("Please provide expression to validate")
}
