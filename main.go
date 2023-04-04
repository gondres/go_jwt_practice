package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var SECRET = []byte("super-secret-auth-key")
var api_key = "1234"

func GetJWT(w http.ResponseWriter, r *http.Request) {
	if r.Header["Access"] != nil {
		if r.Header["Access"][0] == api_key {
			token, err := CreateJWT()
			if err != nil {
				fmt.Printf("error creating JWT")
				return
			}

			fmt.Fprint(w, token)
		} else {
			fmt.Fprintf(w, "error creating JWT")
			return
		}
	} else {
		fmt.Fprintf(w, "error creating JWT")
		return
	}
}
func Home(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, " super secret area")
}

func ValidateJWT(next func(w http.ResponseWriter, r *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header["Token"] != nil {
			token, err := jwt.Parse(r.Header["Token"][0], func(t *jwt.Token) (interface{}, error) {
				_, ok := t.Method.(*jwt.SigningMethodHMAC)
				if !ok {
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte("not authorized"))
				}
				return SECRET, nil
			})
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("not authorized: " + err.Error()))
				return
			}
			if token.Valid {
				next(w, r)
			} else {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("not authorized"))
			}
		} else {
			fmt.Fprintf(w, "Token is needed")
		}
	})
}

func CreateJWT() (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)

	claims["exp"] = time.Now().Add(time.Hour).Unix()

	tokenStr, err := token.SignedString(SECRET)

	if err != nil {
		fmt.Println(err.Error())
		return "Error build", err
	}

	return tokenStr, nil
}

func main() {

	http.Handle("/api", ValidateJWT(Home))
	http.HandleFunc("/jwt", GetJWT)
	http.ListenAndServe(":3500", nil)
}
