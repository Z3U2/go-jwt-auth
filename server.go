package main

import (
	"context"
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
)

//login
type login struct {
	Email    string
	Password string
}

// DATABASE

func dbConn() (db *sql.DB) {
	db, err := sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/gestion_commande")
	err = db.Ping() //theoriquement ça envoie une erreur si la bd est innaccessible
	if err != nil {
		panic(err.Error())
		fmt.Println("echec de connection à la bd ")

	}
	//fmt.Println("connection à la bd réussie")
	return db
}

var db = dbConn()

var secret = []byte("my_super_awesome_secret_key") // This is your secret key, change it to something more secret like

var tpl *template.Template

//PROCESS
func init() {
	tpl = template.Must(template.ParseGlob("templates/*.html"))
}

func main() {
	http.HandleFunc("/", ValidateUser(handleIndex))
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/logout", ValidateUser(handleLogout))
	log.Fatal(http.ListenAndServe(":8080", nil))
	defer db.Close()
}

// ROUTES
func handleIndex(w http.ResponseWriter, r *http.Request) {
	u := r.Context().Value("user")
	tpl.ExecuteTemplate(w, "logged.html", u)
	return
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		tpl.ExecuteTemplate(w, "login.html", nil)
		return

	case http.MethodPost:
		fn := r.FormValue("Email")
		fp := r.FormValue("Password")
		//	fmt.Println(fn, fp)

		auth, err := db.Query("SELECT Email , Password FROM users WHERE Email=? AND Password=?", fn, fp)

		if err != nil {

			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		u := login{}

		for auth.Next() {
			var Email string
			var Password string
			err = auth.Scan(&Email, &Password)
			if err != nil {
				panic(err.Error())
			}
			u.Email = Email
			u.Password = Password
			fmt.Println(Email)
			fmt.Println(Password)
		}
		//	tpl.ExecuteTemplate(w, "logged.html", u)

		tokenString := CreateToken(u)

		http.SetCookie(w, &http.Cookie{
			Name:     "sessionToken",
			Value:    tokenString,
			HttpOnly: true,
		})

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return

	default:
		http.Error(w, http.StatusText(http.StatusNotImplemented), http.StatusNotImplemented)
		return
	}
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		tpl.ExecuteTemplate(w, "logout.html", nil)
		return

	case http.MethodPost:

		http.SetCookie(w, &http.Cookie{
			Name:   "sessionToken",
			MaxAge: -1,
		})

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return

	default:
		http.Error(w, http.StatusText(http.StatusNotImplemented), http.StatusNotImplemented)
		return
	}
}

// MIDDLEWARE
func ValidateUser(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("sessionToken")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		u := ReadToken(c.Value)

		ctx := context.WithValue(r.Context(), "user", u)
		r = r.WithContext(ctx)

		h(w, r)
	}
}

// Creates Token
func CreateToken(u login) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"Email":    u.Email,
		"Password": u.Password,
	})
	tokenString, err := token.SignedString(secret)
	if err != nil {
		fmt.Println(err)
	}
	return tokenString
}

// Reads Token
func ReadToken(tokenString string) login {
	token, err := jwt.Parse(tokenString, ReturnKey)
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		fmt.Println("Error getting claims")
	}
	if err != nil {
		fmt.Println(err)
	}
	return login{Email: claims["Email"].(string), Password: claims["Password"].(string)}

}

// Function passed to jwt.Parse
func ReturnKey(token *jwt.Token) (interface{}, error) {
	return secret, nil
}
