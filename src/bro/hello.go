package hello

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	"appengine"
	"appengine/datastore"
)

type User struct {
	Username string
	Phone    string
	Passhash string
}

type NewUser struct {
	Username *string
	Phone    *string
	Password *string
}

func init() {
	http.HandleFunc("/sign_up", signUp)
	http.HandleFunc("/sign_in", signIn)
}

func signUp(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		jsonDecoder := json.NewDecoder(r.Body)
		var newUser NewUser
		err := jsonDecoder.Decode(&newUser)
		if err != nil {
			http.Error(w, "INVALID JSON, BRO!", http.StatusBadRequest)
			return
		}

		var pwHash []byte
		if newUser.Password != nil {
			pwHash, _ = bcrypt.GenerateFromPassword([]byte(*newUser.Password), bcrypt.DefaultCost)
		}

		user := User{
			Username: *newUser.Username,
			Phone:    *newUser.Phone,
			Passhash: string(pwHash),
		}

		c := appengine.NewContext(r)
		userKey := datastore.NewKey(c, "USER", user.Username, 0, nil)
		_, err = datastore.Put(c, userKey, &user)
		if err != nil {
			http.Error(w, "Oh Noes", http.StatusInternalServerError)
			return
		}
	} else {
		http.Error(w, "GTFO BRO!", http.StatusForbidden)
	}
}

type SignInData struct {
	Username   *string
	Password   *string
	DeviceId   *string `json:"device_id"`
	DeviceType *string `json:"device_type"`
}

type Device struct {
	Id    string
	Type  string
	Token string
}

func signIn(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		jsonDecoder := json.NewDecoder(r.Body)
		var signInData SignInData
		err := jsonDecoder.Decode(&signInData)
		if err != nil {
			http.Error(w, "INVALID JSON, BRO!", http.StatusBadRequest)
			return
		}

		c := appengine.NewContext(r)
		var user User
		userKey := datastore.NewKey(c, "USER", *signInData.Username, 0, nil)
		if err = datastore.Get(c, userKey, &user); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if err = bcrypt.CompareHashAndPassword([]byte(user.Passhash), []byte(*signInData.Password)); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		deviceKey := datastore.NewKey(c, "DEVICE", *signInData.DeviceId, 0, userKey)
		device := Device{
			Id:    *signInData.DeviceId,
			Type:  *signInData.DeviceType,
			Token: pseudo_uuid(),
		}
		if _, err = datastore.Put(c, deviceKey, &device); err != nil {
			http.Error(w, "Oh Noes", http.StatusInternalServerError)
			return
		}

		fmt.Fprint(w, device)
	} else {
		http.Error(w, "GTFO BRO!", http.StatusForbidden)
	}
}

func pseudo_uuid() string {

	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		fmt.Println("Error: ", err)
		return ""
	}

	return fmt.Sprintf("%X", b)
}
