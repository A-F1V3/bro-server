package hello

import (
	"crypto/rand"
	"encoding/json"
	"errors"
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
	http.HandleFunc("/find_friends", findFriends)
	http.HandleFunc("/add_friend", addFriend)
	http.HandleFunc("/friends", getFriends)
	http.HandleFunc("/bro", sendBro)
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

type FindFriendsData struct {
	PhoneNumbers []string `json:"phone_numbers"`
}

func findFriends(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		_, err := authUser(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		jsonDecoder := json.NewDecoder(r.Body)
		var findFriendsData FindFriendsData
		err = jsonDecoder.Decode(&findFriendsData)
		if err != nil {
			http.Error(w, "INVALID JSON, BRO!", http.StatusBadRequest)
			return
		}

		c := appengine.NewContext(r)
		friends := make(map[string]string)
		for _, phoneNumber := range findFriendsData.PhoneNumbers {
			q := datastore.NewQuery("USER").
				Filter("Phone =", phoneNumber)
			var matches []User
			_, err := q.GetAll(c, &matches)
			if err != nil {
				http.Error(w, "OH SHIT", http.StatusInternalServerError)
			}
			if len(matches) != 0 {
				friends[matches[0].Phone] = matches[0].Username
			}
		}

		encodedFriends, _ := json.Marshal(friends)
		fmt.Fprint(w, string(encodedFriends))
	} else {
		http.Error(w, "GTFO BRO!", http.StatusForbidden)
	}
}

type Friend struct {
	Username string
	Key      *datastore.Key
}

func addFriend(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		currentUser, err := authUser(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		var friend Friend
		jsonDecoder := json.NewDecoder(r.Body)
		err = jsonDecoder.Decode(&friend)
		if err != nil {
			http.Error(w, "INVALID JSON, BRO!", http.StatusBadRequest)
			return
		}

		//TODO: Prolly should verify the friend exists
		c := appengine.NewContext(r)
		friend.Key = datastore.NewKey(c, "USER", friend.Username, 0, nil)
		friendKey := datastore.NewKey(c, "FRIEND", friend.Username, 0, currentUser)

		_, err = datastore.Put(c, friendKey, &friend)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	} else {
		http.Error(w, "GTFO BRO!", http.StatusForbidden)
	}
}

func getFriends(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		currentUser, err := authUser(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		c := appengine.NewContext(r)
		q := datastore.NewQuery("FRIEND").
			Ancestor(currentUser).Order("Username")
		var friends []Friend
		_, err = q.GetAll(c, &friends)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		friendResponse := struct {
			Friends []string
		}{
			make([]string, len(friends)),
		}

		for i, friend := range friends {
			friendResponse.Friends[i] = friend.Username
		}

		encodedFriends, err := json.Marshal(friendResponse)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		fmt.Fprint(w, string(encodedFriends))

	} else {
		http.Error(w, "GTFO BRO!", http.StatusForbidden)
	}
}

func sendBro(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		_, err := authUser(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		var friend Friend
		jsonDecoder := json.NewDecoder(r.Body)
		err = jsonDecoder.Decode(&friend)
		if err != nil {
			http.Error(w, "INVALID JSON, BRO!", http.StatusBadRequest)
			return
		}

		c := appengine.NewContext(r)

		friendKey := datastore.NewKey(c, "USER", friend.Username, 0, nil)

		// if err = datastore.Get(c, friendKey, &friend); err != nil {
		// 	http.Error(w, err.Error(), http.StatusInternalServerError)
		// 	return
		// }

		q := datastore.NewQuery("DEVICE").
			Ancestor(friendKey)
		var devices []Device
		_, err = q.GetAll(c, &devices)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		fmt.Fprint(w, devices)
		//TODO: SEND BRO TO DEVICES

	} else {
		http.Error(w, "GTFO BRO!", http.StatusForbidden)
	}
}

func authUser(r *http.Request) (*datastore.Key, error) {
	if token, ok := r.Header["X-Bro-Token"]; ok {
		c := appengine.NewContext(r)
		q := datastore.NewQuery("DEVICE").
			Filter("Token =", token[0])
		var devices []Device
		keys, err := q.GetAll(c, &devices)
		if err != nil {
			return nil, err
		}

		if len(keys) == 0 {
			return nil, errors.New("GTFO: Unknown Token")
		}
		return keys[0].Parent(), nil
	}

	return nil, errors.New("GTFO: Missing header")
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
