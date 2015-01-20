package bro

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

type UserSignup struct {
	Username *string
	Phone    *string
	Password *string
}

type HttpMethod string

const (
	GET    HttpMethod = "GET"
	POST   HttpMethod = "POST"
	PUT    HttpMethod = "PUT"
	DELETE HttpMethod = "DELETE"
)

type ApiRequest struct {
	CurrentUser *datastore.Key
	Context     appengine.Context
	*http.Request
}

func authUser(r *ApiRequest) (*datastore.Key, error) {
	if token, ok := r.Header["X-Bro-Token"]; ok {
		q := datastore.NewQuery("DEVICE").
			Filter("Token =", token[0])

		var devices []Device
		keys, err := q.GetAll(r.Context, &devices)
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

type Handler struct {
	Method         HttpMethod
	Auth           bool
	HandleFunction func(http.ResponseWriter, *ApiRequest)
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != string(h.Method) {
		http.Error(w, "GTFO BRO!", http.StatusForbidden)
		return
	}

	apiRequest := &ApiRequest{nil, appengine.NewContext(r), r}
	if h.Auth {
		var err error
		if apiRequest.CurrentUser, err = authUser(apiRequest); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
	}
	h.HandleFunction(w, apiRequest)
}

func init() {
	http.Handle("/sign_up", Handler{POST, false, signUp})
	http.Handle("/sign_in", Handler{POST, false, signIn})
	http.Handle("/find_friends", Handler{POST, true, findFriends})
	http.Handle("/add_friend", Handler{POST, true, addFriend})
	http.Handle("/friends", Handler{GET, true, getFriends})
	http.Handle("/bro", Handler{POST, true, sendBro})
}

func JsonDecode(r *ApiRequest, v interface{}) error {
	decoder := json.NewDecoder(r.Body)
	return decoder.Decode(v)
}

func signUp(w http.ResponseWriter, r *ApiRequest) {

	var newUser UserSignup
	if err := JsonDecode(r, &newUser); err != nil {
		http.Error(w, "INVALID JSON, BRO!", http.StatusBadRequest)
		return
	}

	if newUser.Password == nil {
		http.Error(w, "Password Required", http.StatusUnauthorized)
	}

	pwHash, err := bcrypt.GenerateFromPassword([]byte(*newUser.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	user := User{
		Username: *newUser.Username,
		Phone:    *newUser.Phone,
		Passhash: string(pwHash),
	}

	userKey := datastore.NewKey(r.Context, "USER", user.Username, 0, nil)
	_, err = datastore.Put(r.Context, userKey, &user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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

func (device *Device) sendBro() error {
	return nil
}

func signIn(w http.ResponseWriter, r *ApiRequest) {

	var signInData SignInData
	if err := JsonDecode(r, &signInData); err != nil {
		http.Error(w, "INVALID JSON, BRO!", http.StatusBadRequest)
		return
	}

	userKey := datastore.NewKey(r.Context, "USER", *signInData.Username, 0, nil)

	var user User
	if err := datastore.Get(r.Context, userKey, &user); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Passhash), []byte(*signInData.Password)); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	deviceKey := datastore.NewKey(r.Context, "DEVICE", *signInData.DeviceId, 0, userKey)

	device := Device{
		Id:    *signInData.DeviceId,
		Type:  *signInData.DeviceType,
		Token: pseudo_uuid(),
	}

	if _, err := datastore.Put(r.Context, deviceKey, &device); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Fprint(w, device)
}

func findFriends(w http.ResponseWriter, r *ApiRequest) {
	type FindFriendsData struct {
		PhoneNumbers []string `json:"phone_numbers"`
	}

	var findFriendsData FindFriendsData

	if err := JsonDecode(r, &findFriendsData); err != nil {
		http.Error(w, "INVALID JSON, BRO!", http.StatusBadRequest)
		return
	}

	friends := make(map[string]string)
	for _, phoneNumber := range findFriendsData.PhoneNumbers {
		q := datastore.NewQuery("USER").
			Filter("Phone =", phoneNumber)

		var matches []User
		if _, err := q.GetAll(r.Context, &matches); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if len(matches) != 0 {
			friends[matches[0].Phone] = matches[0].Username
		}
	}

	encodedFriends, err := json.Marshal(friends)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Fprint(w, string(encodedFriends))
}

type Friend struct {
	Username string
	Key      *datastore.Key
}

func addFriend(w http.ResponseWriter, r *ApiRequest) {
	var friend Friend
	if err := JsonDecode(r, &friend); err != nil {
		http.Error(w, "INVALID JSON, BRO!", http.StatusBadRequest)
		return
	}

	//TODO: Prolly should verify the friend exists
	friend.Key = datastore.NewKey(r.Context, "USER", friend.Username, 0, nil)
	friendKey := datastore.NewKey(r.Context, "FRIEND", friend.Username, 0, r.CurrentUser)

	if _, err := datastore.Put(r.Context, friendKey, &friend); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func getFriends(w http.ResponseWriter, r *ApiRequest) {
	q := datastore.NewQuery("FRIEND").
		Ancestor(r.CurrentUser).Order("Username")

	var friends []Friend
	if _, err := q.GetAll(r.Context, &friends); err != nil {
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
}

func sendBro(w http.ResponseWriter, r *ApiRequest) {
	var friend Friend
	if err := JsonDecode(r, &friend); err != nil {
		http.Error(w, "INVALID JSON, BRO!", http.StatusBadRequest)
		return
	}

	friendKey := datastore.NewKey(r.Context, "USER", friend.Username, 0, nil)

	q := datastore.NewQuery("DEVICE").
		Ancestor(friendKey)

	var devices []Device
	if _, err := q.GetAll(r.Context, &devices); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	for _, device := range devices {
		if err := device.sendBro(); err != nil {
			//Just eat the error right now
		}
	}
}

func pseudo_uuid() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		fmt.Println("Error: ", err)
		return ""
	}

	return fmt.Sprintf("%X", b)
}