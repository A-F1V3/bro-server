package bro

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"appengine"
	"appengine/datastore"

	apns "github.com/anachronistic/apns"
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
	CurrentUserKey  *datastore.Key
	CurrentUser 	*User
	Context     	appengine.Context
	*http.Request
}

func authUser(r *ApiRequest) (error) {
	r.Context.Debugf("Authing")
	if token, ok := r.Header["X-Bro-Token"]; ok {
		r.Context.Debugf("Got a bro token: " + token[0])
		q := datastore.NewQuery("DEVICE").Filter("Token =", token[0])

		var devices []Device
		keys, err := q.GetAll(r.Context, &devices)

		if err != nil {
			r.Context.Debugf("Failed to get devices")
			return err
		}

		if len(keys) == 0 {
			r.Context.Debugf("Unknown token")
			return errors.New("GTFO: Unknown Token")
		}

		var user User
		if err := datastore.Get(r.Context, keys[0].Parent(), &user); err != nil {
			r.Context.Debugf("Failed to load device")
			return err
		}

		r.CurrentUser = &user
		r.CurrentUserKey = keys[0].Parent()

		return nil
	}

	r.Context.Debugf("Missing bro token")

	return errors.New("GTFO: Missing header")
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

	apiRequest := &ApiRequest{nil, nil, appengine.NewContext(r), r}

	if h.Auth {
		var err error
		if err = authUser(apiRequest); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
	}
	h.HandleFunction(w, apiRequest)
}

func init() {
	http.Handle("/", Handler{GET, false, homePage})
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

func homePage(w http.ResponseWriter, r *ApiRequest) {
	fmt.Fprint(w, "<html><body><p>Hello, world!</p></body></html>")
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
		Passhash: string(pwHash),
	}

	if newUser.Phone == nil {
		user.Phone = ""
	} else {
		user.Phone = *newUser.Phone
	}

	userKey := datastore.NewKey(r.Context, "USER", user.Username, 0, nil)
	if _, err = datastore.Put(r.Context, userKey, &user); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	result := make(map[string]string)
	result["success"] = "true"
	var encodedResult []byte
	encodedResult, err = json.Marshal(result)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Fprint(w, string(encodedResult))
}

type SignInData struct {
	Username   *string
	Password   *string
	DeviceId   *string `json:"device_id"`
	DeviceType *string `json:"device_type"`
	PushToken  *string `json:"push_token"`
}

type Device struct {
	Id    		string
	Type  		string
	Token 		string // Our own internal login token
	PushToken 	string // Used for sending push notifications
}

type TokenResponse struct {
	Token string	`json:"token"`
}

func (device *Device) sendBro(r *ApiRequest) error {

	payload := apns.NewPayload()
	payload.Alert = "Hello, world!"

	pn := apns.NewPushNotification()
	pn.DeviceToken = device.PushToken
	pn.AddPayload(payload)

	client := apns.NewClient("gateway.sandbox.push.apple.com:2195", "cert.pem", "key.pem")
	resp := client.Send(pn)

	alert, _ := pn.PayloadString()
	r.Context.Debugf("  Alert:", alert)
	r.Context.Debugf("Success:", resp.Success)
	r.Context.Debugf("  Error:", resp.Error)

	return nil
}

func signIn(w http.ResponseWriter, r *ApiRequest) {

	var signInData SignInData
	if err := JsonDecode(r, &signInData); err != nil {
		http.Error(w, "INVALID JSON, BRO!", http.StatusBadRequest)
		return
	}

	r.Context.Debugf("Username: " + *signInData.Username)

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

	var push_token string
	if signInData.PushToken == nil {
		push_token = ""
	} else {
		push_token = *signInData.PushToken
	}

	device := Device{
		Id:    *signInData.DeviceId,
		Type:  *signInData.DeviceType,
		Token: pseudo_uuid(),
		PushToken: push_token,
	}

	if _, err := datastore.Put(r.Context, deviceKey, &device); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// XXX: Workaround to ensure device is applied before returning
	// TODO: Investigate is transactions would fix this
	var newDevice Device
	if err := datastore.Get(r.Context, deviceKey, &newDevice); err != nil {
		r.Context.Debugf("Datastore doesn't see devicekey, weird")
	}

	tokenResponse := TokenResponse {
		Token: device.Token,
	}

	encodedToken, err := json.Marshal(tokenResponse)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	r.Context.Debugf(string(encodedToken))
	fmt.Fprint(w, string(encodedToken))
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
	var newFriend Friend
	if err := JsonDecode(r, &newFriend); err != nil {
		http.Error(w, "INVALID JSON, BRO!", http.StatusBadRequest)
		return
	}

	if strings.EqualFold(r.CurrentUser.Username, newFriend.Username) {
		http.Error(w, "Can't be your own bro, bro", http.StatusBadRequest)
		return
	}

	newFriend.Key = datastore.NewKey(r.Context, "USER", newFriend.Username, 0, nil)

	var friendUser User
	if err := datastore.Get(r.Context, newFriend.Key, &friendUser); err != nil {
		if err == datastore.ErrNoSuchEntity {
			http.Error(w, "Friend not found", http.StatusNotFound)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		return
	}

	friendKey := datastore.NewKey(r.Context, "FRIEND", newFriend.Username, 0, r.CurrentUserKey)

	if _, err := datastore.Put(r.Context, friendKey, &newFriend); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func getFriends(w http.ResponseWriter, r *ApiRequest) {
	q := datastore.NewQuery("FRIEND").Ancestor(r.CurrentUserKey).Order("Username")

	var friends []Friend
	if _, err := q.GetAll(r.Context, &friends); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	friendResponse := struct {
		Friends []string	`json:"friends"`
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
		if err := device.sendBro(r); err != nil {
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
