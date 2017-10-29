package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/gorilla/websocket"
	_ "github.com/mattn/go-sqlite3"
)

// const
const SESSION_NAME string = "default"

// variables
var store = sessions.NewCookieStore([]byte("my super duper secret"))
var conn *sql.DB
var templates *template.Template
var logger *log.Logger = log.New(os.Stdout, "APPLOG:", log.Ldate|log.Ltime|log.Lshortfile)
var messageChan chan *Message = make(chan *Message)
var wsChan chan *WebSocketTransport = make(chan *WebSocketTransport)
var upgrader websocket.Upgrader = websocket.Upgrader{}

// init
func db() *sql.DB {
	var err error
	if conn == nil {
		log.Println("Connecting to db")
		conn, err = sql.Open("sqlite3", ":memory:")
		// conn, err = sql.Open("sqlite3", "dev.sqlite")
		if err != nil {
			panic(err)
		}
	}
	return conn
}

// helpers
func encrypt(value string) string {
	h := sha256.New()
	io.WriteString(h, value)
	return string(h.Sum(nil))
}

func current_user(r *http.Request) *User {
	session, err := store.Get(r, SESSION_NAME)
	if err != nil {
		panic(err)
	}
	user_id := session.Values["user_id"]
	user_id64, ok := user_id.(int64)
	if !ok {
		panic(errors.New("Failed to convert user id into int64"))
	}
	user, err := UserRepo(db()).Find(user_id64)
	if err != nil {
		logger.Println(err)
	}
	return user
}

func createSchema(db *sql.DB) {
	if _, err := db.Exec(`
		CREATE TABLE chats ( 
			id INTEGER PRIMARY KEY AUTOINCREMENT, 
			name TEXT UNIQUE 
		)
	`); err != nil {
		panic(err)
	}
	if _, err := db.Exec(`
		CREATE TABLE users ( 
			id INTEGER PRIMARY KEY AUTOINCREMENT, 
			username TEXT UNIQUE, 
			password TEXT NOT NULL 
		)
	`); err != nil {
		panic(err)
	}
	if _, err := db.Exec(`
		CREATE TABLE messages ( 
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			chat_id INTEGER NOT NULL,
			username TEXT NOT NULL,
			body TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`); err != nil {
		panic(err)
	}
}

// models
type Message struct {
	ID        int64
	Body      string
	Username  string
	ChatID    int64
	CreatedAt time.Time
}

type Chat struct {
	ID       int64
	Name     string
	Messages []*Message
}

type User struct {
	ID       int64
	Username string
	Password string
}

func (this *User) HasPassword(password string) bool {
	return this.Password == encrypt(password)
}

// repos
type chatRepo struct {
	db *sql.DB
}

func ChatRepo(db *sql.DB) *chatRepo {
	return &chatRepo{db}
}

func (this *chatRepo) FindAll() ([]*Chat, error) {
	var id int64
	var name string
	var chats []*Chat

	rows, err := this.db.Query("SELECT id, name FROM chats")
	if err != nil {
		return chats, err
	}
	defer rows.Close()
	for rows.Next() {
		err = rows.Scan(&id, &name)
		if err != nil {
			return chats, err
		}
		chats = append(chats, &Chat{ID: id, Name: name})
	}
	return chats, nil
}

func (this *chatRepo) Save(chat *Chat) (*Chat, error) {
	if chat.ID == 0 {
		return this.create(chat)
	} else {
		return this.update(chat)
	}
}

func (this *chatRepo) create(chat *Chat) (*Chat, error) {
	stmt, err := this.db.Prepare("INSERT INTO chats (name) values (?)")
	if err != nil {
		return chat, err
	}
	res, err := stmt.Exec(chat.Name)
	if err != nil {
		return chat, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return chat, err
	}
	chat.ID = id
	return chat, nil
}

func (this *chatRepo) update(chat *Chat) (*Chat, error) {
	stmt, err := this.db.Prepare("UPDATE chats SET name=? WHERE id=?")
	if err != nil {
		return chat, err
	}
	res, err := stmt.Exec(chat.Name, chat.ID)
	if err != nil {
		return chat, err
	}
	affected, err := res.RowsAffected()
	if affected != 1 {
		return chat, errors.New("Failed to update chat")
	}
	return chat, nil
}

func (this *chatRepo) Find(uid int64) (*Chat, error) {
	var chat_name string
	var username string
	var body string
	var message_id int64
	var chat *Chat

	rows, err := this.db.Query(`
		SELECT 
			chats.name as chat_name, 
			messages.id, 
			messages.username, 
			messages.body
		FROM chats 
		LEFT OUTER JOIN messages on messages.chat_id = chats.id 
		WHERE chats.id = ?
		ORDER BY messages.id ASC
	`, uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		rows.Scan(&chat_name, &message_id, &username, &body)
		if chat == nil {
			chat = &Chat{ID: uid, Name: chat_name}
		}
		if &message_id != nil { // there are messages available
			chat.Messages = append(chat.Messages, &Message{
				ID:       message_id,
				Username: username,
				Body:     body,
			})
		}
	}
	return chat, nil
}

type userRepo struct {
	db *sql.DB
}

func UserRepo(db *sql.DB) *userRepo {
	return &userRepo{db}
}

func (this *userRepo) Find(id int64) (*User, error) {
	user := &User{}
	if err := this.db.QueryRow("SELECT id, username, password FROM users WHERE id = ?", id).Scan(&user.ID, &user.Username, &user.Password); err != nil {
		return nil, err
	}
	return user, nil
}

func (this *userRepo) Register(username string, password string) (*User, error) {
	var encryptedPassword string
	stmt, err := this.db.Prepare("INSERT INTO users (username, password) VALUES (?, ?)")
	if err != nil {
		return nil, err
	}
	encryptedPassword = encrypt(password)
	res, err := stmt.Exec(username, encryptedPassword)
	if err != nil {
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	return &User{ID: id, Username: username, Password: encryptedPassword}, nil
}

func (this *userRepo) FindByUsername(username string) (*User, error) {
	user := &User{}
	err := this.db.QueryRow("SELECT id, username, password FROM users WHERE username = ?", username).Scan(&user.ID, &user.Username, &user.Password)
	if err != nil {
		return nil, err
	}
	return user, nil
}

type messageRepo struct {
	db *sql.DB
}

func MessageRepo(db *sql.DB) *messageRepo {
	return &messageRepo{db}
}

func (this *messageRepo) Create(username, body string, chatID int64) (*Message, error) {
	stmt, err := this.db.Prepare("INSERT INTO messages (username, body, chat_id, created_at) VALUES (?, ?, ?, ?)")
	if err != nil {
		return nil, err
	}
	now := time.Now()
	nowFormatted := time.Now().Format(time.RFC3339)
	result, err := stmt.Exec(username, body, chatID, nowFormatted)
	if err != nil {
		return nil, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}
	return &Message{ID: id, Username: username, ChatID: chatID, Body: body, CreatedAt: now}, nil

}

// view models

type Page struct {
	Title   string
	User    *User
	Errors  []error
	Content map[string]interface{}
}

func NewPage(title string) Page {
	content := make(map[string]interface{})
	return Page{Title: title, Content: content}
}

type WebSocketTransport struct {
	Socket *websocket.Conn
	ChatID string
}

// forms

type RegistrationForm struct {
	Username string  `valid:"required,length(4|50),alphanum"`
	Password string  `valid:"required,length(4|50)"`
	Errors   []error `valid:"-"`
}

func (this *RegistrationForm) Submit(username, password string) bool {
	this.Username = username
	this.Password = password
	this.Errors = make([]error, 0)
	if this.isValid() {
		_, err := UserRepo(db()).Register(username, password)
		if err != nil {
			this.Errors = append(this.Errors, err)
			return false
		}
		return true
	} else {
		return false
	}
}

func (this *RegistrationForm) isValid() bool {
	var total int
	_, err := govalidator.ValidateStruct(this)
	if err != nil {
		this.Errors = append(this.Errors, err)
	}
	if err = db().QueryRow("SELECT count(*) as total FROM users WHERE username = ?", this.Username).Scan(&total); err != nil {
		logger.Println("Failed to validate user", err)
		this.Errors = append(this.Errors, errors.New("Problem in validating user."))
	}
	if total > 0 {
		this.Errors = append(this.Errors, errors.New("Username is already taken."))
	}
	return len(this.Errors) == 0
}

type CreateChatForm struct {
	Name   string  `valid:"required,alphanum,length(4|50)"`
	Errors []error `valid:"-"`
	Chat   *Chat   `valid:"-"`
}

func (this *CreateChatForm) Submit(name string) bool {
	this.Errors = make([]error, 0)
	this.Name = name
	if this.isValid() {
		chat := &Chat{Name: this.Name}
		this.Chat = chat
		ChatRepo(db()).Save(chat)
		return true
	} else {
		return false
	}
}

func (this *CreateChatForm) isValid() bool {
	var total int
	_, err := govalidator.ValidateStruct(this)
	if err != nil {
		this.Errors = append(this.Errors, err)
	}
	if err = db().QueryRow("SELECT count(*) as total FROM chats WHERE name = ?", this.Name).Scan(&total); err != nil {
		logger.Println("There was an error in validating chat", err)
		this.Errors = append(this.Errors, errors.New("Problem in validating chat."))
	}

	if total > 0 {
		this.Errors = append(this.Errors, errors.New("Chat name is already taken."))
	}
	return len(this.Errors) == 0
}

type CreateMessageForm struct {
	Username string   `valid:"required"`
	ChatID   int64    `valid:"required"`
	Body     string   `valid:"required,length(1|256)"`
	Errors   []error  `valid:"-"`
	Message  *Message `valid:"-"`
}

func (this *CreateMessageForm) Submit(username string, chatID string, messageBody string) bool {
	this.Errors = make([]error, 0)
	this.Username = username
	this.Body = messageBody
	chatID64, err := strconv.ParseInt(chatID, 10, 64)
	if err != nil {
		this.Errors = append(this.Errors, err)
	} else {
		this.ChatID = chatID64
	}
	if this.isValid() {
		message, err := MessageRepo(db()).Create(username, messageBody, chatID64)
		if err != nil {
			this.Errors = append(this.Errors, err)
			return false
		}
		this.Message = message
		return true
	} else {
		return false
	}
}

func (this *CreateMessageForm) isValid() bool {
	_, err := govalidator.ValidateStruct(this)
	if err != nil {
		this.Errors = append(this.Errors, err)
	}
	return len(this.Errors) == 0
}

// middlewares

func LoginRequired(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, SESSION_NAME)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		user_id := session.Values["user_id"]
		if user_id == nil {
			http.Redirect(w, r, "/login", 301)
			return
		}
		h(w, r)
	}
}

// handlers

func Home(w http.ResponseWriter, r *http.Request) {
	page := NewPage("Home")
	page.User = current_user(r)
	chats, err := ChatRepo(db()).FindAll()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	page.Content["Chats"] = chats
	templates.ExecuteTemplate(w, "index.html", page)
}

func ChatNew(w http.ResponseWriter, r *http.Request) {
	page := NewPage("New Chat")
	page.User = current_user(r)
	chat := &Chat{}
	if r.Method == "POST" {
		form := &CreateChatForm{}
		name := r.FormValue("chat_name")
		if form.Submit(name) {
			http.Redirect(w, r, fmt.Sprintf("/chats/show/%d", form.Chat.ID), 301)
			return
		} else {
			page.Errors = append(page.Errors, form.Errors...)
		}
	}
	page.Content["Chat"] = chat
	templates.ExecuteTemplate(w, "new.html", page)
}

func ChatShow(w http.ResponseWriter, r *http.Request) {
	page := NewPage("Chat Page")
	page.User = current_user(r)
	vars := mux.Vars(r)
	id, err := strconv.ParseUint(vars["id"], 10, 64)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	chat, err := ChatRepo(db()).Find(int64(id))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	page.Content["Chat"] = chat
	templates.ExecuteTemplate(w, "show.html", page)
}

func Register(w http.ResponseWriter, r *http.Request) {
	page := NewPage("Register")
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")
		form := &RegistrationForm{}
		if form.Submit(username, password) {
			http.Redirect(w, r, "/", 301)
			return
		}
		page.Errors = append(page.Errors, form.Errors...)
	}
	templates.ExecuteTemplate(w, "register.html", page)
}

func Login(w http.ResponseWriter, r *http.Request) {
	page := NewPage("Login")
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")
		user, err := UserRepo(db()).FindByUsername(username)
		if err != nil {
			page.Errors = append(page.Errors, errors.New("Wrong username and password combination"))
		} else if !user.HasPassword(password) {
			page.Errors = append(page.Errors, errors.New("Wrong username and password combination"))
		} else {
			session, err := store.Get(r, SESSION_NAME)
			if err == nil {
				session.Values["user_id"] = user.ID
				session.Save(r, w)
				http.Redirect(w, r, "/", 301)
				return
			} else {
				page.Errors = append(page.Errors, err)
			}
		}
	}
	templates.ExecuteTemplate(w, "login.html", page)
}

func Logout(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, SESSION_NAME)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	session.Values["user_id"] = nil
	session.Save(r, w)
	http.Redirect(w, r, "/", 301)
}

func CreateMessage(w http.ResponseWriter, r *http.Request) {
	user := current_user(r)
	form := &CreateMessageForm{}
	if r.Method == "POST" {
		chatID := r.FormValue("chat_id")
		messageBody := r.FormValue("message_body")
		if form.Submit(user.Username, chatID, messageBody) {
			go func() {
				messageChan <- form.Message
			}()
			// notify success
			res, _ := json.Marshal(form.Message)
			w.WriteHeader(http.StatusCreated)
			w.Write(res)
		} else {
			// notify failure
			res, _ := json.Marshal(form.Errors)
			w.WriteHeader(http.StatusBadRequest)
			w.Write(res)
		}
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func WS(w http.ResponseWriter, r *http.Request) {
	chatID := r.FormValue("chat_id")
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	go func() {
		wsChan <- &WebSocketTransport{Socket: ws, ChatID: chatID}
	}()
}

type WebsocketsMap map[*websocket.Conn]bool

// main
func main() {

	go func() {
		var sockets map[string]WebsocketsMap = make(map[string]WebsocketsMap)
		var socketsForRemoval []*websocket.Conn = make([]*websocket.Conn, 0)
		for {
			select {
			case msg := <-messageChan:
				chatID := strconv.FormatInt(msg.ChatID, 10)
				for ws, _ := range sockets[chatID] {
					err := ws.WriteJSON(msg)
					if err != nil {
						socketsForRemoval = append(socketsForRemoval, ws)
					}
				}
				for _, socketForRemoval := range socketsForRemoval {
					delete(sockets[chatID], socketForRemoval)
					socketForRemoval.Close()
				}
			case socketTransport := <-wsChan:
				if sockets[socketTransport.ChatID] == nil {
					sockets[socketTransport.ChatID] = make(map[*websocket.Conn]bool)
				}
				sockets[socketTransport.ChatID][socketTransport.Socket] = true
			}
		}
	}()

	defer db().Close()
	createSchema(db())

	templates = template.Must(template.ParseGlob("templates/*.html"))

	router := mux.NewRouter()

	router.HandleFunc("/", LoginRequired(Home))
	router.HandleFunc("/chats/new", LoginRequired(ChatNew))
	router.HandleFunc("/chats/show/{id}", LoginRequired(ChatShow))
	router.HandleFunc("/messages/create", LoginRequired(CreateMessage))
	router.HandleFunc("/ws", LoginRequired(WS))
	router.HandleFunc("/register", Register)
	router.HandleFunc("/login", Login)
	router.HandleFunc("/logout", LoginRequired(Logout))

	http.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("public"))))
	http.Handle("/", router)
	log.Println("Server up and running on http://localhost:8000")
	http.ListenAndServe(":8000", nil)
}
