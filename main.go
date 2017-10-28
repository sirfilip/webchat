package main

import (
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
)

// const
const SESSION_NAME string = "default"

// variables
var store = sessions.NewCookieStore([]byte("my super duper secret"))
var conn *sql.DB
var templates *template.Template

// init
func db() *sql.DB {
	var err error
	if conn == nil {
		fmt.Println("Connecting to db")
		conn, err = sql.Open("sqlite3", ":memory:")
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
		fmt.Println(err)
	}
	return user
}

func createSchema(db *sql.DB) {
	if _, err := db.Exec(`
		CREATE TABLE chats ( 
			id INTEGER PRIMARY KEY AUTOINCREMENT, 
			name TEXT 
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
}

// models
type Chat struct {
	ID   int64
	Name string
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
		chats = append(chats, &Chat{id, name})
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
	var name string
	var id int64

	err := this.db.QueryRow("SELECT id, name FROM chats WHERE id=?", uid).Scan(&id, &name)
	if err != nil {
		return nil, err
	}
	return &Chat{id, name}, nil
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
		chat.Name = r.FormValue("chat_name")
		ChatRepo(db()).Save(chat)
		http.Redirect(w, r, "/", 301)
		return
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
		_, err := UserRepo(db()).Register(username, password)
		if err == nil {
			http.Redirect(w, r, "/", 301)
			return
		}
		page.Errors = append(page.Errors, err)
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

// main
func main() {
	defer db().Close()
	createSchema(db())

	templates = template.Must(template.ParseGlob("templates/*.html"))

	router := mux.NewRouter()

	router.HandleFunc("/", LoginRequired(Home))
	router.HandleFunc("/chats/new", LoginRequired(ChatNew))
	router.HandleFunc("/chats/show/{id}", LoginRequired(ChatShow))
	router.HandleFunc("/register", Register)
	router.HandleFunc("/login", Login)
	router.HandleFunc("/logout", LoginRequired(Logout))

	http.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("public"))))
	http.Handle("/", router)
	http.ListenAndServe(":8000", nil)
}
