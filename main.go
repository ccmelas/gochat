package main

import (
	"flag"
	"github.com/ccmelas/trace"
	"github.com/stretchr/gomniauth"
	"github.com/stretchr/gomniauth/providers/facebook"
	"github.com/stretchr/gomniauth/providers/github"
	"github.com/stretchr/gomniauth/providers/google"
	"github.com/stretchr/objx"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"text/template"
)

var avatars Avatar = TryAvatars{
	UseFileSystemAvatar,
	UseAuthAvatar,
	UseGravatar,
}

type templateHandler struct {
	once     sync.Once
	filename string
	templ    *template.Template
}

func (t *templateHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	t.once.Do(func() {
		t.templ = template.Must(template.ParseFiles(filepath.Join("templates", t.filename)))
	})
	data := map[string]interface{}{
		"Host": req.Host,
	}

	if authCookie, err := req.Cookie("auth"); err == nil {
		data["UserData"] = objx.MustFromBase64(authCookie.Value)
	}
	t.templ.Execute(w, data)
}

func main() {
	var addr = flag.String("addr", ":8080", "The address of the application")
	flag.Parse()
	gomniauth.SetSecurityKey("myAuthKey")
	gomniauth.WithProviders(
		google.New("267168534902-8oc8ae814dpi9ntbirmrcnke0b5n364g.apps.googleusercontent.com",
			"R9tRLytr_Bav6WPk1FwGgtHJ",
			"http://localhost"+*addr+"/auth/callback/google"),
		facebook.New("688657768582820", "d5048cd1a3141622dac6fc036fbd2e2f",
			"http://localhost"+*addr+"/auth/callback/facebook"),
		github.New("4d8d44615ee369f4c914", "a92d69db777308e72ac039c1eac8eef2e2b05d99",
			"http://localhost"+*addr+"/auth/callback/github"))
	r := newRoom()
	r.tracer = trace.New(os.Stdout)
	http.Handle("/avatars/", http.StripPrefix("/avatars/", http.FileServer(http.Dir("./avatars"))))
	http.Handle("/chat", MustAuth(&templateHandler{filename: "chat.html"}))
	http.Handle("/upload", MustAuth(&templateHandler{filename: "upload.html"}))
	http.Handle("/login", &templateHandler{filename: "login.html"})
	http.HandleFunc("/auth/", loginHandler)
	http.HandleFunc("/uploader", uploadHandler)
	http.Handle("/room", r)
	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:   "auth",
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		})
		w.Header().Set("Location", "/chat")
		w.WriteHeader(http.StatusTemporaryRedirect)
	})
	go r.run()
	log.Println("Starting web server on", *addr)
	log.Fatal("ListenAndServe: ", http.ListenAndServe(*addr, nil))
}
