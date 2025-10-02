package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	secretKey = flag.String("secret-key", "", "Secret key")
	logLevel  = flag.String("log-level", "info", "Log level")
)

type Secret struct {
	ID       string `json:"id"`
	Author   string `json:"author"`
	Content  string `json:"content"`
	IsPublic bool   `json:"is_public"`
}

func createToken(username string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"username": username,
			"exp":      time.Now().Add(time.Hour * 24).Unix(),
		},
	)

	tokenString, err := token.SignedString([]byte(*secretKey))
	if err != nil {
		return "", fmt.Errorf("creating token: %w", err)
	}

	return tokenString, nil
}

func verifyToken(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		return []byte(*secretKey), nil
	})
	if err != nil {
		return "", fmt.Errorf("parsing token: %w", err)
	}

	if !token.Valid {
		return "", fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid claims")
	}

	username, ok := claims["username"]
	if !ok {
		return "", fmt.Errorf("missing username in claims")
	}

	usernameStr, ok := username.(string)
	if !ok {
		return "", fmt.Errorf("invalid username type: %T", username)
	}

	return usernameStr, nil
}

func writeError(w http.ResponseWriter, err error, status int) {
	slog.Warn("response error", slog.String("error", err.Error()))
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]any{"error": err.Error()}); err != nil {
		slog.Error("error writing error", slog.String("error", err.Error()))
	}
}

type Storage struct {
	db *badger.DB
}

func NewStorage(db *badger.DB) *Storage {
	return &Storage{db: db}
}

func (s *Storage) Add(secret *Secret) error {
	data, err := json.Marshal(secret)
	if err != nil {
		return fmt.Errorf("marshalling secret: %w", err)
	}
	for {
		if err := s.db.Update(func(tx *badger.Txn) error {
			if err := tx.SetEntry(badger.NewEntry(secretIDKey(secret.ID), data).WithTTL(30 * time.Minute)); err != nil {
				return fmt.Errorf("setting secret data: %w", err)
			}

			if err := tx.SetEntry(badger.NewEntry(userSecretKey(secret.Author, secret.ID), data).WithTTL(30 * time.Minute)); err != nil {
				return fmt.Errorf("setting user data: %w", err)
			}

			return nil
		}); err != nil {
			if errors.Is(err, badger.ErrConflict) {
				time.Sleep(time.Millisecond)
				continue
			}
			return fmt.Errorf("adding secret to db: %w", err)
		}
		return nil
	}
}

func (s *Storage) Get(id string) (*Secret, error) {
	var secret Secret
	if err := s.db.View(func(tx *badger.Txn) error {
		item, err := tx.Get(secretIDKey(id))
		if err != nil {
			return fmt.Errorf("getting data: %w", err)
		}
		if err := item.Value(func(val []byte) error {
			if err := json.Unmarshal(val, &secret); err != nil {
				return fmt.Errorf("unmarshalling secret: %w", err)
			}
			return nil
		}); err != nil {
			return fmt.Errorf("processing item value: %w", err)
		}

		return nil
	}); err != nil {
		return nil, fmt.Errorf("in tx: %w", err)
	}

	return &secret, nil
}

func (s *Storage) SetPassword(user, password string) error {
	for {
		if err := s.db.Update(func(tx *badger.Txn) error {
			if _, err := tx.Get(passwordKey(user)); !errors.Is(err, badger.ErrKeyNotFound) {
				return fmt.Errorf("already exists")
			}
			if err := tx.SetEntry(badger.NewEntry(passwordKey(user), []byte(password)).WithTTL(30 * time.Minute)); err != nil {
				return fmt.Errorf("setting password: %w", err)
			}
			return nil
		}); err != nil {
			if errors.Is(err, badger.ErrConflict) {
				time.Sleep(time.Millisecond)
				continue
			}
			return fmt.Errorf("setting password in db: %w", err)
		}
		return nil
	}
}

func (s *Storage) GetPassword(user string) (string, error) {
	var password string
	if err := s.db.View(func(tx *badger.Txn) error {
		item, err := tx.Get(passwordKey(user))
		if err != nil {
			return fmt.Errorf("getting password: %w", err)
		}
		if err := item.Value(func(val []byte) error {
			password = string(val)
			return nil
		}); err != nil {
			return fmt.Errorf("processing item value: %w", err)
		}

		return nil
	}); err != nil {
		return "", fmt.Errorf("in tx: %w", err)
	}

	return password, nil
}

func (s *Storage) ListUser(user, start string) ([]*Secret, error) {
	const limit = 50

	var results []*Secret
	if err := s.db.View(func(tx *badger.Txn) error {
		prefix := userSecretKey(user, "")
		opts := badger.DefaultIteratorOptions
		opts.PrefetchSize = limit
		opts.Prefix = prefix
		iter := tx.NewIterator(opts)
		defer iter.Close()

		var seekValue []byte
		if start != "" {
			seekValue = append(userSecretKey(user, start), 0)
		}

		for iter.Seek(seekValue); iter.Valid(); iter.Next() {
			if err := iter.Item().Value(func(val []byte) error {
				var secret Secret
				if err := json.Unmarshal(val, &secret); err != nil {
					return fmt.Errorf("unmarshalling secret: %w", err)
				}
				results = append(results, &secret)
				return nil
			}); err != nil {
				return fmt.Errorf("processing value for key %s: %w", string(iter.Item().Key()), err)
			}
			if len(results) >= limit {
				break
			}
		}

		return nil
	}); err != nil {
		return nil, fmt.Errorf("in tx: %w", err)
	}

	return results, nil
}

func secretIDKey(id string) []byte {
	return []byte(fmt.Sprintf("secret:%s", id))
}

func userSecretKey(user, id string) []byte {
	return []byte(fmt.Sprintf("user_secrets:%s:%s", user, id))
}

func passwordKey(user string) []byte {
	return []byte(fmt.Sprintf("password:%s", user))
}

type App struct {
	storage *Storage
}

func NewApp(storage *Storage) *App {
	return &App{storage: storage}
}

func (a *App) handleAddSecret() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := verifyToken(r.Header.Get("Authentication"))
		if err != nil {
			writeError(w, err, http.StatusUnauthorized)
			return
		}

		if err := r.ParseForm(); err != nil {
			writeError(w, err, http.StatusBadRequest)
			return
		}

		content := r.FormValue("content")
		if content == "" {
			writeError(w, fmt.Errorf("missing content"), http.StatusBadRequest)
			return
		}

		isPublic := r.FormValue("is_public") == "true"

		secret := Secret{
			ID:       uuid.New().String(),
			Author:   user,
			Content:  content,
			IsPublic: isPublic,
		}

		slog.Debug(
			"adding secret",
			slog.String("secret", secret.ID),
			slog.String("content", secret.Content),
			slog.Bool("is_public", secret.IsPublic),
			slog.String("user", user),
		)

		if err := a.storage.Add(&secret); err != nil {
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(secret)
	}
}

func (a *App) handleGetSecret() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := verifyToken(r.Header.Get("Authentication"))
		if err != nil {
			writeError(w, err, http.StatusUnauthorized)
			return
		}

		id := r.URL.Query().Get("id")
		if id == "" {
			writeError(w, fmt.Errorf("missing id"), http.StatusBadRequest)
			return
		}

		secret, err := a.storage.Get(id)
		if err != nil {
			writeError(w, err, http.StatusBadRequest)
			return
		}

		slog.Debug(
			"getting secret",
			slog.String("secret", secret.ID),
			slog.String("user", user),
			slog.Bool("is_public", secret.IsPublic),
			slog.String("author", secret.Author),
		)

		if !secret.IsPublic && secret.Author != user {
			writeError(w, fmt.Errorf("not allowed"), http.StatusForbidden)
			return
		}

		if secret.IsPublic && secret.Author != user {
			// Hide author for public secrets
			secret.Author = ""
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(secret)
	}
}

func (a *App) handleListUserSecrets() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := verifyToken(r.Header.Get("Authentication"))
		if err != nil {
			writeError(w, err, http.StatusUnauthorized)
			return
		}

		start := r.URL.Query().Get("start")
		secrets, err := a.storage.ListUser(user, start)
		if err != nil {
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		slog.Debug(
			"listing user secrets",
			slog.String("user", user),
			slog.String("start", start),
		)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(secrets)
	}
}

func (a *App) handleRegister() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			writeError(w, err, http.StatusBadRequest)
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")

		passwordHash := sha256.Sum256([]byte(password))
		if err := a.storage.SetPassword(username, hex.EncodeToString(passwordHash[:])); err != nil {
			writeError(w, err, http.StatusBadRequest)
			return
		}

		token, err := createToken(username)
		if err != nil {
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		slog.Debug(
			"registering user",
			slog.String("user", username),
		)

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Authentication", token)
		w.WriteHeader(http.StatusOK)
	}
}

func (a *App) handleLogin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			writeError(w, err, http.StatusBadRequest)
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")

		passwordHash := sha256.Sum256([]byte(password))
		storedPassword, err := a.storage.GetPassword(username)
		if err != nil {
			writeError(w, err, http.StatusBadRequest)
			return
		}

		if storedPassword != hex.EncodeToString(passwordHash[:]) {
			writeError(w, fmt.Errorf("invalid password"), http.StatusUnauthorized)
			return
		}

		token, err := createToken(username)
		if err != nil {
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		slog.Debug(
			"logging in user",
			slog.String("user", username),
		)

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Authentication", token)
		w.WriteHeader(http.StatusOK)
	}
}

func main() {
	flag.Parse()

	var level slog.Level
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		panic(err)
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	})))

	db, err := badger.Open(badger.DefaultOptions("data"))
	if err != nil {
		panic(err)
	}
	defer db.Close()

	app := NewApp(NewStorage(db))

	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			for {
				err := db.RunValueLogGC(0.7)
				if err == badger.ErrNoRewrite {
					break
				}
				if err != nil {
					slog.Error("error running value log GC", slog.String("error", err.Error()))
					break
				}
			}
		}
	}()

	http.HandleFunc("/add", app.handleAddSecret())
	http.HandleFunc("/get", app.handleGetSecret())
	http.HandleFunc("/list", app.handleListUserSecrets())
	http.HandleFunc("/register", app.handleRegister())
	http.HandleFunc("/login", app.handleLogin())

	http.ListenAndServe(":31339", nil)
}
