package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	cookieName = "gw_session"
	sessionTTL = 7 * 24 * time.Hour
)

type sessionUser struct {
	Username string `json:"username"`
	Role     string `json:"role"`
}

type ctxKey int

const ctxUser ctxKey = iota

func userKey(u string) string    { return "admin_user:" + u }
func sessionKey(s string) string { return "session:" + s }

// 首次启动时,如果设置了 BOOTSTRAP_ADMIN_USER/PASSWORD 且该用户不存在,
// 创建一个 superadmin。已存在则跳过(永远不覆盖现有密码)。
func bootstrapAdmin(ctx context.Context) error {
	username := strings.TrimSpace(os.Getenv("BOOTSTRAP_ADMIN_USER"))
	password := strings.TrimSpace(os.Getenv("BOOTSTRAP_ADMIN_PASSWORD"))
	if username == "" || password == "" {
		return nil
	}
	exists, err := rdb.Exists(ctx, userKey(username)).Result()
	if err != nil {
		return err
	}
	if exists > 0 {
		return nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if err := rdb.HSet(ctx, userKey(username), map[string]any{
		"username":      username,
		"password_hash": string(hash),
		"role":          "superadmin",
		"created_at":    time.Now().Unix(),
	}).Err(); err != nil {
		return err
	}
	log.Printf("[bootstrap] created superadmin=%s", username)
	return nil
}

func loadSession(ctx context.Context, sid string) (*sessionUser, error) {
	if sid == "" {
		return nil, nil
	}
	res, err := rdb.HGetAll(ctx, sessionKey(sid)).Result()
	if err != nil || len(res) == 0 {
		return nil, err
	}
	rdb.Expire(ctx, sessionKey(sid), sessionTTL) // sliding TTL
	return &sessionUser{Username: res["username"], Role: res["role"]}, nil
}

func createSession(ctx context.Context, u *sessionUser) (string, error) {
	sid := randomToken(24)
	if err := rdb.HSet(ctx, sessionKey(sid), map[string]any{
		"username":   u.Username,
		"role":       u.Role,
		"created_at": time.Now().Unix(),
	}).Err(); err != nil {
		return "", err
	}
	rdb.Expire(ctx, sessionKey(sid), sessionTTL)
	return sid, nil
}

func currentUser(r *http.Request) *sessionUser {
	if u, ok := r.Context().Value(ctxUser).(*sessionUser); ok {
		return u
	}
	return nil
}

// ---------- handlers ----------

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" {
		writeErr(w, 400, "username/password required")
		return
	}
	u, err := rdb.HGetAll(r.Context(), userKey(req.Username)).Result()
	if err != nil || len(u) == 0 {
		writeErr(w, 401, "invalid credentials")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u["password_hash"]), []byte(req.Password)); err != nil {
		writeErr(w, 401, "invalid credentials")
		return
	}
	su := &sessionUser{Username: u["username"], Role: u["role"]}
	sid, err := createSession(r.Context(), su)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionTTL.Seconds()),
		// HTTPS 后面跑时 OpenResty 透传,Secure 由前端 cookie 框架处理;
		// 想强制 Secure 可以 export GW_COOKIE_SECURE=1 自行加上
	})
	log.Printf("[login] %s ok", su.Username)
	writeJSON(w, 200, su)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		rdb.Del(r.Context(), sessionKey(c.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func meHandler(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	if u == nil {
		writeErr(w, 401, "not logged in")
		return
	}
	writeJSON(w, 200, u)
}

// ---------- user CRUD (superadmin only) ----------

func requireSuperadmin(r *http.Request) bool {
	u := currentUser(r)
	return u != nil && u.Role == "superadmin"
}

func listUsersHandler(w http.ResponseWriter, r *http.Request) {
	keys, err := scanKeys(r.Context(), "admin_user:*")
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	users := make([]map[string]string, 0, len(keys))
	for _, k := range keys {
		u, _ := rdb.HGetAll(r.Context(), k).Result()
		delete(u, "password_hash")
		users = append(users, u)
	}
	writeJSON(w, 200, users)
}

func createUserHandler(w http.ResponseWriter, r *http.Request) {
	if !requireSuperadmin(r) {
		writeErr(w, 403, "superadmin only")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || len(req.Password) < 8 {
		writeErr(w, 400, "username required, password >=8 chars")
		return
	}
	if req.Role == "" {
		req.Role = "operator"
	}
	if req.Role != "superadmin" && req.Role != "operator" {
		writeErr(w, 400, "role must be superadmin or operator")
		return
	}
	exists, _ := rdb.Exists(r.Context(), userKey(req.Username)).Result()
	if exists > 0 {
		writeErr(w, 409, "user exists")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	rdb.HSet(r.Context(), userKey(req.Username), map[string]any{
		"username":      req.Username,
		"password_hash": string(hash),
		"role":          req.Role,
		"created_at":    time.Now().Unix(),
	})
	log.Printf("[admin] %s created user=%s role=%s",
		currentUser(r).Username, req.Username, req.Role)
	writeJSON(w, 201, map[string]string{"username": req.Username, "role": req.Role})
}

func deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	if !requireSuperadmin(r) {
		writeErr(w, 403, "superadmin only")
		return
	}
	username := r.PathValue("username")
	if username == currentUser(r).Username {
		writeErr(w, 400, "cannot delete yourself")
		return
	}
	n, _ := rdb.Del(r.Context(), userKey(username)).Result()
	log.Printf("[admin] %s deleted user=%s", currentUser(r).Username, username)
	writeJSON(w, 200, map[string]int64{"deleted": n})
}

// ---------- shared ----------

func scanKeys(ctx context.Context, pattern string) ([]string, error) {
	var cursor uint64
	var out []string
	for {
		keys, next, err := rdb.Scan(ctx, cursor, pattern, 200).Result()
		if err != nil {
			return nil, err
		}
		out = append(out, keys...)
		cursor = next
		if cursor == 0 {
			break
		}
	}
	return out, nil
}
