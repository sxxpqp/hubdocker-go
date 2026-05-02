package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// mountAdminRoutes 把 admin 控制台和 REST API 挂到外部传入的 mux 上。
// 由 main.go 在 apex host(cdn.your.com)的子 mux 上调用。
//
// 浏览器走 cookie session(登录后);机器调用(支付回调等)走 X-Admin-Token。
func mountAdminRoutes(mux *http.ServeMux, secret string) {
	// 公开:登录
	mux.HandleFunc("POST /admin/login", loginHandler)

	// 已登录
	mux.HandleFunc("POST /admin/logout", auth(secret, logoutHandler))
	mux.HandleFunc("GET /admin/me", auth(secret, meHandler))

	// Token CRUD(任何已登录用户)
	mux.HandleFunc("GET /admin/tokens", auth(secret, listTokens))
	mux.HandleFunc("POST /admin/tokens", auth(secret, createToken))
	mux.HandleFunc("GET /admin/tokens/{token}", auth(secret, getToken))
	mux.HandleFunc("POST /admin/tokens/{token}/topup", auth(secret, topupToken))
	mux.HandleFunc("POST /admin/tokens/{token}/revoke", auth(secret, revokeToken))
	mux.HandleFunc("POST /admin/tokens/{token}/reactivate", auth(secret, reactivateToken))
	mux.HandleFunc("DELETE /admin/tokens/{token}", auth(secret, deleteToken))
	mux.HandleFunc("GET /admin/tokens/{token}/usage", auth(secret, getUsage))

	// 用户管理(superadmin)
	mux.HandleFunc("GET /admin/users", auth(secret, listUsersHandler))
	mux.HandleFunc("POST /admin/users", auth(secret, createUserHandler))
	mux.HandleFunc("DELETE /admin/users/{username}", auth(secret, deleteUserHandler))

	// 客服聊天(共享收件箱)
	mux.HandleFunc("/admin/chat/ws", auth(secret, adminChatWS))
	mux.HandleFunc("GET /admin/chat/threads", auth(secret, listChatThreads))
	mux.HandleFunc("GET /admin/chat/threads/{token}/messages", auth(secret, getChatHistory))
	mux.HandleFunc("POST /admin/chat/threads/{token}/messages", auth(secret, sendAdminChat))
	// Note: 控制台 HTML(GET /admin)由 main.go 的 serveAdminIndex 处理
}

// auth 接受两种鉴权:
//  1. cookie session(浏览器,登录后)
//  2. X-Admin-Token 共享密钥(机器调用,如支付回调)
//
// 把当前用户存入 context,handler 通过 currentUser(r) 取。
func auth(secret string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 机器调用:共享密钥
		if secret != "" && r.Header.Get("X-Admin-Token") == secret {
			ctx := context.WithValue(r.Context(),
				ctxUser, &sessionUser{Username: "machine", Role: "superadmin"})
			h(w, r.WithContext(ctx))
			return
		}
		// 浏览器:cookie session
		c, err := r.Cookie(cookieName)
		if err != nil {
			writeErr(w, 401, "login required")
			return
		}
		u, err := loadSession(r.Context(), c.Value)
		if err != nil || u == nil {
			writeErr(w, 401, "session invalid or expired")
			return
		}
		ctx := context.WithValue(r.Context(), ctxUser, u)
		h(w, r.WithContext(ctx))
	}
}

// 列出全部 token(用于控制台表格)。
// SCAN 不会阻塞 Redis,前期几千 token 完全够用;以后超过 10w 再加分页。
func listTokens(w http.ResponseWriter, r *http.Request) {
	keys, err := scanKeys(r.Context(), "token:*")
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := make([]map[string]string, 0, len(keys))
	for _, k := range keys {
		t, _ := rdb.HGetAll(r.Context(), k).Result()
		t["token"] = strings.TrimPrefix(k, "token:")
		out = append(out, t)
	}
	writeJSON(w, 200, out)
}

// POST /admin/tokens
//
//	{"user_id":"u1","balance_gb":100,"expires_days":30,"token":"(optional)"}
func createToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token       string `json:"token"`
		UserID      string `json:"user_id"`
		BalanceGB   int64  `json:"balance_gb"`
		ExpiresDays int64  `json:"expires_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.UserID == "" || req.BalanceGB <= 0 {
		writeErr(w, 400, "user_id and balance_gb (>0) required")
		return
	}
	if req.Token == "" {
		req.Token = randomToken(8)
	}
	if !hostRe.MatchString(req.Token + ".x") {
		writeErr(w, 400, "token must match [a-z0-9]{4,}")
		return
	}

	balance := req.BalanceGB * 1024 * 1024 * 1024
	expiresAt := int64(0)
	if req.ExpiresDays > 0 {
		expiresAt = time.Now().Unix() + req.ExpiresDays*86400
	}

	if err := rdb.HSet(r.Context(), "token:"+req.Token, map[string]any{
		"user_id":    req.UserID,
		"balance":    balance,
		"status":     "active",
		"expires_at": expiresAt,
		"created_at": time.Now().Unix(),
	}).Err(); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	log.Printf("[admin] create token=%s user=%s balance=%dGB days=%d",
		req.Token, req.UserID, req.BalanceGB, req.ExpiresDays)

	writeJSON(w, 201, map[string]any{
		"token":      req.Token,
		"user_id":    req.UserID,
		"balance":    balance,
		"expires_at": expiresAt,
	})
}

func getToken(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	info, err := rdb.HGetAll(r.Context(), "token:"+token).Result()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if len(info) == 0 {
		writeErr(w, 404, "not found")
		return
	}
	writeJSON(w, 200, info)
}

// POST /admin/tokens/{token}/topup
//
//	{"add_gb":50,"extend_days":30}
func topupToken(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	var req struct {
		AddGB      int64 `json:"add_gb"`
		ExtendDays int64 `json:"extend_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	key := "token:" + token
	exists, _ := rdb.Exists(r.Context(), key).Result()
	if exists == 0 {
		writeErr(w, 404, "not found")
		return
	}
	if req.AddGB > 0 {
		rdb.HIncrBy(r.Context(), key, "balance", req.AddGB*1024*1024*1024)
	}
	if req.ExtendDays > 0 {
		cur, _ := rdb.HGet(r.Context(), key, "expires_at").Int64()
		now := time.Now().Unix()
		base := cur
		if base < now {
			base = now // 已过期就从今天起算,不让用户白嫖以前的过期天数
		}
		rdb.HSet(r.Context(), key, "expires_at", base+req.ExtendDays*86400)
	}
	info, _ := rdb.HGetAll(r.Context(), key).Result()
	log.Printf("[admin] topup token=%s +%dGB +%dd", token, req.AddGB, req.ExtendDays)
	writeJSON(w, 200, info)
}

func revokeToken(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	key := "token:" + token
	n, _ := rdb.Exists(r.Context(), key).Result()
	if n == 0 {
		writeErr(w, 404, "not found")
		return
	}
	rdb.HSet(r.Context(), key, "status", "revoked")
	log.Printf("[admin] revoke token=%s", token)
	writeJSON(w, 200, map[string]string{"status": "revoked"})
}

func reactivateToken(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	key := "token:" + token
	n, _ := rdb.Exists(r.Context(), key).Result()
	if n == 0 {
		writeErr(w, 404, "not found")
		return
	}
	rdb.HSet(r.Context(), key, "status", "active")
	log.Printf("[admin] reactivate token=%s", token)
	writeJSON(w, 200, map[string]string{"status": "active"})
}

func deleteToken(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	n, _ := rdb.Del(r.Context(), "token:"+token).Result()
	log.Printf("[admin] delete token=%s removed=%d", token, n)
	writeJSON(w, 200, map[string]int64{"deleted": n})
}

// GET /admin/tokens/{token}/usage?days=7
func getUsage(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	userID, err := rdb.HGet(r.Context(), "token:"+token, "user_id").Result()
	if err != nil {
		writeErr(w, 404, "not found")
		return
	}
	days := 7
	if d := r.URL.Query().Get("days"); d != "" {
		if n, err := strconv.Atoi(d); err == nil && n > 0 && n <= 90 {
			days = n
		}
	}
	usage := make(map[string]int64, days)
	for i := 0; i < days; i++ {
		day := time.Now().AddDate(0, 0, -i).Format("20060102")
		b, _ := rdb.HGet(r.Context(), fmt.Sprintf("usage:%s:%s", userID, day), "bytes").Int64()
		usage[day] = b
	}
	writeJSON(w, 200, map[string]any{
		"user_id": userID,
		"usage":   usage,
	})
}

// ---------- helpers ----------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return strings.ToLower(hex.EncodeToString(b))
}
