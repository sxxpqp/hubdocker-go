package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// 子域名 token 提取:abc123.cdn.your.com -> abc123
// 长度 >=4,只允许小写字母数字,避免与系统子域(www/api 等)冲突
var hostRe = regexp.MustCompile(`^([a-z0-9]{4,})\.`)

var (
	rdb           *redis.Client
	upstreamURL   *url.URL
	harborProject string
	proxy         *httputil.ReverseProxy
)

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func main() {
	upstream := env("UPSTREAM_URL", "http://harbor:80")
	harborProject = env("HARBOR_PROJECT", "dockerhub")
	redisAddr := env("REDIS_ADDR", "redis:6379")
	listen := env("LISTEN", ":7000")
	adminToken := env("ADMIN_TOKEN", "")

	var err error
	upstreamURL, err = url.Parse(upstream)
	if err != nil {
		log.Fatalf("invalid UPSTREAM_URL: %v", err)
	}

	rdb = redis.NewClient(&redis.Options{Addr: redisAddr})
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		log.Fatalf("redis ping failed: %v", err)
	}
	if err := bootstrapAdmin(context.Background()); err != nil {
		log.Fatalf("bootstrap admin: %v", err)
	}

	proxy = httputil.NewSingleHostReverseProxy(upstreamURL)
	origDirector := proxy.Director
	proxy.Director = func(r *http.Request) {
		origDirector(r)
		r.Host = upstreamURL.Host
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("[proxy] err: %v", err)
		registryDeny(w, http.StatusBadGateway, "UNAVAILABLE", "upstream registry unavailable")
	}

	// 统一 mux,纯路径路由,不分 host。
	// admin 路径 /admin/* 在任何子域都可访问;cookie 由浏览器按 host 自动隔离。
	mux := http.NewServeMux()

	// 健康检查
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	})

	// admin(任何 host 都能登;cookie host-locked)
	mux.HandleFunc("GET /admin", serveAdminIndex)
	mountAdminRoutes(mux, adminToken)

	// 客户端 portal + JSON API + chat WS(需要 token 子域)
	mux.HandleFunc("GET /portal", servePortal)
	mux.HandleFunc("GET /api/me", customerMe)
	mux.HandleFunc("GET /api/chat/messages", customerChatHistory)
	mux.HandleFunc("/api/chat/ws", customerChatWS)

	// Docker registry 反代
	mux.HandleFunc("/v2/", handleRegistry)

	// 根路径:浏览器视访问类型分流
	mux.HandleFunc("/", rootRedirect)

	log.Printf("gateway on %s | upstream=%s | project=%s", listen, upstream, harborProject)
	if err := http.ListenAndServe(listen, mux); err != nil {
		log.Fatal(err)
	}
}

// rootRedirect:浏览器访问 / 时:
//   - 有 token 子域 → /portal
//   - 没 token(apex 或裸 IP) → /admin
//
// 非浏览器(Docker 等)直接走 handleRegistry。
func rootRedirect(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if !strings.Contains(r.Header.Get("Accept"), "text/html") {
		// 非浏览器(Docker 客户端 / curl)— 走 registry,让 /v2/ 自然处理
		handleRegistry(w, r)
		return
	}
	if extractToken(r.Host) != "" {
		http.Redirect(w, r, "/portal", http.StatusFound)
	} else {
		http.Redirect(w, r, "/admin", http.StatusFound)
	}
}

func serveAdminIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./web/index.html")
}

func servePortal(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./web/portal.html")
}

// GET /api/me — 当前 token 的余额/到期/用量摘要,portal 用
func customerMe(w http.ResponseWriter, r *http.Request) {
	token := extractToken(r.Host)
	if token == "" {
		writeErr(w, 400, "missing token (subdomain)")
		return
	}
	info, err := loadToken(r.Context(), token)
	if err != nil || info == nil {
		writeErr(w, 401, "invalid token")
		return
	}
	usage := make(map[string]int64, 7)
	for i := 0; i < 7; i++ {
		day := time.Now().AddDate(0, 0, -i).Format("20060102")
		b, _ := rdb.HGet(r.Context(), fmt.Sprintf("usage:%s:%s", info.UserID, day), "bytes").Int64()
		usage[day] = b
	}
	adminOnline, _ := rdb.SCard(r.Context(), "chat:admins_online").Result()
	unread, _ := rdb.Get(r.Context(), "chat:unread_user:"+token).Int64()

	scheme := "https"
	if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
		scheme = "http"
	}
	writeJSON(w, 200, map[string]any{
		"token":        token,
		"user_id":      info.UserID,
		"balance":      info.Balance,
		"status":       info.Status,
		"expires_at":   info.Expires,
		"usage_7d":     usage,
		"admin_online": adminOnline > 0,
		"unread":       unread,
		"mirror_url":   scheme + "://" + r.Host,
	})
}

// ---------- Docker registry 反代 ----------

func handleRegistry(w http.ResponseWriter, r *http.Request) {
	token := extractToken(r.Host)
	if token == "" {
		registryDeny(w, http.StatusBadRequest, "DENIED", "missing token (subdomain)")
		return
	}

	info, err := loadToken(r.Context(), token)
	if err != nil {
		log.Printf("[redis] %v", err)
		registryDeny(w, http.StatusServiceUnavailable, "UNAVAILABLE", "auth backend down")
		return
	}
	if info == nil {
		registryDeny(w, http.StatusGone, "DENIED", "token not found")
		return
	}
	if info.Status != "active" {
		registryDeny(w, http.StatusGone, "DENIED", "token "+info.Status)
		return
	}
	if info.Expires > 0 && info.Expires < time.Now().Unix() {
		registryDeny(w, http.StatusGone, "DENIED", "token expired, please renew")
		return
	}
	if info.Balance <= 0 {
		registryDeny(w, http.StatusGone, "DENIED", "quota exhausted, please top up")
		return
	}

	r.URL.Path = rewritePath(r.URL.Path)

	cw := &countingWriter{ResponseWriter: w}
	proxy.ServeHTTP(cw, r)

	if cw.bytes > 0 && cw.billable(r.Method) {
		bg := context.Background()
		newBal, err := rdb.HIncrBy(bg, "token:"+token, "balance", -cw.bytes).Result()
		if err != nil {
			log.Printf("[redis] decrement %s by %d failed: %v", token, cw.bytes, err)
			return
		}
		ts := time.Now().Format("20060102")
		rdb.HIncrBy(bg, fmt.Sprintf("usage:%s:%s", info.UserID, ts), "bytes", cw.bytes)
		log.Printf("[usage] token=%s user=%s path=%s status=%d bytes=%d/%d remaining=%d billable=true",
			token, info.UserID, r.URL.Path, cw.status, cw.bytes, cw.contentLength, newBal)
	} else if cw.bytes > 0 {
		log.Printf("[no-bill] token=%s path=%s status=%d bytes=%d/%d writeErr=%v method=%s",
			token, r.URL.Path, cw.status, cw.bytes, cw.contentLength, cw.writeErr, r.Method)
	}
}

func extractToken(host string) string {
	if i := strings.IndexByte(host, ':'); i > 0 {
		host = host[:i]
	}
	host = strings.ToLower(host)
	m := hostRe.FindStringSubmatch(host)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

func rewritePath(p string) string {
	if !strings.HasPrefix(p, "/v2/") {
		return p
	}
	rest := strings.TrimPrefix(p, "/v2/")
	if rest == "" {
		return p
	}
	if strings.HasPrefix(rest, harborProject+"/") {
		return p
	}
	return "/v2/" + harborProject + "/" + rest
}

// ---------- token 数据 ----------

type tokenInfo struct {
	UserID  string
	Balance int64
	Status  string
	Expires int64
}

func loadToken(ctx context.Context, token string) (*tokenInfo, error) {
	res, err := rdb.HGetAll(ctx, "token:"+token).Result()
	if err != nil {
		return nil, err
	}
	if len(res) == 0 {
		return nil, nil
	}
	bal, _ := strconv.ParseInt(res["balance"], 10, 64)
	exp, _ := strconv.ParseInt(res["expires_at"], 10, 64)
	return &tokenInfo{
		UserID:  res["user_id"],
		Balance: bal,
		Status:  res["status"],
		Expires: exp,
	}, nil
}

func registryDeny(w http.ResponseWriter, code int, dockerCode, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
	w.WriteHeader(code)
	fmt.Fprintf(w, `{"errors":[{"code":%q,"message":%q}]}`, dockerCode, msg)
}

// ---------- countingWriter:billable 计费 ----------

type countingWriter struct {
	http.ResponseWriter
	bytes         int64
	status        int
	contentLength int64
	writeErr      error
}

func (c *countingWriter) WriteHeader(s int) {
	c.status = s
	if cl := c.Header().Get("Content-Length"); cl != "" {
		c.contentLength, _ = strconv.ParseInt(cl, 10, 64)
	}
	c.ResponseWriter.WriteHeader(s)
}

func (c *countingWriter) Write(b []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
		if cl := c.Header().Get("Content-Length"); cl != "" {
			c.contentLength, _ = strconv.ParseInt(cl, 10, 64)
		}
	}
	n, err := c.ResponseWriter.Write(b)
	c.bytes += int64(n)
	if err != nil {
		c.writeErr = err
	}
	return n, err
}

func (c *countingWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// 计费规则(只在四个条件全满足时才扣):
//
//  1. 非 HEAD(HEAD 是元数据探测,不扣)
//  2. 状态 2xx(4xx/5xx 上游错,不让客户买单)
//  3. 写过程无错(writeErr == nil — 客户端中途断网,不扣)
//  4. Content-Length > 0 时,实际写出字节 == Content-Length(完整传输才扣)
//
// chunked transfer 没 Content-Length,只能靠"无写错"兜底。
func (c *countingWriter) billable(method string) bool {
	if method == http.MethodHead {
		return false
	}
	if c.status < 200 || c.status >= 300 {
		return false
	}
	if c.writeErr != nil {
		return false
	}
	if c.contentLength > 0 && c.bytes < c.contentLength {
		return false
	}
	return true
}
