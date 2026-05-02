package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/redis/go-redis/v9"
)

// 聊天数据模型(全部存 Redis,不引 SQL):
//
//	chat:msgs:<token>          LIST<json>      消息历史(保留最后 1000 条)
//	chat:inbox                 ZSET            收件箱:score=最后活跃 ts(ms),member=token
//	chat:unread_admin:<token>  counter         admin 视角的未读数
//	chat:unread_user:<token>   counter         客户视角的未读数
//	chat:admins_online         SET<username>   当前 WS 在线的 admin
//
//	PUBSUB channel chat.thread.<token>          单线程 fanout(客户和监听该 thread 的 admin)
//	PUBSUB channel chat.inbox                  收件箱级 fanout(admin 列表实时刷新)

type chatMsg struct {
	ID   string `json:"id"`
	From string `json:"from"` // "user" 或 "admin:<username>"
	Text string `json:"text"`
	TS   int64  `json:"ts"` // unix milliseconds
}

var upgrader = websocket.Upgrader{
	// 同源 + 子域之间会跨 host,直接放开;真正鉴权由 token/cookie 完成
	CheckOrigin: func(r *http.Request) bool { return true },
}

const maxMsgLen = 2000

// ---------- 客户端:WS at /api/chat/ws (子域 token 鉴权) ----------

func customerChatWS(w http.ResponseWriter, r *http.Request) {
	token := extractToken(r.Host)
	if token == "" {
		http.Error(w, "no token", http.StatusBadRequest)
		return
	}
	info, err := loadToken(r.Context(), token)
	if err != nil || info == nil || info.Status != "active" {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sub := rdb.Subscribe(ctx, "chat.thread."+token)
	defer sub.Close()

	// 客户打开聊天就清掉自己的未读
	rdb.Del(ctx, "chat:unread_user:"+token)

	// pubsub -> client
	done := make(chan struct{})
	go func() {
		defer close(done)
		ch := sub.Channel()
		for {
			select {
			case <-ctx.Done():
				return
			case m, ok := <-ch:
				if !ok {
					return
				}
				if err := conn.WriteMessage(websocket.TextMessage, []byte(m.Payload)); err != nil {
					return
				}
			}
		}
	}()

	// client -> persistence + fanout
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var inbound struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(data, &inbound); err != nil {
			continue
		}
		text := strings.TrimSpace(inbound.Text)
		if text == "" || len(text) > maxMsgLen {
			continue
		}
		persistAndPublish(ctx, token, "user", text)
	}
}

// GET /api/chat/messages — 客户拉历史(打开聊天时调一次)
func customerChatHistory(w http.ResponseWriter, r *http.Request) {
	token := extractToken(r.Host)
	if _, err := loadToken(r.Context(), token); err != nil {
		writeErr(w, 401, "invalid token")
		return
	}
	msgs, _ := rdb.LRange(r.Context(), "chat:msgs:"+token, 0, -1).Result()
	out := make([]json.RawMessage, len(msgs))
	for i, m := range msgs {
		out[i] = json.RawMessage(m)
	}
	rdb.Del(r.Context(), "chat:unread_user:"+token)
	writeJSON(w, 200, out)
}

// ---------- Admin:WS at /admin/chat/ws (cookie session 鉴权) ----------

func adminChatWS(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	if user == nil {
		http.Error(w, "login required", http.StatusUnauthorized)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rdb.SAdd(ctx, "chat:admins_online", user.Username)
	defer rdb.SRem(context.Background(), "chat:admins_online", user.Username)

	sub := rdb.PSubscribe(ctx, "chat.thread.*", "chat.inbox")
	defer sub.Close()

	go func() {
		ch := sub.Channel()
		for {
			select {
			case <-ctx.Done():
				return
			case m, ok := <-ch:
				if !ok {
					return
				}
				wrap, _ := json.Marshal(map[string]string{
					"channel": m.Channel,
					"payload": m.Payload,
				})
				if err := conn.WriteMessage(websocket.TextMessage, wrap); err != nil {
					return
				}
			}
		}
	}()

	// admin 发消息: { token, text }
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var inbound struct {
			Token string `json:"token"`
			Text  string `json:"text"`
		}
		if err := json.Unmarshal(data, &inbound); err != nil {
			continue
		}
		text := strings.TrimSpace(inbound.Text)
		if inbound.Token == "" || text == "" || len(text) > maxMsgLen {
			continue
		}
		persistAndPublish(ctx, inbound.Token, "admin:"+user.Username, text)
	}
}

// HTTP 入口:POST /admin/chat/threads/{token}/messages
// 给不想用 WS 的脚本/工单/邮件回复用
func sendAdminChat(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	if user == nil {
		writeErr(w, 401, "login required")
		return
	}
	token := r.PathValue("token")
	var req struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json")
		return
	}
	text := strings.TrimSpace(req.Text)
	if text == "" || len(text) > maxMsgLen {
		writeErr(w, 400, "text empty or too long")
		return
	}
	persistAndPublish(r.Context(), token, "admin:"+user.Username, text)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// GET /admin/chat/threads — 收件箱列表
func listChatThreads(w http.ResponseWriter, r *http.Request) {
	members, err := rdb.ZRevRangeWithScores(r.Context(), "chat:inbox", 0, 99).Result()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(members))
	for _, m := range members {
		token, _ := m.Member.(string)
		last, _ := rdb.LIndex(r.Context(), "chat:msgs:"+token, -1).Result()
		unread, _ := rdb.Get(r.Context(), "chat:unread_admin:"+token).Int64()
		userID := ""
		if info, _ := loadToken(r.Context(), token); info != nil {
			userID = info.UserID
		}
		entry := map[string]any{
			"token":   token,
			"user_id": userID,
			"unread":  unread,
			"last_at": int64(m.Score),
		}
		if last != "" {
			entry["last"] = json.RawMessage(last)
		}
		out = append(out, entry)
	}
	writeJSON(w, 200, out)
}

// GET /admin/chat/threads/{token}/messages — 单线程历史
func getChatHistory(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	msgs, _ := rdb.LRange(r.Context(), "chat:msgs:"+token, 0, -1).Result()
	out := make([]json.RawMessage, len(msgs))
	for i, m := range msgs {
		out[i] = json.RawMessage(m)
	}
	rdb.Del(r.Context(), "chat:unread_admin:"+token)
	writeJSON(w, 200, out)
}

// ---------- 共用:落库 + 广播 ----------

func persistAndPublish(ctx context.Context, token, from, text string) {
	msg := chatMsg{
		ID:   randomToken(6),
		From: from,
		Text: text,
		TS:   time.Now().UnixMilli(),
	}
	b, _ := json.Marshal(msg)

	pipe := rdb.Pipeline()
	pipe.RPush(ctx, "chat:msgs:"+token, b)
	pipe.LTrim(ctx, "chat:msgs:"+token, -1000, -1)
	pipe.ZAdd(ctx, "chat:inbox", redis.Z{Score: float64(msg.TS), Member: token})
	if from == "user" {
		pipe.Incr(ctx, "chat:unread_admin:"+token)
	} else {
		pipe.Incr(ctx, "chat:unread_user:"+token)
	}
	pipe.Publish(ctx, "chat.thread."+token, b)
	pipe.Publish(ctx, "chat.inbox", b)
	if _, err := pipe.Exec(ctx); err != nil {
		log.Printf("[chat] persist failed token=%s: %v", token, err)
	}
}
