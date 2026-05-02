package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

const dockerHubAPI = "https://hub.docker.com/v2"

// 默认代理地址,如果不需要代理留空字符串即可。
// 可通过环境变量 PROXY_URL 覆盖,例如:PROXY_URL=http://127.0.0.1:7890 ./main
// 也可以走标准的 HTTP_PROXY / HTTPS_PROXY 环境变量(下面 fallback 自动生效)
const defaultProxyURL = "http://127.0.0.1:7890"

// httpClient 在 main 启动时初始化(因为要根据环境变量配代理)
var httpClient *http.Client

// newHTTPClient 根据环境变量 / 默认值创建带代理的 client
func newHTTPClient() *http.Client {
	transport := &http.Transport{
		// 默认值会读 HTTP_PROXY / HTTPS_PROXY / NO_PROXY 环境变量
		Proxy:               http.ProxyFromEnvironment,
		MaxIdleConns:        20,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	// 优先级:PROXY_URL 环境变量 > 代码里写死的 defaultProxyURL > 标准 HTTP(S)_PROXY
	proxy := strings.TrimSpace(os.Getenv("PROXY_URL"))
	if proxy == "" && defaultProxyURL != "" {
		proxy = defaultProxyURL
	}

	if proxy != "" {
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			log.Printf("[warn] invalid PROXY_URL %q, fallback to env: %v", proxy, err)
		} else {
			transport.Proxy = http.ProxyURL(proxyURL)
			log.Printf("[info] using proxy: %s", proxy)
		}
	} else {
		log.Printf("[info] no proxy configured (will respect HTTP_PROXY/HTTPS_PROXY env if set)")
	}

	return &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}
}

// ---------- Docker Hub API 响应结构 ----------

type Repository struct {
	User        string `json:"user"`
	Name        string `json:"name"`
	Namespace   string `json:"namespace"`
	Description string `json:"description"`
	IsPrivate   bool   `json:"is_private"`
	StarCount   int    `json:"star_count"`
	PullCount   int64  `json:"pull_count"`
	LastUpdated string `json:"last_updated"`
}

type TagImage struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Size         int64  `json:"size"`
	Digest       string `json:"digest"`
}

type Tag struct {
	Name        string     `json:"name"`
	FullSize    int64      `json:"full_size"`
	LastUpdated string     `json:"last_updated"`
	Images      []TagImage `json:"images"`
}

type TagsResponse struct {
	Count    int    `json:"count"`
	Next     string `json:"next"`
	Previous string `json:"previous"`
	Results  []Tag  `json:"results"`
}

// ---------- 对外响应结构 ----------

type ExistsData struct {
	Exists     bool        `json:"exists"`
	Repository *Repository `json:"repository,omitempty"`

	// Available=false 表示上游(hub.docker.com)不可达。
	// 前端用来渲染"暂时无法访问"占位,而不是红色 error。
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"` // upstream_unavailable
}

type TagsData struct {
	Image    string `json:"image"`
	Page     int    `json:"page"`
	PageSize int    `json:"page_size"`
	Total    int    `json:"total"`
	HasNext  bool   `json:"has_next"`
	HasPrev  bool   `json:"has_prev"`
	Tags     []Tag  `json:"tags"`

	// Available=false 表示上游不可用(404 或网络/5xx 故障)。
	// 前端用来渲染友好占位,而不是红色 error。
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"` // not_found | upstream_unavailable
}

// ---------- 请求参数 ----------

type ExistsQuery struct {
	Image string `form:"image" binding:"required"`
}

type TagsQuery struct {
	Image    string `form:"image" binding:"required"`
	Page     int    `form:"page,default=1" binding:"omitempty,min=1"`
	PageSize int    `form:"page_size,default=10" binding:"omitempty,min=1,max=100"`
	Name     string `form:"name"`
}

// ---------- 工具函数 ----------

func parseImageName(image string) (string, string, error) {
	image = strings.TrimSpace(image)
	if image == "" {
		return "", "", fmt.Errorf("image name cannot be empty")
	}
	parts := strings.SplitN(image, "/", 2)
	if len(parts) == 1 {
		return "library", parts[0], nil
	}
	return parts[0], parts[1], nil
}

func okResp(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, gin.H{
		"code":    0,
		"message": "ok",
		"data":    data,
	})
}

func errResp(c *gin.Context, status int, msg string) {
	c.JSON(status, gin.H{
		"code":    status,
		"message": msg,
	})
}

// ---------- Docker Hub 调用 ----------

// errNotFound 表示上游 Docker Hub 返回 404,这是一个"业务"上的可预期结果,
// 而不是真正的报错 — 前端会渲染成友好的"未找到"占位,而不是红色 error box。
var errNotFound = fmt.Errorf("not found")

func checkImageExists(namespace, repository string) (bool, *Repository, error) {
	apiURL := fmt.Sprintf("%s/repositories/%s/%s/", dockerHubAPI, namespace, repository)
	resp, err := httpClient.Get(apiURL)
	if err != nil {
		log.Printf("[upstream] GET %s failed: %v", apiURL, err)
		return false, nil, fmt.Errorf("request docker hub failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return false, nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("[upstream] GET %s returned %d: %s", apiURL, resp.StatusCode, strings.TrimSpace(string(body)))
		return false, nil, fmt.Errorf("docker hub returned %d", resp.StatusCode)
	}

	var repo Repository
	if err := json.NewDecoder(resp.Body).Decode(&repo); err != nil {
		log.Printf("[upstream] decode %s failed: %v", apiURL, err)
		return false, nil, fmt.Errorf("decode response failed: %w", err)
	}
	return true, &repo, nil
}

func listImageTags(namespace, repository string, page, pageSize int, name string) (*TagsResponse, error) {
	params := url.Values{}
	params.Set("page", strconv.Itoa(page))
	params.Set("page_size", strconv.Itoa(pageSize))
	if name = strings.TrimSpace(name); name != "" {
		params.Set("name", name)
	}

	apiURL := fmt.Sprintf("%s/repositories/%s/%s/tags/?%s",
		dockerHubAPI, namespace, repository, params.Encode())

	resp, err := httpClient.Get(apiURL)
	if err != nil {
		log.Printf("[upstream] GET %s failed: %v", apiURL, err)
		return nil, fmt.Errorf("request docker hub failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, errNotFound
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("[upstream] GET %s returned %d: %s", apiURL, resp.StatusCode, strings.TrimSpace(string(body)))
		return nil, fmt.Errorf("docker hub returned %d", resp.StatusCode)
	}

	var tagsResp TagsResponse
	if err := json.NewDecoder(resp.Body).Decode(&tagsResp); err != nil {
		log.Printf("[upstream] decode %s failed: %v", apiURL, err)
		return nil, fmt.Errorf("decode response failed: %w", err)
	}
	return &tagsResp, nil
}

// ---------- Handlers ----------

func handleExists(c *gin.Context) {
	var q ExistsQuery
	if err := c.ShouldBindQuery(&q); err != nil {
		errResp(c, http.StatusBadRequest, err.Error())
		return
	}
	namespace, repository, err := parseImageName(q.Image)
	if err != nil {
		errResp(c, http.StatusBadRequest, err.Error())
		return
	}
	exists, repo, err := checkImageExists(namespace, repository)
	if err != nil {
		// 上游不可达:错误已在 checkImageExists 内部 log 过,这里返回友好占位响应。
		okResp(c, ExistsData{Exists: false, Available: false, Reason: "upstream_unavailable"})
		return
	}
	okResp(c, ExistsData{Exists: exists, Repository: repo, Available: true})
}

func handleTags(c *gin.Context) {
	var q TagsQuery
	if err := c.ShouldBindQuery(&q); err != nil {
		errResp(c, http.StatusBadRequest, err.Error())
		return
	}
	namespace, repository, err := parseImageName(q.Image)
	if err != nil {
		errResp(c, http.StatusBadRequest, err.Error())
		return
	}
	imageRef := fmt.Sprintf("%s/%s", namespace, repository)
	tagsResp, err := listImageTags(namespace, repository, q.Page, q.PageSize, q.Name)
	if err != nil {
		// 不论 404 还是上游 5xx/网络故障,都给前端返回 200 + Available=false。
		// 真正的错误细节已在 listImageTags 内部 log。
		reason := "upstream_unavailable"
		if err == errNotFound {
			reason = "not_found"
		}
		okResp(c, TagsData{
			Image:     imageRef,
			Page:      q.Page,
			PageSize:  q.PageSize,
			Available: false,
			Reason:    reason,
		})
		return
	}
	okResp(c, TagsData{
		Image:     imageRef,
		Page:      q.Page,
		PageSize:  q.PageSize,
		Total:     tagsResp.Count,
		HasNext:   tagsResp.Next != "",
		HasPrev:   tagsResp.Previous != "",
		Tags:      tagsResp.Results,
		Available: true,
	})
}

// ---------- main ----------

func main() {
	// gin.SetMode(gin.ReleaseMode)

	// 初始化 HTTP 客户端(带代理配置)
	httpClient = newHTTPClient()

	r := gin.Default()
	r.Use(cors.Default())

	// 健康检查
	r.GET("/health", func(c *gin.Context) {
		okResp(c, gin.H{"status": "up"})
	})

	// API 路由
	api := r.Group("/api/image")
	{
		api.GET("/exists", handleExists)
		api.GET("/tags", handleTags)
	}

	// 静态前端文件托管:把 web/ 目录下整个挂到根路径
	// 访问 http://localhost:8080/ 会自动加载 web/index.html
	r.StaticFile("/", "./web/index.html")
	r.Static("/static", "./web")

	addr := ":8080"
	log.Printf("Docker Hub query service is listening on http://localhost%s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
