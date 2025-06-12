// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package mockusso

import (
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/julienschmidt/httprouter"
	"github.com/mhilton/openid/openid2"
)

type User struct {
	ID       string
	NickName string
	FullName string
	Email    string
	Groups   []string

	// OAuth Credentials
	ConsumerSecret string
	TokenKey       string
	TokenSecret    string
}

// Handler is a http.Handler that provides a mock implementation of
// Ubuntu SSO. It is designed to closely match the responses provided by
// Ubuntu SSO providing openid login and oauth verification.
type Handler struct {
	openidUser        string
	users             map[string]*User
	router            *httprouter.Router
	location          string
	excludeExtensions bool
}

func New(location string) *Handler {
	h := &Handler{
		users:    map[string]*User{},
		router:   httprouter.New(),
		location: location,
	}
	openidHandler := &openid2.Handler{
		Login: h,
	}
	h.router.GET("/", h.root)
	h.router.HEAD("/", h.root)
	h.router.GET("/+xrds", h.xrds)
	h.router.GET("/+id/:id", h.id)
	h.router.HEAD("/+id/:id", h.id)
	h.router.GET("/+id/:id/+xrds", h.xrdsid)
	h.router.Handler("GET", "/+openid", openidHandler)
	h.router.Handler("POST", "/+openid", openidHandler)
	h.router.POST("/api/v2/requests/validate", h.validate)
	h.router.NotFound = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "could not find %s\n", req.URL)
	})
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.router.ServeHTTP(w, r)
}

// Login handles OpenID login requests.
func (h *Handler) Login(_ http.ResponseWriter, _ *http.Request, lr *openid2.LoginRequest) (*openid2.LoginResponse, error) {
	u := h.users[h.openidUser]
	var extensions []openid2.Extension
	if !h.excludeExtensions {
		extensions = []openid2.Extension{{
			Namespace: "http://openid.net/extensions/sreg/1.1",
			Prefix:    "sreg",
			Params: map[string]string{
				"nickname": u.NickName,
				"fullname": u.FullName,
				"email":    u.Email,
			},
		}, {
			Namespace: "http://ns.launchpad.net/2007/openid-teams",
			Prefix:    "lp",
			Params: map[string]string{
				"is_member": strings.Join(u.Groups, ","),
			},
		}}
	}
	return &openid2.LoginResponse{
		Identity:   h.location + "/+id/" + h.openidUser,
		ClaimedID:  h.location + "/+id/" + h.openidUser,
		OPEndpoint: h.location + "/+openid",
		Extensions: extensions,
	}, nil
}

// AddUser adds u to the handles user database.
func (h *Handler) AddUser(u *User) {
	h.users[u.ID] = u
}

// Reset sets all of the state in the Handler back to the default. This
// should be called between tests.
func (h *Handler) Reset() {
	h.users = map[string]*User{}
	h.openidUser = ""
	h.excludeExtensions = false
}

// SetLoginUser sets the user that is logged in when an OpenID request is
// recieved.
func (h *Handler) SetLoginUser(user string) {
	if _, ok := h.users[user]; !ok {
		panic("no such user: " + user)
	}
	h.openidUser = user
}

// ExcludeExtensions prevents an OpenID login response from including any
// extensions.
func (h *Handler) ExcludeExtensions() {
	h.excludeExtensions = true
}

func (h *Handler) root(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("X-Xrds-Location", h.location+"/+xrds")
	content := `<html><head><title>Mock UbuntuSSO</title></head><body></body><html>`
	w.Header().Set("Content-Length", fmt.Sprint(len(content)))
	if r.Method == "HEAD" {
		return
	}
	w.Write([]byte(content))
}

func (h *Handler) xrds(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	w.Header().Set("Content-Type", "application/xrds+xml")
	w.Write([]byte(`<?xml version="1.0"?>
<xrds:XRDS
    xmlns="xri://$xrd*($v*2.0)"
    xmlns:xrds="xri://$xrds">
  <XRD>
    <Service priority="0">
      <Type>http://specs.openid.net/auth/2.0/server</Type>
      <Type>http://openid.net/srv/ax/1.0</Type>
      <Type>http://openid.net/extensions/sreg/1.1</Type>
      <Type>http://ns.launchpad.net/2007/openid-teams</Type>
      <URI>` + h.location + `/+openid</URI>
    </Service>
  </XRD>
</xrds:XRDS>`))
}

func (h *Handler) id(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	id := p.ByName("id")
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("X-Xrds-Location", fmt.Sprintf("%s/+id/%s/+xrds", h.location, id))
	content := fmt.Sprintf(`<html><head><title>Mock UbuntuSSO</title></head><body><p>%s</p></body><html>`, id)
	w.Header().Set("Content-Length", fmt.Sprint(len(content)))
	if r.Method == "HEAD" {
		return
	}
	w.Write([]byte(content))
}

func (h *Handler) xrdsid(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	id := p.ByName("id")
	w.Header().Set("Content-Type", "application/xrds+xml")
	fmt.Fprintf(w, `<?xml version="1.0"?>
<xrds:XRDS
    xmlns="xri://$xrd*($v*2.0)"
    xmlns:xrds="xri://$xrds">
  <XRD>
    <Service priority="0">
      <Type>http://specs.openid.net/auth/2.0/signon</Type>
      <URI>`+h.location+`/+openid</URI>
      <LocalID>`+h.location+`+id/%s</LocalID>
    </Service>
  </XRD>
</xrds:XRDS>
`, id)
}

func (h *Handler) validate(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	var response struct {
		IsValid bool   `json:"is_valid"`
		Error   string `json:"error,omitempty"`
	}
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		response.Error = fmt.Sprintf("error parsing Content-Type: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		enc.Encode(response)
		return
	}
	if mt != "application/json" {
		response.Error = fmt.Sprintf("incorrect content type %q", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusBadRequest)
		enc.Encode(response)
		return
	}
	buf, err := io.ReadAll(r.Body)
	if err != nil {
		response.Error = fmt.Sprintf("error reading request: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		enc.Encode(response)
		return
	}
	var request struct {
		URL           string `json:"http_url"`
		Method        string `json:"http_method"`
		Authorization string `json:"authorization"`
		QueryString   string `json:"query_string"`
	}
	if err := json.Unmarshal(buf, &request); err != nil {
		response.Error = fmt.Sprintf("error reading request: %s", err)
		w.WriteHeader(http.StatusBadRequest)
		enc.Encode(response)
		return
	}
	params := parseOAuth(request.Authorization)
	// For now just check the keys are ones we know about.
	user := h.users[params["oauth_consumer_key"]]
	if user == nil {
		enc.Encode(response)
		return
	}
	if user.TokenKey != params["oauth_token"] {
		enc.Encode(response)
		return
	}
	response.IsValid = true
	enc.Encode(response)
	return
}

// parse the OAuth Authorization header see
// http://tools.ietf.org/html/rfc5849#section-3.1
func parseOAuth(oauth string) map[string]string {
	oauth = strings.TrimSpace(oauth)
	parts := strings.SplitN(oauth, " ", 2)
	if !strings.EqualFold(parts[0], "OAuth") {
		return nil
	}
	params := strings.Split(parts[1], ",")
	parsed := make(map[string]string, len(params))
	for _, p := range params {
		p = strings.TrimSpace(p)
		parts := strings.SplitN(p, "=", 2)
		v := strings.TrimPrefix(parts[1], `"`)
		v = strings.TrimSuffix(v, `"`)
		parsed[parts[0]] = v
	}
	return parsed
}
