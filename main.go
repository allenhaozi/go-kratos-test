package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"

	openapiclient "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	hydra "github.com/ory/hydra-client-go/client"
	hydra_admin "github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/client/public"
	hydra_models "github.com/ory/hydra-client-go/models"
	kratos "github.com/ory/kratos-client-go"
	log "github.com/sirupsen/logrus"
)

var ctx = context.Background()

//go:embed templates
var templates embed.FS

// templateData contains data for template
type templateData struct {
	Title   string
	UI      *kratos.UiContainer
	Details string
}

// server contains server information
type server struct {
	KratosAPIClient      *kratos.APIClient
	KratosPublicEndpoint string
	HydraAdminClient     *hydra.OryHydra
	HydraPublicClient    *hydra.OryHydra
	HydraPublicEndpoint  string
	Port                 string
}

func init() {
	log.SetLevel(log.DebugLevel)

	log.SetOutput(os.Stdout)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})

}

func main() {
	// create server
	s, err := NewServer(4433, 4445)
	if err != nil {
		log.Fatalln(err)
	}

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("/templates/static"))))

	http.HandleFunc("/login", s.handleLogin)
	http.HandleFunc("/logout", s.handleLogout)
	http.HandleFunc("/error", s.handleError)
	http.HandleFunc("/dashboard", s.handleDashboard)
	http.HandleFunc("/settings", s.ensureCookieFlowID("settings", s.handleSettings))

	http.HandleFunc("/auth/consent", s.handleHydraConsent)

	// start server
	log.Println("Auth Server listening on port 8000")
	log.Fatalln(http.ListenAndServe(":8000", http.DefaultServeMux))
}

// handleLogin handles login request from hydra and kratos login flow
func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {

	log.Infof("got request time:%v", time.Now().UnixNano())

	// get login challenge from url query parameters
	challenge := r.URL.Query().Get("login_challenge")
	flowID := r.URL.Query().Get("flow")
	// redirect to login page if there is no login challenge or flow id in url query parameters
	if challenge == "" && flowID == "" {

		b := make([]byte, 32)
		_, err := rand.Read(b)
		if err != nil {
			log.Errorf("generate state failed: %v", err)
			return
		}

		state := base64.StdEncoding.EncodeToString(b)

		response_type := r.URL.Query().Get("response_type")
		prompt := r.URL.Query().Get("prompt")
		//refresh_type := r.URL.Query().Get("refresh_type")
		client_id := r.URL.Query().Get("client_id")
		scope := r.URL.Query().Get("scope")
		redirect_uri := r.URL.Query().Get("redirect_uri")

		/*
			params := url.Values{
				//"response_type": []string{"code+token+id_token"},
				"response_type": []string{response_type},
				"prompt":        []string{"login"},
				"refresh_type":  []string{"code"},
				"client_id":     []string{"openaios-client-openid-03"},
				"scope":         []string{"openid"},
				"redirect_uri":  []string{"http://kratos.dev.openaios.4pd.io/iam-web/dashboard"},
				"state":         []string{state},
			}
		*/
		params := url.Values{
			"response_type": []string{response_type},
			"prompt":        []string{prompt},
			//"refresh_type":  []string{refresh_type},
			"client_id":    []string{client_id},
			"scope":        []string{scope},
			"redirect_uri": []string{redirect_uri},
			"state":        []string{state},
		}
		redirectTo := fmt.Sprintf("%s/oauth2/auth?", s.HydraPublicEndpoint) + params.Encode()
		log.Infof("redirect to hydra, url: %s", redirectTo)
		http.Redirect(w, r, redirectTo, http.StatusFound)
		return
		//log.Println("No login challenge found or flow ID found in URL Query Parameters")
		//writeError(w, http.StatusUnauthorized, errors.New("Unauthorized OAuth Client"))
		//return
	}

	// get login request from hydra only if there is no flow id in the url query parameters
	// check login challenge
	// TODO: Is it redundant?
	if flowID == "" {
		log.Infof("handler login flow id not found")

		params := hydra_admin.NewGetLoginRequestParamsWithContext(ctx)

		params.SetLoginChallenge(challenge)

		log.Infof("start get login flow request")

		_, err := s.HydraAdminClient.Admin.GetLoginRequest(params)

		if err != nil {
			log.Errorf("get login request failure,err:%v ", err.Error())
			writeError(w, http.StatusUnauthorized, errors.New("Unauthorized OAuth Client"))
			return
		}

		log.Infof("end get login flow request")
	}

	log.Infof("parse cookie")
	// get cookie from headers
	cookie := r.Header.Get("cookie")

	// check for kratos session details

	log.Infof("get session from cookie")
	session, _, err := s.KratosAPIClient.V0alpha2Api.ToSession(ctx).Cookie(cookie).Execute()

	// if there is no session, redirect to login page with login challenge
	if err != nil {
		log.Errorf("get session from cookie failure, err:%v", err)
		// build return_to url with hydra login challenge as url query parameter
		returnToParams := url.Values{
			"login_challenge": []string{challenge},
		}
		returnTo := "/iam-web/login?" + returnToParams.Encode()
		// build redirect url with return_to as url query parameter
		// refresh=true forces a new login from kratos regardless of browser sessions
		// this is important because we are letting Hydra handle sessions
		redirectToParam := url.Values{
			"return_to": []string{returnTo},
			"refresh":   []string{"true"},
		}
		redirectTo := fmt.Sprintf("%s/self-service/login/browser?", s.KratosPublicEndpoint) + redirectToParam.Encode()

		log.Errorf("redirect to login browser, url:%s", redirectTo)
		// get flowID from url query parameters
		flowID := r.URL.Query().Get("flow")

		// if there is no flow id in url query parameters, create a new flow
		if flowID == "" {
			http.Redirect(w, r, redirectTo, http.StatusFound)
			return
		}

		// get cookie from headers
		cookie := r.Header.Get("cookie")
		// get the login flow
		flow, _, err := s.KratosAPIClient.V0alpha2Api.GetSelfServiceLoginFlow(ctx).Id(flowID).Cookie(cookie).Execute()
		if err != nil {
			log.Errorf("get login flow error:%s", err.Error())
			writeError(w, http.StatusUnauthorized, err)
			return
		}
		templateData := templateData{
			Title: "Login",
			UI:    &flow.Ui,
		}
		log.Infof("render login template")
		// render template index.html
		templateData.Render(w)
		return
	}

	log.Infof("login handler got session:%v", session)

	// if there is a valid session, marshal session.identity.traits to json to be stored in subject
	traitsJSON, err := json.Marshal(session.Identity.Traits)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	subject := string(traitsJSON)

	loginAcceptParam := hydra_admin.NewAcceptLoginRequestParams()

	loginAcceptParam.SetContext(ctx)
	loginAcceptParam.SetLoginChallenge(challenge)

	body := &hydra_models.AcceptLoginRequest{
		Remember:    true,
		RememberFor: 3600,
		Subject:     &subject,
	}

	loginAcceptParam.SetBody(body)

	// accept hydra login request
	res, err := s.HydraAdminClient.Admin.AcceptLoginRequest(loginAcceptParam)

	if err != nil {
		log.Errorf("accept login request failure,err:%v", err)
		writeError(w, http.StatusUnauthorized, errors.New("Unauthorized OAuth Client"))
		return
	}

	log.Infof("login success, redirect to consent page: %s", *res.GetPayload().RedirectTo)

	http.Redirect(w, r, *res.GetPayload().RedirectTo, http.StatusFound)
}

// handleLogout handles kratos logout flow
func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// get cookie from headers
	cookie := r.Header.Get("cookie")
	// create self-service logout flow for browser
	flow, _, err := s.KratosAPIClient.V0alpha2Api.CreateSelfServiceLogoutFlowUrlForBrowsers(ctx).Cookie(cookie).Execute()
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	// redirect to logout url if session is valid
	if flow != nil {
		http.Redirect(w, r, flow.LogoutUrl, http.StatusFound)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// handleError handles login/registration error
func (s *server) handleError(w http.ResponseWriter, r *http.Request) {
	// get url query parameters
	msg := r.URL.Query().Get("error")
	// get error details
	templateData := templateData{
		Title:   "Error",
		Details: msg,
	}
	// render template index.html
	templateData.Render(w)
}

// handleSettings handles kratos settings flow
func (s *server) handleSettings(w http.ResponseWriter, r *http.Request, cookie, flowID string) {
	// get self-service recovery flow for browser
	flow, _, err := s.KratosAPIClient.V0alpha2Api.GetSelfServiceSettingsFlow(ctx).Id(flowID).Cookie(cookie).Execute()
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}

	templateData := templateData{
		Title: "Settings",
		UI:    &flow.Ui,
	}
	// render template index.html
	templateData.Render(w)
}

// handleDashboard shows dashboard
func (s *server) handleDashboard(w http.ResponseWriter, r *http.Request) {

	response := map[string]interface{}{}

	{
		// get cookie from headers
		cookie := r.Header.Get("cookie")
		// get session details
		session, _, err := s.KratosAPIClient.V0alpha2Api.ToSession(ctx).Cookie(cookie).Execute()
		if err != nil {
			http.Redirect(w, r, "/iam-web/login", http.StatusFound)
			return
		}
		response["session"] = session
	}

	{
		code := r.URL.Query().Get("code")
		response["code"] = code

		params := &public.Oauth2TokenParams{}

		clientID := "openaios-client-openid-04"
		redirectURI := "http://kratos.dev.openaios.4pd.io/iam-web/dashboard"

		params.SetClientID(&clientID)
		params.SetCode(&code)
		params.WithContext(ctx)
		params.SetGrantType("authorization_code")
		params.SetRedirectURI(&redirectURI)

		log.Infof("request hydra for token, request params: %+v", params)
		log.Infof("request hydra for token, request params.code: %+v", *params.Code)
		log.Infof("request hydra for token, request params.redirect: %+v", *params.RedirectURI)
		log.Infof("request hydra for token, request params.grant_type: %+v", params.GrantType)
		log.Infof("request hydra for token, request params.clientID: %+v", *params.ClientID)

		//s.HydraAPIClient.SetTransport(transport runtime.ClientTransport)

		//info := openapiclient.BasicAuth("client_secret", "openaios-client-secret")
		info := openapiclient.BasicAuth("openaios-client-openid-04", "openaios-client-secret")

		//info := httptransport.BasicAuth(clientID, "openaios-client-secret")
		//info := openapiclient.APIKeyAuth("client_secret", "query", "openaios-client-secret")

		res, err := s.HydraPublicClient.Public.Oauth2Token(params, info)
		if err != nil {
			log.Errorf("request hydra for token failure,err:%v", err)
			response["oauth2token_error"] = err.Error()
		} else {
			response["Oauth2Token"] = res
		}

	}

	{
		errMsg := r.URL.Query().Get("error_description")
		response["error_description"] = errMsg
	}

	// marshal session to json
	sessionJSON, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	templateData := templateData{
		Title:   "Session Details",
		Details: string(sessionJSON),
	}
	// render template index.html
	templateData.Render(w)
}

// handleHydraConsent shows hydra consent screen
func (s *server) handleHydraConsent(w http.ResponseWriter, r *http.Request) {
	// get consent challenge from url query parameters
	challenge := r.URL.Query().Get("consent_challenge")

	if challenge == "" {
		log.Println("Missing consent challenge")
		writeError(w, http.StatusUnauthorized, errors.New("Unauthorized OAuth Client"))
		return
	}

	consentGetParams := hydra_admin.NewGetConsentRequestParams()
	consentGetParams.WithContext(ctx)
	consentGetParams.SetConsentChallenge(challenge)

	// get consent request
	getConsentRes, err := s.HydraAdminClient.Admin.GetConsentRequest(consentGetParams)

	if err != nil {
		log.Println(err)
		writeError(w, http.StatusUnauthorized, errors.New("Unauthorized OAuth Client"))
		return
	}

	skip := getConsentRes.GetPayload().Skip
	log.Infof("consent page get consent request by consent challenge,skip:%v", skip)

	// demo stage, so skip always is true
	skip = true
	if skip {

		log.Infof("consent request scope value: %v", getConsentRes.GetPayload().RequestedScope)
		// Now it's time to grant the consent request.
		// You could also deny the request if something went terribly wrong
		consentAcceptBody := &hydra_models.AcceptConsentRequest{
			GrantAccessTokenAudience: getConsentRes.GetPayload().RequestedAccessTokenAudience,
			GrantScope:               getConsentRes.GetPayload().RequestedScope,
		}

		consentAcceptParams := hydra_admin.NewAcceptConsentRequestParams()
		consentAcceptParams.WithContext(ctx)
		consentAcceptParams.SetConsentChallenge(challenge)
		consentAcceptParams.WithBody(consentAcceptBody)

		consentAcceptResp, err := s.HydraAdminClient.Admin.AcceptConsentRequest(consentAcceptParams)

		if err != nil {
			log.Errorf("accept consent failure, err:%v", err)
			writeError(w, http.StatusUnauthorized, errors.New("Unauthorized OAuth Client"))
		}

		log.Infof("process consent success, redirect to:%s", *consentAcceptResp.GetPayload().RedirectTo)

		http.Redirect(w, r, *consentAcceptResp.GetPayload().RedirectTo, http.StatusFound)
	}

}

func NewServer(kratosPublicEndpointPort, hydraPublicEndpointPort int) (*server, error) {
	// create a new kratos client for self hosted server
	conf := kratos.NewConfiguration()
	conf.Servers = kratos.ServerConfigurations{{URL: "http://kratos.dev.openaios.4pd.io"}}
	cj, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	conf.HTTPClient = &http.Client{Jar: cj}

	return &server{
		KratosAPIClient:      kratos.NewAPIClient(conf),
		KratosPublicEndpoint: "http://kratos.dev.openaios.4pd.io",
		HydraAdminClient: hydra.NewHTTPClientWithConfig(strfmt.Default, &hydra.TransportConfig{
			BasePath: "/",
			Host:     "admin.hydra.dev.openaios.4pd.io",
			Schemes:  []string{"http"},
		}),
		HydraPublicClient: hydra.NewHTTPClientWithConfig(strfmt.Default, &hydra.TransportConfig{
			BasePath: "/",
			Host:     "hydra.dev.openaios.4pd.io",
			Schemes:  []string{"http"},
		}),

		HydraPublicEndpoint: "http://hydra.dev.openaios.4pd.io",
		Port:                ":80",
	}, nil
}

// writeError writes error to the response
func writeError(w http.ResponseWriter, statusCode int, err error) {
	w.WriteHeader(statusCode)
	if _, e := w.Write([]byte(err.Error())); e != nil {
		log.Fatal(err)
	}
}

// ensureCookieFlowID is a middleware function that ensures that a request contains
// flow ID in url query parameters and cookie in header
func (s *server) ensureCookieFlowID(flowType string, next func(w http.ResponseWriter, r *http.Request, cookie, flowID string)) http.HandlerFunc {
	// create redirect url based on flow type
	redirectURL := fmt.Sprintf("%s/self-service/%s/browser", s.KratosPublicEndpoint, flowType)

	return func(w http.ResponseWriter, r *http.Request) {
		// get flowID from url query parameters
		flowID := r.URL.Query().Get("flow")
		// if there is no flow id in url query parameters, create a new flow
		if flowID == "" {
			http.Redirect(w, r, redirectURL, http.StatusFound)
			return
		}

		// get cookie from headers
		cookie := r.Header.Get("cookie")
		// if there is no cookie in header, return error
		if cookie == "" {
			writeError(w, http.StatusBadRequest, errors.New("missing cookie"))
			return
		}

		// call next handler
		next(w, r, cookie, flowID)
	}
}

// ensureCookieReferer is a middleware function that ensures that cookie in header contains csrf_token and referer is not empty
func ensureCookieReferer(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// get cookie from headers
		cookie := r.Header.Get("cookie")
		// if there is no csrf_token in cookie, return error
		if !strings.Contains(cookie, "csrf_token") {
			writeError(w, http.StatusUnauthorized, errors.New(http.StatusText(int(http.StatusUnauthorized))))
			return
		}

		// get referer from headers
		referer := r.Header.Get("referer")
		// if there is no referer in header, return error
		if referer == "" {
			writeError(w, http.StatusBadRequest, errors.New(http.StatusText(int(http.StatusUnauthorized))))
			return
		}

		// call next handler
		next(w, r)
	}
}

// Render renders template with provided data
func (td *templateData) Render(w http.ResponseWriter) {
	// render template index.html
	tmpl := template.Must(template.ParseFS(templates, "templates/index.html"))
	if err := tmpl.Execute(w, td); err != nil {
		writeError(w, http.StatusInternalServerError, err)
	}
}
