package lib

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/deamwork/aws-aad/lib/saml"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"golang.org/x/net/publicsuffix"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"

	azPri "github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	azPub "github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
)

const (
	AADServerGlobal   = "login.microsoftonline.com"
	AADLauncherGlobal = "launcher.myapps.microsoft.com"
	AADServerCN       = "login.partner.microsoftonline.cn" // https://login.partner.microsoftonline.cn/login.srf?wa=wsignin1.0&whr=domain.tld
	AADServerDefault  = AADServerGlobal

	// deprecated; use AADServerGlobal
	AADServer = AADServerGlobal

	Timeout = time.Duration(60 * time.Second)
)

func GetAADDomain(region string) (string, error) {
	switch region {
	case "global":
		return AADServerGlobal, nil
	case "cn":
		return AADServerCN, nil
	}
	return "", fmt.Errorf("invalid region %s", region)
}

type AADClient struct {
	// Organization will be deprecated in the future
	Organization           string
	Username               string
	Password               string
	UserAuth               azPub.AuthResult
	UserCode               string
	AccessKeyId            string
	SecretAccessKey        string
	SessionToken           string
	Expiration             time.Time
	MiddlewareClientID     string
	MiddlewareClientSecret string
	CLIClientID            string
	CookieJar              http.CookieJar
	BaseURL                *url.URL
	Domain                 string
	MFAConfig              MFAConfig
}

func NewAADClient2(creds AADCreds, cookies AADCookies, mfaConfig MFAConfig) (*AADClient, error) {
	var domain string

	// maintain compatibility for deprecated creds.Organization
	if creds.Domain == "" && creds.Organization != "" {
		domain = AADServerDefault
	} else if creds.Domain != "" {
		domain = creds.Domain
	} else {
		return &AADClient{}, errors.New("either creds.Organization (deprecated) or creds.Domain must be set, but not both. To remedy this, re-add your credentials with `aws-aad add`")
	}

	// url parse & set base
	base, err := url.Parse(fmt.Sprintf("https://%s/%s", domain, creds.Organization))
	if err != nil {
		return nil, err
	}

	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil, err
	}

	if cookies.Session != "" {
		jar.SetCookies(base, []*http.Cookie{
			{
				Name:  "sid",
				Value: cookies.Session,
			},
		})
	}
	if cookies.DeviceToken != "" {
		jar.SetCookies(base, []*http.Cookie{
			{
				Name:  "DT",
				Value: cookies.DeviceToken,
			},
		})
	}
	log.Debug("domain: " + domain)

	return &AADClient{
		// Setting Organization for backwards compatibility
		Organization:           creds.Organization,
		Username:               creds.Username,
		Password:               creds.Password,
		MiddlewareClientID:     creds.MiddlewareClientID,
		MiddlewareClientSecret: creds.MiddlewareClientSecret,
		CLIClientID:            creds.CLIClientID,
		CookieJar:              jar,
		BaseURL:                base,
		Domain:                 domain,
		MFAConfig:              mfaConfig,
	}, nil
}

type AADProvider struct {
	Keyring            keyring.Keyring
	ProfileARN         string
	SessionDuration    time.Duration
	AADAwsTenant       string
	AADAwsClientID     string
	AADAwsClientSecret string
	// AADSessionCookieKey represents the name of the session cookie
	// to be stored in the keyring.
	AADSessionCookieKey string
	AADAccountName      string
	MFAConfig           MFAConfig
	AwsRegion           string
}

type MFAConfig struct {
	Provider   string // Which MFA provider to use when presented with an MFA challenge
	FactorType string // Which of the factor types of the MFA provider to use
	DuoDevice  string // Which DUO device to use for DUO MFA
}

type SAMLAssertion struct {
	Resp    *saml.Response `xml:"samlp:Response"`
	RawData []byte
}

type AADCreds struct {
	// Organization will be deprecated in the future
	Organization string
	Username     string
	Password     string
	Domain       string

	MiddlewareClientID     string
	MiddlewareClientSecret string
	CLIClientID            string
}

type AADCookies struct {
	Session     string
	DeviceToken string
}

func (p *AADProvider) Retrieve() (sts.Credentials, string, error) {
	log.Debugf("Using aad provider (%s)", p.AADAccountName)
	item, err := p.Keyring.Get(p.AADAccountName)
	if err == keyring.ErrKeyNotFound {
		return sts.Credentials{}, "", errors.New("AAD credentials are not in your keyring.  Please make sure you have added aad credentials with `aws-aad add`")
	}
	if err != nil {
		log.Debugf("Couldnt get aad creds from keyring: %s", err)
		return sts.Credentials{}, "", err
	}

	var aadCreds AADCreds
	if err = json.Unmarshal(item.Data, &aadCreds); err != nil {
		return sts.Credentials{}, "", errors.New("Failed to get aad credentials from your keyring.  Please make sure you have added aad credentials with `aws-aad add`")
	}

	// Check for stored session and device token cookies
	var cookies AADCookies
	cookieItem, err := p.Keyring.Get(p.AADSessionCookieKey)
	if err == nil {
		cookies.Session = string(cookieItem.Data)
	}
	cookieItem2, err := p.Keyring.Get("aad-device-token-cookie")
	if err == nil {
		cookies.DeviceToken = string(cookieItem2.Data)
	}

	aadClient, err := NewAADClient2(aadCreds, cookies, p.MFAConfig)
	if err != nil {
		return sts.Credentials{}, "", err
	}

	creds, newCookies, err := aadClient.AuthenticateProfile3(p.ProfileARN, p.SessionDuration, p.AwsRegion)
	if err != nil {
		return sts.Credentials{}, "", err
	}

	log.Debug("pAADSessionCookieKey: ", p.AADSessionCookieKey)

	newCookieItem := keyring.Item{
		Key:                         p.AADSessionCookieKey,
		Data:                        []byte(newCookies.Session),
		Label:                       "aad session cookie",
		KeychainNotTrustApplication: false,
	}

	p.Keyring.Set(newCookieItem)

	newCookieItem2 := keyring.Item{
		Key:                         "aad-device-token-cookie",
		Data:                        []byte(newCookies.DeviceToken),
		Label:                       "aad device token",
		KeychainNotTrustApplication: false,
	}

	p.Keyring.Set(newCookieItem2)

	return creds, aadCreds.Username, err
}

func (o *AADClient) AuthenticateUser(ctx context.Context, client azPub.Client, account azPub.Account, scopes []string) (err error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Step 1 : Basic authentication, request for device code
	log.Debug("Step: 1, request for device code")
	deviceCodeResult, err := client.AcquireTokenByDeviceCode(ctx, scopes)
	if err != nil {
		return fmt.Errorf("failed to authenticate with Azure AD. If your credentials have changed, use 'aws-aad add': %#v", err)
	}

	o.UserCode = deviceCodeResult.Result.UserCode

	log.Infof("Login in https://aka.ms/devicelogin (Cmd + Click) with code %s within 60 seconds", deviceCodeResult.Result.UserCode)
	o.UserAuth, err = deviceCodeResult.AuthenticationResult(context.Background())
	if err != nil {
		return fmt.Errorf("failed to authenticate with aad. Maybe exceeded with 60 seconds?: %#v", err)
	}

	// Step 2 : Exchange for access code
	log.Debug("Step: 2, exchange for access code")

	if o.UserAuth.AccessToken == "" {
		return fmt.Errorf("authentication failed for %s", o.Username)
	}

	return nil
}

func (o *AADClient) accountSelection(accounts []azPub.Account) azPub.Account {
	for _, account := range accounts {
		if account.PreferredUsername == o.Username {
			return account
		}
	}

	return azPub.Account{}
}

func (o *AADClient) azureInitCLI() (azPub.Client, azPub.Account, error) {
	authority := fmt.Sprintf("https://%s/%s", o.Domain, o.Organization)

	aad, err := azPub.New(o.CLIClientID, azPub.WithAuthority(authority))
	if err != nil {
		log.Error("Failed to start VM")
		return azPub.Client{}, azPub.Account{}, err
	}

	accounts, err := aad.Accounts(context.Background())
	if err != nil {
		log.Error("Failed to read cache")
		return aad, azPub.Account{}, err
	}

	return aad, o.accountSelection(accounts), err
}

func (o *AADClient) azureInitPrivate() (azPri.Client, error) {
	authority := fmt.Sprintf("https://%s/%s", o.Domain, o.Organization)
	cred, err := azPri.NewCredFromSecret(o.MiddlewareClientSecret)
	if err != nil {
		log.Fatal("unable parse secret, %v", err)
	}

	aad, err := azPri.New(authority, o.MiddlewareClientID, cred)
	if err != nil {
		log.Error("Failed to start private VM")
		return azPri.Client{}, err
	}

	return aad, err
}

func (o *AADClient) AuthenticateProfile3(profileARN string, duration time.Duration, region string) (sts.Credentials, AADCookies, error) {

	// Attempt to reuse session cookie
	var assertion SAMLAssertion
	var oc AADCookies
	var ctx = context.Background()

	scopes := []string{fmt.Sprintf("api://%s/user_impersonation", o.MiddlewareClientID)}

	client, account, err := o.azureInitCLI()
	if err != nil {
		return sts.Credentials{}, oc, err
	}

	o.UserAuth, err = client.AcquireTokenSilent(ctx, scopes, azPub.WithSilentAccount(account))
	if err != nil {
		log.Debug("Failed to reuse session token, starting flow from start")

		// Clear DT cookie before starting AuthN flow again. Bug #279.
		o.CookieJar.SetCookies(o.BaseURL, []*http.Cookie{{Name: "DT", MaxAge: -1}})

		if err := o.AuthenticateUser(ctx, client, account, scopes); err != nil {
			return sts.Credentials{}, oc, err
		}
	}

	// Step 3 : Get SAML Assertion and retrieve IAM Roles via o.UserAuth
	log.Debug("Step: 3, exchange code for SAML request")

	pClient, err := o.azureInitPrivate()
	if err != nil {
		return sts.Credentials{}, oc, err
	}
	log.Debug("Step: 3.1, pClient init ok")

	// exchange for SAML document
	result, err := pClient.AcquireTokenOnBehalfOf(
		ctx,
		o.UserAuth.AccessToken,
		//[]string{fmt.Sprintf("spn:%s/.default", o.CLIClientID)},
		//[]string{fmt.Sprintf("api://%s/.default", o.CLIClientID)},
		//[]string{fmt.Sprintf("spn:urn:amazon:webservices:cn-northwest-1/.default", o.CLIClientID)},
		[]string{"urn:amazon:webservices:cn-north-1/.default"},
		azPri.WithTokenType("urn:ietf:params:oauth:token-type:saml2"),
	)
	if err != nil {
		return sts.Credentials{}, oc, err
	}
	log.Debug("Step: 3.2, exchange OBO SAML document ok")
	//log.Debug(result.AccessToken)

	// decode with URL safe base64
	samlXML, err := base64.RawURLEncoding.DecodeString(result.AccessToken)
	if err != nil {
		log.Error(err)
		return sts.Credentials{}, oc, err
	}
	log.Debug("Step: 3.3.1, decode document ok")

	// Parse to assertion
	if err = ParseSAML(samlXML, &assertion, o.Organization); err != nil {
		log.Error(err)
		return sts.Credentials{}, oc, err
	}
	log.Debug("Step: 3.3.2, parse SAML ok")

	log.Debug("Step: 3.3, parse document ok")

	principal, role, err := GetRoleFromSAML(assertion.Resp, profileARN)
	if err != nil {
		return sts.Credentials{}, oc, err
	}

	log.Debug("Step: 3.3, GetRoleFromSAML() ok")

	// Step 4 : Assume Role with SAML
	log.Debug("Step 4: Assume Role with SAML")
	var samlSess *session.Session
	if region != "" {
		log.Debugf("Using region: %s\n", region)
		conf := &aws.Config{
			Region:              aws.String(region),
			STSRegionalEndpoint: endpoints.RegionalSTSEndpoint,
			LogLevel:            aws.LogLevel(aws.LogDebug),
		}
		samlSess = session.Must(session.NewSession(conf))
	} else {
		samlSess = session.Must(session.NewSession())
	}
	svc := sts.New(samlSess)

	samlParams := &sts.AssumeRoleWithSAMLInput{
		PrincipalArn:    aws.String(principal),
		RoleArn:         aws.String(role),
		SAMLAssertion:   aws.String(string(assertion.RawData)),
		DurationSeconds: aws.Int64(int64(duration.Seconds())),
	}

	samlResp, err := svc.AssumeRoleWithSAML(samlParams)
	if err != nil {
		log.WithField("role", role).Errorf(
			"error assuming role with SAML: %s", err.Error())
		return sts.Credentials{}, oc, err
	}

	cookies := o.CookieJar.Cookies(o.BaseURL)
	for _, cookie := range cookies {
		if cookie.Name == "sid" {
			oc.Session = cookie.Value
		}
		if cookie.Name == "DT" {
			oc.DeviceToken = cookie.Value
		}
	}

	return *samlResp.Credentials, oc, nil
}

func (p *AADProvider) GetSAMLLoginURL() (*url.URL, error) {
	item, err := p.Keyring.Get(p.AADAccountName)
	if err != nil {
		log.Debugf("couldnt get azPub ad creds from keyring: %s", err)
		return &url.URL{}, err
	}

	var aadCreds AADCreds
	if err = json.Unmarshal(item.Data, &aadCreds); err != nil {
		return &url.URL{}, errors.New("Failed to get aad credentials from your keyring.  Please make sure you have added aad credentials with `aws-aad add`")
	}

	var samlURL string

	// maintain compatibility for deprecated creds.Organization
	if aadCreds.Domain == "" && aadCreds.Organization != "" {
		samlURL = AADLauncherGlobal
	} else if aadCreds.Domain != "" {
		samlURL = aadCreds.Domain
	} else {
		return &url.URL{}, errors.New("either creds.Organization (deprecated) or creds.Domain must be set, but not both. To remedy this, re-add your credentials with `aws-aad add`")
	}

	fullSamlURL, err := url.Parse(fmt.Sprintf("https://%s/api/signin/%s?tenantId=%s", samlURL, aadCreds.MiddlewareClientID, aadCreds.Organization))

	if err != nil {
		return &url.URL{}, err
	}

	return fullSamlURL, nil
}
