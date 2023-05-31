package lib

import (
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

	azure "github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
)

const (
	AADServerGlobal  = "login.microsoftonline.com"
	AADServerCN      = "login.partner.microsoftonline.cn" // https://login.partner.microsoftonline.cn/login.srf?wa=wsignin1.0&whr=domain.tld
	AADServerDefault = AADServerGlobal

	// deprecated; use AADServerGlobal
	AADServer = AADServerGlobal

	Timeout = time.Duration(60 * time.Second)
)

type AADClient struct {
	// Organization will be deprecated in the future
	Organization    string
	Username        string
	Password        string
	UserAuth        azure.AuthResult
	AccessKeyId     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
	AADAwsSAMLUrl   string
	AADAwsClientID  string
	AADAwsTenant    string
	CookieJar       http.CookieJar
	BaseURL         *url.URL
	Domain          string
	MFAConfig       MFAConfig
}

func NewAADClient2(creds AADCreds, aadAwsSAMLUrl, aadAwsTenant, aadAwsClientID string, cookies AADCookies, mfaConfig MFAConfig) (*AADClient, error) {
	var domain string

	// maintain compatibility for deprecated creds.Organization
	if creds.Domain == "" && creds.Organization != "" {
		domain = fmt.Sprintf("%s.%s", creds.Organization, AADServerDefault)
	} else if creds.Domain != "" {
		domain = creds.Domain
	} else {
		return &AADClient{}, errors.New("either creds.Organization (deprecated) or creds.Domain must be set, but not both. To remedy this, re-add your credentials with `aws-aad add`")
	}

	// url parse & set base
	base, err := url.Parse(fmt.Sprintf(
		"https://%s%s", domain, aadAwsTenant,
	))
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
		Organization:   creds.Organization,
		Username:       creds.Username,
		Password:       creds.Password,
		AADAwsSAMLUrl:  aadAwsSAMLUrl,
		AADAwsClientID: aadAwsClientID,
		AADAwsTenant:   aadAwsTenant,
		CookieJar:      jar,
		BaseURL:        base,
		Domain:         domain,
		MFAConfig:      mfaConfig,
	}, nil
}

type AADProvider struct {
	Keyring         keyring.Keyring
	ProfileARN      string
	SessionDuration time.Duration
	AADAwsSAMLUrl   string
	AADAwsTenant    string
	AADAwsClientID  string
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
	Resp    *saml.Response
	RawData []byte
}

type AADCreds struct {
	// Organization will be deprecated in the future
	Organization string
	Username     string
	Password     string
	Domain       string
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

	aadClient, err := NewAADClient2(aadCreds, p.AADAwsSAMLUrl, p.AADAwsTenant, p.AADAwsClientID, cookies, p.MFAConfig)
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

func (o *AADClient) AuthenticateUser(client azure.Client, account azure.Account, scopes []string) (err error) {
	// Step 1 : Basic authentication
	log.Debug("Step: 1")
	o.UserAuth, err = client.AcquireTokenByDeviceCode(
		context.Background(),
		scopes,
		o.Username,
		o.Password,
	)
	if err != nil {
		return fmt.Errorf("Failed to authenticate with okta. If your credentials have changed, use 'aws-aad add': %#v", err)
	}

	// Step 2 : Challenge MFA if needed
	log.Debug("Step: 2")
	if o.UserAuth.Status == "MFA_REQUIRED" {
		log.Info("Requesting MFA. Please complete two-factor authentication with your second device")
		if err = o.challengeMFA(); err != nil {
			return err
		}
	}

	if o.UserAuth.SessionToken == "" {
		return fmt.Errorf("authentication failed for %s", o.Username)
	}

	return nil
}

func (o *AADClient) accountSelection(accounts []azure.Account) azure.Account {
	for _, account := range accounts {
		if account.PreferredUsername == o.Username {
			return account
		}
	}

	return azure.Account{}
}

func (o *AADClient) azureInit() (azure.Client, azure.Account, error) {
	authority := fmt.Sprintf("https://%s%s/%s", AADServerDefault, o.AADAwsSAMLUrl, o.AADAwsTenant)

	aad, err := azure.New(o.AADAwsClientID, azure.WithAuthority(authority))
	if err != nil {
		log.Error("Failed to start VM")
		return azure.Client{}, azure.Account{}, err
	}

	accounts, err := aad.Accounts(context.Background())
	if err != nil {
		log.Error("Failed to read cache")
		return aad, azure.Account{}, err
	}

	return aad, o.accountSelection(accounts), err
}

func (o *AADClient) AuthenticateProfile3(profileARN string, duration time.Duration, region string) (sts.Credentials, AADCookies, error) {

	// Attempt to reuse session cookie
	var assertion SAMLAssertion
	var oc AADCookies
	scopes := []string{fmt.Sprintf("api://%s/user_impersonation", o.AADAwsClientID)}

	client, account, err := o.azureInit()
	if err != nil {
		return sts.Credentials{}, oc, err
	}

	authResult, err := client.AcquireTokenSilent(
		context.Background(),
		scopes,
		azure.WithSilentAccount(account),
	)
	if err != nil {
		log.Debug("Failed to reuse session token, starting flow from start")

		// Clear DT cookie before starting AuthN flow again. Bug #279.
		o.CookieJar.SetCookies(o.BaseURL, []*http.Cookie{
			{
				Name:   "DT",
				MaxAge: -1,
			},
		})

		if err := o.AuthenticateUser(client, account, scopes); err != nil {
			return sts.Credentials{}, oc, err
		}

		// Step 3 : Get SAML Assertion and retrieve IAM Roles
		log.Debug("Step: 3")
		if err = o.Get("GET", o.OktaAwsSAMLUrl+"?onetimetoken="+o.UserAuth.SessionToken,
			nil, &assertion, "saml"); err != nil {
			return sts.Credentials{}, oc, err
		}
	}

	principal, role, err := GetRoleFromSAML(assertion.Resp, profileARN)
	if err != nil {
		return sts.Credentials{}, oc, err
	}

	// Step 4 : Assume Role with SAML
	log.Debug("Step 4: Assume Role with SAML")
	var samlSess *session.Session
	if region != "" {
		log.Debugf("Using region: %s\n", region)
		conf := &aws.Config{
			Region:              aws.String(region),
			STSRegionalEndpoint: endpoints.RegionalSTSEndpoint,
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
		log.Debugf("couldnt get azure ad creds from keyring: %s", err)
		return &url.URL{}, err
	}

	var aadCreds AADCreds
	if err = json.Unmarshal(item.Data, &aadCreds); err != nil {
		return &url.URL{}, errors.New("Failed to get aad credentials from your keyring.  Please make sure you have added aad credentials with `aws-aad add`")
	}

	var samlURL string

	// maintain compatibility for deprecated creds.Organization
	if aadCreds.Domain == "" && aadCreds.Organization != "" {
		samlURL = fmt.Sprintf("%s.%s", aadCreds.Organization, AADServerDefault)
	} else if aadCreds.Domain != "" {
		samlURL = aadCreds.Domain
	} else {
		return &url.URL{}, errors.New("either aadCreds.Organization (deprecated) or aadCreds.Domain must be set, but not both. To remedy this, re-add your credentials with `aws-aad add`")
	}

	fullSamlURL, err := url.Parse(fmt.Sprintf(
		"https://%s%s/%s",
		samlURL,
		p.AADAwsSAMLUrl,
		p.AADAwsTenant,
	))

	if err != nil {
		return &url.URL{}, err
	}

	return fullSamlURL, nil
}
