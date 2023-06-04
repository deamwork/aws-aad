package lib

import (
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"errors"

	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/deamwork/aws-aad/sessioncache"
	log "github.com/sirupsen/logrus"

	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	aws_session "github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"

	// use xerrors until 1.13 is stable/the oldest supported version
	"golang.org/x/xerrors"
)

const (
	MaxSessionDuration    = time.Hour * 24 * 90
	MinSessionDuration    = time.Minute * 15
	MinAssumeRoleDuration = time.Minute * 15
	MaxAssumeRoleDuration = time.Hour * 12

	DefaultSessionDuration    = time.Hour * 4
	DefaultAssumeRoleDuration = time.Minute * 15
)

type ProviderOptions struct {
	SessionDuration    time.Duration
	AssumeRoleDuration time.Duration
	ExpiryWindow       time.Duration
	Profiles           Profiles
	MFAConfig          MFAConfig
	AssumeRoleArn      string
	// if true, use store_singlekritem SessionCache (new)
	// if false, use store_kritempersession SessionCache (old)
	SessionCacheSingleItem bool
}

func (o ProviderOptions) Validate() error {
	if o.SessionDuration < MinSessionDuration {
		return errors.New("Minimum session duration is " + MinSessionDuration.String())
	} else if o.SessionDuration > MaxSessionDuration {
		return errors.New("Maximum session duration is " + MaxSessionDuration.String())
	}
	if o.AssumeRoleDuration < MinAssumeRoleDuration {
		return errors.New("Minimum duration for assumed roles is " + MinAssumeRoleDuration.String())
	} else if o.AssumeRoleDuration > MaxAssumeRoleDuration {
		log.Println(o.AssumeRoleDuration)
		return errors.New("Maximum duration for assumed roles is " + MaxAssumeRoleDuration.String())
	}

	return nil
}

func (o ProviderOptions) ApplyDefaults() ProviderOptions {
	if o.AssumeRoleDuration == 0 {
		o.AssumeRoleDuration = DefaultAssumeRoleDuration
	}
	if o.SessionDuration == 0 {
		o.SessionDuration = DefaultSessionDuration
	}
	return o
}

type SessionCacheInterface interface {
	Get(sessioncache.Key) (*sessioncache.Session, error)
	Put(sessioncache.Key, *sessioncache.Session) error
}

type Provider struct {
	credentials.Expiry
	ProviderOptions
	profile                string
	expires                time.Time
	keyring                keyring.Keyring
	sessions               SessionCacheInterface
	profiles               Profiles
	defaultRoleSessionName string
}

func NewProvider(k keyring.Keyring, profile string, opts ProviderOptions) (*Provider, error) {
	opts = opts.ApplyDefaults()
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	var sessions SessionCacheInterface

	if opts.SessionCacheSingleItem {
		log.Debugf("Using SingleKrItemStore")
		sessions = &sessioncache.SingleKrItemStore{k}
	} else {
		log.Debugf("Using KrItemPerSessionStore")
		sessions = &sessioncache.KrItemPerSessionStore{k}
	}

	return &Provider{
		ProviderOptions: opts,
		keyring:         k,
		sessions:        sessions,
		profile:         profile,
		profiles:        opts.Profiles,
	}, nil
}

func (p *Provider) Retrieve() (credentials.Value, error) {

	window := p.ExpiryWindow
	if window == 0 {
		window = time.Minute * 5
	}

	// TODO(nick): why are we using the source profile name and not the actual profile's name?
	source := sourceProfile(p.profile, p.profiles)
	profileConf, ok := p.profiles[p.profile]
	if !ok {
		return credentials.Value{}, fmt.Errorf("missing profile named %s", p.profile)
	}
	key := sessioncache.KeyWithProfileARN{
		ProfileName: source,
		ProfileConf: profileConf,
		Duration:    p.SessionDuration,
		ProfileARN:  p.AssumeRoleArn,
	}

	var creds sts.Credentials
	if cachedSession, err := p.sessions.Get(key); err != nil {
		creds, err = p.getSamlSessionCreds()
		if err != nil {
			return credentials.Value{}, xerrors.Errorf("getting creds via SAML: %w", err)
		}
		newSession := sessioncache.Session{
			Name:        p.roleSessionName(),
			Credentials: creds,
		}
		if err = p.sessions.Put(key, &newSession); err != nil {
			return credentials.Value{}, xerrors.Errorf("putting to sessioncache", err)
		}

		// TODO(nick): not really clear why this is done
		p.defaultRoleSessionName = newSession.Name
	} else {
		creds = cachedSession.Credentials
		p.defaultRoleSessionName = cachedSession.Name
	}

	log.Debugf("Using session %s, expires in %s",
		(*(creds.AccessKeyId))[len(*(creds.AccessKeyId))-4:],
		creds.Expiration.Sub(time.Now()).String())

	// If sourceProfile returns the same source then we do not need to assume a
	// second role. Not assuming a second role allows us to assume IDP enabled
	// roles directly.
	if p.profile != source {
		if role, ok := p.profiles[p.profile]["role_arn"]; ok {
			var err error
			creds, err = p.assumeRoleFromSession(creds, role)
			if err != nil {
				return credentials.Value{}, err
			}

			log.Debugf("using role %s expires in %s",
				(*(creds.AccessKeyId))[len(*(creds.AccessKeyId))-4:],
				creds.Expiration.Sub(time.Now()).String())
		}
	}

	p.SetExpiration(*(creds.Expiration), window)
	p.expires = *(creds.Expiration)

	value := credentials.Value{
		AccessKeyID:     *(creds.AccessKeyId),
		SecretAccessKey: *(creds.SecretAccessKey),
		SessionToken:    *(creds.SessionToken),
		ProviderName:    "aad",
	}

	return value, nil
}

func (p *Provider) GetExpiration() time.Time {
	return p.expires
}

func (p *Provider) getSamlURL() (string, error) {
	aadAwsSAMLUrl, profile, err := p.profiles.GetValue(p.profile, "aws_saml_url")
	if err != nil {
		return "", errors.New("aws_saml_url missing from ~/.aws/config")
	}
	log.Debugf("Using aws_saml_url from profile %s: %s", profile, aadAwsSAMLUrl)
	return aadAwsSAMLUrl, nil
}

func (p *Provider) getTenant() (string, error) {
	aadAwsTenant, profile, err := p.profiles.GetValue(p.profile, "aws_aad_tenant")
	if err != nil {
		return "", errors.New("aws_aad_tenant missing from ~/.aws/config")
	}
	log.Debugf("Using aws_aad_tenant from profile %s: %s", profile, aadAwsTenant)
	return aadAwsTenant, nil
}

func (p *Provider) getClientID() (string, error) {
	aadAwsClientID, profile, err := p.profiles.GetValue(p.profile, "aws_aad_client_id")
	if err != nil {
		return "", errors.New("aws_aad_client_id missing from ~/.aws/config")
	}
	log.Debugf("Using aws_aad_client_id from profile %s: %s", profile, aadAwsClientID)
	return aadAwsClientID, nil
}

func (p *Provider) getResource() (string, error) {
	aadAwsResource, profile, err := p.profiles.GetValue(p.profile, "aws_aad_resource")
	if err != nil {
		return "", errors.New("aws_aad_resource missing from ~/.aws/config")
	}
	log.Debugf("Using aws_aad_resource from profile %s: %s", profile, aadAwsResource)
	return aadAwsResource, nil
}

func (p *Provider) getAADSessionCookieKey() string {
	aadSessionCookieKey, profile, err := p.profiles.GetValue(p.profile, "aad_session_cookie_key")
	if err != nil {
		return "aad-session-cookie"
	}
	log.Debugf("Using aad_session_cookie_key from profile: %s", profile)
	return aadSessionCookieKey
}

func (p *Provider) getAADAccountName() string {
	aadAccountName, profile, err := p.profiles.GetValue(p.profile, "aad_account_name")
	if err != nil {
		return "aad-creds"
	}
	log.Debugf("Using aad_account_name: %s from profile: %s", aadAccountName, profile)
	return "aad-creds-" + aadAccountName
}

func (p *Provider) getSamlSessionCreds() (sts.Credentials, error) {
	var profileARN string
	var ok bool
	source := sourceProfile(p.profile, p.profiles)

	var creds AADCreds

	item, err := p.keyring.Get(p.getAADAccountName())
	if err = json.Unmarshal(item.Data, &creds); err != nil {
		return sts.Credentials{}, err
	}

	aadSessionCookieKey := p.getAADSessionCookieKey()
	aadAccountName := p.getAADAccountName()

	// if the assumable role is passed it have it override what is in the profile
	if p.AssumeRoleArn != "" {
		profileARN = p.AssumeRoleArn
		log.Debug("Overriding Assumable role with: ", profileARN)
	} else {
		profileARN, ok = p.profiles[source]["role_arn"]
		if !ok {
			// profile does not have a role_arn. This is ok as the user will be promted
			// to choose a role from all available roles
			// Support profiles similar to below
			//   [profile my-profile]
			//   output = json
			//   aws_saml_url = /home/some_saml_url
			//   mfa_provider = FIDO
			//   mfa_factor_type = u2f
			log.Debugf("Profile '%s' does not have role_arn", source)
		}
	}

	provider := AADProvider{
		MFAConfig:           p.ProviderOptions.MFAConfig,
		Keyring:             p.keyring,
		ProfileARN:          profileARN,
		SessionDuration:     p.SessionDuration,
		AADAwsTenant:        creds.Organization,
		AADAwsClientID:      creds.MiddlewareClientID,
		AADAwsClientSecret:  creds.MiddlewareClientSecret,
		AADSessionCookieKey: aadSessionCookieKey,
		AADAccountName:      aadAccountName,
	}

	if region := p.profiles[source]["region"]; region != "" {
		provider.AwsRegion = region
	}

	cred, aadUsername, err := provider.Retrieve()
	if err != nil {
		return sts.Credentials{}, err
	}
	p.defaultRoleSessionName = aadUsername

	return cred, nil
}

func (p *Provider) GetSAMLLoginURL() (*url.URL, error) {
	source := sourceProfile(p.profile, p.profiles)
	var creds AADCreds

	item, err := p.keyring.Get(p.getAADAccountName())
	if err = json.Unmarshal(item.Data, &creds); err != nil {
		return &url.URL{}, err
	}
	aadSessionCookieKey := p.getAADSessionCookieKey()
	aadAccountName := p.getAADAccountName()

	profileARN := p.profiles[source]["role_arn"]

	provider := AADProvider{
		MFAConfig:           p.ProviderOptions.MFAConfig,
		Keyring:             p.keyring,
		ProfileARN:          profileARN,
		SessionDuration:     p.SessionDuration,
		AADAwsTenant:        creds.Organization,
		AADAwsClientID:      creds.MiddlewareClientID,
		AADSessionCookieKey: aadSessionCookieKey,
		AADAccountName:      aadAccountName,
	}

	if region := p.profiles[source]["region"]; region != "" {
		provider.AwsRegion = region
	}

	loginURL, err := provider.GetSAMLLoginURL()
	if err != nil {
		return &url.URL{}, err
	}
	return loginURL, nil
}

// assumeRoleFromSession takes a session created with an aad SAML login and uses that to assume a role
func (p *Provider) assumeRoleFromSession(creds sts.Credentials, roleArn string) (sts.Credentials, error) {
	conf := &aws.Config{
		Credentials: credentials.NewStaticCredentials(
			*creds.AccessKeyId,
			*creds.SecretAccessKey,
			*creds.SessionToken,
		),
	}
	if region := p.profiles[sourceProfile(p.profile, p.profiles)]["region"]; region != "" {
		conf.WithRegion(region)
		conf.WithSTSRegionalEndpoint(endpoints.RegionalSTSEndpoint)
	}
	sess := aws_session.Must(aws_session.NewSession(conf))
	client := sts.New(sess)

	input := &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleArn),
		RoleSessionName: aws.String(p.roleSessionName()),
		DurationSeconds: aws.Int64(int64(p.AssumeRoleDuration.Seconds())),
	}

	log.Debugf("Assuming role %s from session token", roleArn)
	resp, err := client.AssumeRole(input)
	if err != nil {
		return sts.Credentials{}, err
	}

	return *resp.Credentials, nil
}

// roleSessionName returns the profile's `role_session_name` if set, or the
// provider's defaultRoleSessionName if set. If neither is set, returns some
// arbitrary unique string
func (p *Provider) roleSessionName() string {
	if name := p.profiles[p.profile]["role_session_name"]; name != "" {
		return name
	}

	if p.defaultRoleSessionName != "" {
		return p.defaultRoleSessionName
	}

	// Try to work out a role name that will hopefully end up unique.
	return fmt.Sprintf("%d", time.Now().UTC().UnixNano())
}

// GetRoleARN uses temporary credentials to call AWS's get-caller-identity and
// returns the assumed role's ARN
func (p *Provider) GetRoleARNWithRegion(creds credentials.Value) (string, error) {
	conf := &aws.Config{
		Credentials: credentials.NewStaticCredentials(
			creds.AccessKeyID,
			creds.SecretAccessKey,
			creds.SessionToken,
		),
	}
	if region := p.profiles[sourceProfile(p.profile, p.profiles)]["region"]; region != "" {
		conf.WithRegion(region)
		conf.WithSTSRegionalEndpoint(endpoints.RegionalSTSEndpoint)
	}
	sess := aws_session.Must(aws_session.NewSession(conf))
	client := sts.New(sess)

	indentity, err := client.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		log.Errorf("Error getting caller identity: %s", err.Error())
		return "", err
	}
	arn := *indentity.Arn
	return arn, nil
}

// GetRoleARN uses p to establish temporary credentials then calls
// lib.GetRoleARN with them to get the role's ARN. It is unused internally and
// is kept for backwards compatability.
func (p *Provider) GetRoleARN() (string, error) {
	creds, err := p.getSamlSessionCreds()
	if err != nil {
		return "", err
	}
	client := sts.New(aws_session.New(&aws.Config{Credentials: credentials.NewStaticCredentials(
		*creds.AccessKeyId,
		*creds.SecretAccessKey,
		*creds.SessionToken,
	)}))
	indentity, err := client.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		log.Errorf("Error getting caller identity: %s", err.Error())
		return "", err
	}
	arn := *indentity.Arn
	return arn, nil
}
