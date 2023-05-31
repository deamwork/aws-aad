package lib

type AADUser struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AccessToken struct {
	HomeAccountID     string `json:"home_account_id"`
	Environment       string `json:"environment"`
	Realm             string `json:"realm"`
	CredentialType    string `json:"credential_type"`
	ClientID          string `json:"client_id"`
	Secret            string `json:"secret"`
	Target            string `json:"target"`
	ExpiresOn         string `json:"expires_on"`
	ExtendedExpiresOn string `json:"extended_expires_on"`
	CachedAt          string `json:"cached_at"`
}

type RefreshToken struct {
	HomeAccountID  string `json:"home_account_id"`
	Environment    string `json:"environment"`
	Realm          string `json:"realm"`
	CredentialType string `json:"credential_type"`
	ClientID       string `json:"client_id"`
	Secret         string `json:"secret"`
}

type IDToken struct {
	HomeAccountID  string `json:"home_account_id"`
	Environment    string `json:"environment"`
	Realm          string `json:"realm"`
	CredentialType string `json:"credential_type"`
	ClientID       string `json:"client_id"`
	Secret         string `json:"secret"`
}

type Account struct {
	HomeAccountID  string `json:"home_account_id"`
	Environment    string `json:"environment"`
	Realm          string `json:"realm"`
	LocalAccountID string `json:"local_account_id"`
	AuthorityType  string `json:"authority_type"`
	Username       string `json:"username"`
}

type AppMetadata struct {
	ClientID    string `json:"client_id"`
	Environment string `json:"environment"`
}

type AADUserAuthn struct {
	AccessToken  map[string]AccessToken  `json:"AccessToken"`
	RefreshToken map[string]RefreshToken `json:"RefreshToken"`
	IDToken      map[string]IDToken      `json:"IdToken"`
	Account      map[string]Account      `json:"Account"`
	AppMetadata  map[string]AppMetadata  `json:"AppMetadata"`
}
