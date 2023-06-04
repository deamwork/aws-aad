package saml

import "encoding/xml"

type AssumableRole struct {
	Role      string
	Principal string
}

type AssumableRoles []AssumableRole

type Response struct {
	XMLName xml.Name
	SAMLP   string `xml:"xmlns:samlp,attr"`
	//SAML         string `xml:"xmlns:saml,attr"`
	//SAMLSIG      string `xml:"xmlns:samlsig,attr"`
	Destination  string `xml:"Destination,attr"`
	ID           string `xml:"ID,attr"`
	Version      string `xml:"Version,attr"`
	IssueInstant string `xml:"IssueInstant,attr"`
	//InResponseTo string `xml:"InResponseTo,attr"`

	Issuer    Issuer    `xml:"Issuer"`
	Status    Status    `xml:"samlp:Status"`
	Assertion Assertion `xml:"Assertion"`

	originalString string
}

type Issuer struct {
	XMLName xml.Name
	X       string `xml:"xmlns,attr"`
	Value   string `xml:",innerxml"`
}

type Assertion struct {
	XMLName xml.Name
	ID      string `xml:"ID,attr"`
	Version string `xml:"Version,attr"`
	//XS                 string `xml:"xmlns:xs,attr"`
	//XSI                string `xml:"xmlns:xsi,attr"`
	//SAML               string `xml:"saml,attr"`
	IssueInstant       string `xml:"IssueInstant,attr"`
	Issuer             Issuer
	Signature          Signature
	Subject            Subject
	Conditions         Conditions
	AttributeStatement AttributeStatement
	AuthnStatement     AuthnStatement
}

type Signature struct {
	XMLName        xml.Name
	X              string `xml:"xmlns,attr"`
	SignedInfo     SignedInfo
	SignatureValue SignatureValue
	KeyInfo        KeyInfo
}

type SignatureValue struct {
	Value string `xml:",innerxml"`
}

type KeyInfo struct {
	X509Data X509Data
}

type X509Data struct {
	X509Certificate X509Certificate
}

type X509Certificate struct {
	Value string `xml:",innerxml"`
}

type SignedInfo struct {
	CanonicalizationMethod CanonicalizationMethod
	SignatureMethod        SignatureMethod
	Reference              Reference
}

type Reference struct {
	URI          string `xml:"URI,attr"`
	Transforms   Transforms
	DigestMethod DigestMethod
	DigestValue  DigestValue
}

type Transforms struct {
	Transforms []Transform `xml:"Transform"`
}

type Transform struct {
	Algorithm string `xml:",attr"`
}

type DigestValue struct {
	Value string `xml:",innerxml"`
}

type DigestMethod struct {
	Algorithm string `xml:",attr"`
}

type SignatureMethod struct {
	Algorithm string `xml:",attr"`
}

type CanonicalizationMethod struct {
	Algorithm string `xml:",attr"`
}

type Conditions struct {
	XMLName             xml.Name
	NotBefore           string `xml:",attr"`
	NotOnOrAfter        string `xml:",attr"`
	AudienceRestriction AudienceRestriction
}

type AudienceRestriction struct {
	Audience string `xml:",innerxml"`
}

type Subject struct {
	XMLName             xml.Name
	NameID              NameID
	SubjectConfirmation SubjectConfirmation
}

type SubjectConfirmation struct {
	XMLName                 xml.Name
	Method                  string `xml:",attr"`
	SubjectConfirmationData SubjectConfirmationData
}

type Status struct {
	XMLName    xml.Name
	StatusCode StatusCode `xml:"samlp:StatusCode"`
}

type SubjectConfirmationData struct {
	InResponseTo string `xml:",attr"`
	NotOnOrAfter string `xml:",attr"`
	Recipient    string `xml:",attr"`
}

type NameID struct {
	XMLName xml.Name
	Format  string `xml:",attr"`
	Value   string `xml:",innerxml"`
}

type StatusCode struct {
	XMLName xml.Name
	Value   string `xml:",attr"`
}

type AttributeValue struct {
	XMLName xml.Name
	Type    string `xml:"xsi:type,attr"`
	Value   string `xml:",innerxml"`
}

type Attribute struct {
	XMLName         xml.Name
	Name            string           `xml:",attr"`
	FriendlyName    string           `xml:",attr"`
	NameFormat      string           `xml:",attr"`
	AttributeValues []AttributeValue `xml:"AttributeValue"`
}

type AttributeStatement struct {
	XMLName    xml.Name
	Attributes []Attribute `xml:"Attribute"`
}

type AuthnStatement struct {
	AuthnInstant string `xml:"AuthnInstant,attr"`
	SessionIndex string `xml:"SessionIndex,attr"`
	AuthnContext AuthnContext
}

type AuthnContext struct {
	AuthnContextClassRef AuthnContextClassRef
}

type AuthnContextClassRef struct {
	Value string `xml:",innerxml"`
}
