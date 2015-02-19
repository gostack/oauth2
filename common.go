package oauth2

type User struct {
	ID int64
}

type Client struct {
	ID, Secret string
	Internal   bool
}

type Authorization struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}
