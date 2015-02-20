package oauth2

type User struct {
	Login string
}

type Client struct {
	ID, Secret string
	Internal   bool
}

type Authorization struct {
	Client *Client `json:"-"`
	User   *User   `json:"-"`

	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope"`
}
