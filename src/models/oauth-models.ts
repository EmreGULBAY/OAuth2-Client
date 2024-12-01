export interface OAuthConfig {
  clientId: string;
  redirectUri: string;
  authEndpoint: string;
  scope?: string;
}

export interface AuthUrlResponse {
  url: string;
  state: string;
}

export interface CallbackParams {
  code?: string;
  state?: string;
  error?: string;
  error_description?: string;
}
