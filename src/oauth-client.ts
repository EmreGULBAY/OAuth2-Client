import {
  OAuthConfig,
  AuthUrlResponse,
  CallbackParams,
} from "./models/oauth-models";
import crypto, { randomUUID } from "crypto";

export class OAuth2Client {
  private config: OAuthConfig;
  private readonly STATE_KEY = 'oauth_state';
  private popup: Window | null = null;
  private readonly POPUP_WIDTH = 500;
  private readonly POPUP_HEIGHT = 600;

  constructor(config: OAuthConfig) {
    try {
      this.validateConfig(config);
      this.config = config;
    } catch (error) {
      throw new Error(
        `OAuth2Client initialization failed: ${(error as Error).message}`
      );
    }
  }

  private validateConfig(config: OAuthConfig): void {
    const required: (keyof OAuthConfig)[] = [
      "clientId",
      "redirectUri",
      "authEndpoint",
    ];
    const missing = required.filter((field) => !config[field]);

    if (missing.length) {
      throw new Error(`Missing required configuration: ${missing.join(", ")}`);
    }
  }

  public getAuthorizationUrl(): AuthUrlResponse {
    try {
      const state = randomUUID();

      try {
        sessionStorage.setItem(this.STATE_KEY, state);
      } catch (error) {
        throw new Error(`Failed to store state: ${(error as Error).message}`);
      }

      const url = new URL(this.config.authEndpoint);

      try {
        url.searchParams.append("client_id", this.config.clientId);
        url.searchParams.append("redirect_uri", this.config.redirectUri);
        url.searchParams.append("response_type", "code");
        url.searchParams.append("state", state);

        if (this.config.scope) {
          url.searchParams.append("scope", this.config.scope);
        }
      } catch (error) {
        throw new Error(
          `Failed to construct authorization URL: ${(error as Error).message}`
        );
      }

      return { url: url.toString(), state };
    } catch (error) {
      throw new Error(
        `Failed to generate authorization URL: ${(error as Error).message}`
      );
    }
  }

  public handleCallback(params: CallbackParams): string {
    try {
      const { code, state, error, error_description } = params;

      if (error) {
        throw new Error(`Auth error: ${error_description || error}`);
      }

      if (!code || !state) {
        throw new Error("Missing required callback parameters");
      }

      let savedState: string | null;
      try {
        savedState = sessionStorage.getItem(this.STATE_KEY);
        sessionStorage.removeItem(this.STATE_KEY);
      } catch (error) {
        throw new Error(
          `Failed to retrieve state from storage: ${(error as Error).message}`
        );
      }

      if (!savedState) {
        throw new Error(
          "No stored state found - the session might have expired"
        );
      }

      if (state !== savedState) {
        throw new Error("State validation failed - possible CSRF attack");
      }

      return code;
    } catch (error) {
      throw new Error(`Callback handling failed: ${(error as Error).message}`);
    }
  }

  public async authenticateWithPopup(): Promise<string> {
    try {
      const { url } = this.getAuthorizationUrl();
      
      const left = window.screenX + (window.outerWidth - this.POPUP_WIDTH) / 2;
      const top = window.screenY + (window.outerHeight - this.POPUP_HEIGHT) / 2;
      
      this.popup = window.open(
        url,
        'OAuth2 Authentication',
        `width=${this.POPUP_WIDTH},height=${this.POPUP_HEIGHT},left=${left},top=${top}`
      );

      if (!this.popup) {
        throw new Error('Failed to open popup. Please check if popups are blocked.');
      }

      return new Promise((resolve, reject) => {
        const popupCheck = setInterval(() => {
          if (this.popup?.closed) {
            clearInterval(popupCheck);
            reject(new Error('Authentication cancelled'));
          }
        }, 500);

        const messageHandler = (event: MessageEvent) => {
          if (new URL(this.config.redirectUri).origin !== event.origin) {
            return;
          }

          if (event.data?.type === 'oauth2-callback') {
            window.removeEventListener('message', messageHandler);
            clearInterval(popupCheck);
            
            if (this.popup) {
              this.popup.close();
              this.popup = null;
            }

            try {
              const code = this.handleCallback(event.data.params);
              resolve(code);
            } catch (error) {
              reject(error);
            }
          }
        };

        window.addEventListener('message', messageHandler);
      });
    } catch (error) {
      if (this.popup) {
        this.popup.close();
        this.popup = null;
      }
      throw error;
    }
  }
}
