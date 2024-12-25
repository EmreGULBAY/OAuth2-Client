import {
  OAuthConfig,
  AuthUrlResponse,
  CallbackParams,
} from "./models/oauth-models";

function generateUUID(): string {
  return crypto.randomUUID();
}

export class OAuth2Client {
  private config: OAuthConfig;
  private readonly STATE_KEY = "oauth_state";
  private readonly TOKEN_KEY = "oauth_token";
  private popup: Window | null = null;
  private readonly POPUP_WIDTH = 500;
  private readonly POPUP_HEIGHT = 600;
  private overlay: HTMLDivElement | null = null;

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
      "tokenEndpoint",
    ];
    const missing = required.filter((field) => !config[field]);

    if (missing.length) {
      throw new Error(`Missing required configuration: ${missing.join(", ")}`);
    }
  }

  public getAuthorizationUrl(): AuthUrlResponse {
    try {
      const state = generateUUID();

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

  public async handleCallback(params: CallbackParams): Promise<string> {
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

      const loginToken = await fetch(this.config.tokenEndpoint, {
        method: "POST",
        body: JSON.stringify({ code }),
      });

      const token = await loginToken.json();

      sessionStorage.setItem(this.TOKEN_KEY, token);

      return token;
    } catch (error) {
      throw new Error(`Callback handling failed: ${(error as Error).message}`);
    }
  }

  public async authenticateWithPopup(): Promise<void> {
    try {
      const { url } = this.getAuthorizationUrl();

      const left = window.screenX + (window.outerWidth - this.POPUP_WIDTH) / 2;
      const top = window.screenY + (window.outerHeight - this.POPUP_HEIGHT) / 2;

      this.showOverlay();

      this.popup = window.open(
        url,
        "OAuth2 Authentication",
        `width=${this.POPUP_WIDTH},height=${this.POPUP_HEIGHT},left=${left},top=${top}`
      );

      if (!this.popup) {
        this.hideOverlay();
        throw new Error(
          "Failed to open popup. Please check if popups are blocked."
        );
      }
    } catch (error) {
      if (this.popup) {
        this.popup.close();
        this.popup = null;
      }
      throw error;
    }
  }

  public async waitForCallback(): Promise<CallbackParams | null> {
    return new Promise((resolve) => {
      const popupCheck = setInterval(() => {
        try {
          if (this.popup?.closed) {
            clearInterval(popupCheck);
            this.hideOverlay();
            this.popup = null;
            resolve(null);
            return;
          }

          if (this.popup?.location?.origin === window.location.origin) {
            clearInterval(popupCheck);
            const callbackUrl = this.popup.location.href;
            this.popup.close();
            this.popup = null;
            this.hideOverlay();
            const url = new URL(callbackUrl);
            const params: CallbackParams = {
              code: url.searchParams.get("code") || undefined,
              state: url.searchParams.get("state") || undefined,
              error: url.searchParams.get("error") || undefined,
              error_description:
                url.searchParams.get("error_description") || undefined,
            };
            resolve(params);
          }
        } catch (e) {
          if (!(e instanceof DOMException)) {
            console.error("Popup check error:", e);
            clearInterval(popupCheck);
            this.hideOverlay();
            if (this.popup) {
              this.popup.close();
              this.popup = null;
            }
            resolve(null);
          }
        }
      }, 500);
    });
  }

  public logout(): void {
    try {
      sessionStorage.removeItem(this.TOKEN_KEY);
      sessionStorage.removeItem(this.STATE_KEY);

      if (this.config.logoutEndpoint) {
        window.location.href = this.config.logoutEndpoint;
      }

      window.dispatchEvent(new CustomEvent("oauth2Logout"));
    } catch (error) {
      throw new Error(`Logout failed: ${(error as Error).message}`);
    }
  }

  public isAuthenticated(): boolean {
    return !!sessionStorage.getItem(this.TOKEN_KEY);
  }

  private createOverlay(): void {
    if (!document.getElementById("oauth-overlay")) {
      const overlay = document.createElement("div");
      overlay.id = "oauth-overlay";
      overlay.style.cssText = `
        display: none;
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.5);
        z-index: 1000;
        justify-content: center;
        align-items: center;
      `;

      const content = document.createElement("div");
      content.style.cssText = `
        background: rgba(0, 0, 0, 0.8);
        padding: 20px;
        border-radius: 8px;
        text-align: center;
        color: white;
      `;

      const spinner = document.createElement("div");
      spinner.style.cssText = `
        border: 4px solid #f3f3f3;
        border-top: 4px solid #3498db;
        border-radius: 50%;
        width: 40px;
        height: 40px;
        animation: spin 1s linear infinite;
        margin: 10px auto;
      `;

      const style = document.createElement("style");
      style.textContent = `
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
      `;
      document.head.appendChild(style);

      const text = document.createElement("p");
      text.textContent = "Authenticating...";

      content.appendChild(spinner);
      content.appendChild(text);
      overlay.appendChild(content);
      document.body.appendChild(overlay);

      this.overlay = overlay;

      document.addEventListener("keydown", (event) => {
        if (event.key === "Escape" && this.overlay?.style.display === "flex") {
          this.hideOverlay();
          if (this.popup) {
            this.popup.close();
            this.popup = null;
          }
        }
      });
    }
  }

  private showOverlay(): void {
    if (this.overlay) {
      this.overlay.style.display = "flex";
    }
  }

  private hideOverlay(): void {
    if (this.overlay) {
      this.overlay.style.display = "none";
    }
  }
}
