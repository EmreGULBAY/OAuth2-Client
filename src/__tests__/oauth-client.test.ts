import { OAuth2Client } from '../oauth-client';
import { OAuthConfig } from "../models/oauth-models";

describe("OAuth2Client", () => {
  const validConfig: OAuthConfig = {
    clientId: 'test-client-id',
    redirectUri: 'http://localhost/callback',
    authEndpoint: 'http://auth-server/auth',
    scope: 'read write'
  };

  beforeEach(() => {
    sessionStorage.clear();
  });

  describe('constructor', () => {
    it('should initialize with valid config', () => {
      expect(() => new OAuth2Client(validConfig)).not.toThrow();
    });

    it('should throw error for missing required fields', () => {
      const invalidConfig = { ...validConfig, clientId: undefined };
      expect(() => new OAuth2Client(invalidConfig as unknown as OAuthConfig))
        .toThrow('Missing required configuration: clientId');
    });
  });

  describe('getAuthorizationUrl', () => {
    let client: OAuth2Client;

    beforeEach(() => {
      client = new OAuth2Client(validConfig);
    });

    it('should generate valid authorization URL', () => {
      const { url, state } = client.getAuthorizationUrl();
      const parsedUrl = new URL(url);

      expect(parsedUrl.origin + parsedUrl.pathname).toBe(validConfig.authEndpoint);
      expect(parsedUrl.searchParams.get('client_id')).toBe(validConfig.clientId);
      expect(parsedUrl.searchParams.get('redirect_uri')).toBe(validConfig.redirectUri);
      expect(parsedUrl.searchParams.get('response_type')).toBe('code');
      expect(parsedUrl.searchParams.get('scope')).toBe(validConfig.scope);
      expect(parsedUrl.searchParams.get('state')).toBe(state);
    });

    it('should store state in sessionStorage', () => {
      const { state } = client.getAuthorizationUrl();
      expect(sessionStorage.getItem('oauth_state')).toBe(state);
    });

    it('should throw error if sessionStorage is not available', () => {
      const mockSetItem = jest.spyOn(Storage.prototype, 'setItem');
      mockSetItem.mockImplementationOnce(() => {
        throw new Error('Storage is not available');
      });

      expect(() => client.getAuthorizationUrl())
        .toThrow('Failed to store state: Storage is not available');

      mockSetItem.mockRestore();
    });
  });

  describe('handleCallback', () => {
    let client: OAuth2Client;
    let savedState: string;

    beforeEach(() => {
      client = new OAuth2Client(validConfig);
      const { state } = client.getAuthorizationUrl();
      savedState = state;
    });

    it('should successfully handle valid callback', () => {
      const mockCode = 'test-auth-code';
      const code = client.handleCallback({
        code: mockCode,
        state: savedState
      });

      expect(code).toBe(mockCode);
      expect(sessionStorage.getItem('oauth_state')).toBeNull();
    });

    it('should throw error for OAuth provider errors', () => {
      expect(() => client.handleCallback({
        error: 'access_denied',
        error_description: 'User denied access'
      })).toThrow('Auth error: User denied access');
    });

    it('should throw error for missing parameters', () => {
      expect(() => client.handleCallback({
        state: savedState
      })).toThrow('Missing required callback parameters');
    });

    it('should throw error for invalid state', () => {
      expect(() => client.handleCallback({
        code: 'test-code',
        state: 'invalid-state'
      })).toThrow('State validation failed - possible CSRF attack');
    });

    it('should throw error if state is missing from storage', () => {
      sessionStorage.clear();
      expect(() => client.handleCallback({
        code: 'test-code',
        state: savedState
      })).toThrow('No stored state found - the session might have expired');
    });

    it('should clean up state from sessionStorage after successful callback', () => {
      client.handleCallback({
        code: 'test-code',
        state: savedState
      });
      expect(sessionStorage.getItem('oauth_state')).toBeNull();
    });

    it('should throw error if sessionStorage is not accessible', () => {
      const mockGetItem = jest.spyOn(Storage.prototype, 'getItem');
      mockGetItem.mockImplementationOnce(() => {
        throw new Error('Storage is not available');
      });

      expect(() => client.handleCallback({
        code: 'test-code',
        state: savedState
      })).toThrow('Failed to retrieve state from storage: Storage is not available');

      mockGetItem.mockRestore();
    });
  });
}); 