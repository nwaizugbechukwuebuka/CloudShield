import { 
  LoginCredentials, 
  RegisterCredentials, 
  AuthTokens, 
  User, 
  PasswordChangeForm,
  ApiResponse 
} from '@/types';
import { apiService } from './api';

export interface PasswordResetRequest {
  email: string;
}

export interface PasswordResetConfirm {
  token: string;
  new_password: string;
}

export interface MFASetupResponse {
  secret: string;
  qr_code_url: string;
  backup_codes: string[];
}

export interface MFAVerifyRequest {
  code: string;
}

export interface OAuthURLResponse {
  authorization_url: string;
  state: string;
}

export interface OAuthCallbackRequest {
  code: string;
  state: string;
  platform: string;
}

export const authService = {
  // Authentication
  async login(credentials: LoginCredentials): Promise<AuthTokens> {
    return apiService.post<AuthTokens>('/auth/login', credentials);
  },
  
  async register(credentials: RegisterCredentials): Promise<ApiResponse<User>> {
    return apiService.post<ApiResponse<User>>('/auth/register', credentials);
  },
  
  async logout(): Promise<void> {
    return apiService.post<void>('/auth/logout');
  },
  
  async refreshToken(refreshToken: string): Promise<AuthTokens> {
    return apiService.post<AuthTokens>('/auth/refresh', { 
      refresh_token: refreshToken 
    });
  },
  
  // Profile management
  async getProfile(): Promise<User> {
    return apiService.get<User>('/users/me');
  },
  
  async updateProfile(data: Partial<User>): Promise<User> {
    return apiService.put<User>('/users/me', data);
  },
  
  async changePassword(data: PasswordChangeForm): Promise<ApiResponse<string>> {
    return apiService.post<ApiResponse<string>>('/users/change-password', {
      current_password: data.current_password,
      new_password: data.new_password,
    });
  },
  
  // Password reset
  async requestPasswordReset(data: PasswordResetRequest): Promise<ApiResponse<string>> {
    return apiService.post<ApiResponse<string>>('/users/reset-password', data);
  },
  
  async confirmPasswordReset(data: PasswordResetConfirm): Promise<ApiResponse<string>> {
    return apiService.post<ApiResponse<string>>('/users/reset-password/confirm', data);
  },
  
  // Email verification
  async resendVerificationEmail(): Promise<ApiResponse<string>> {
    return apiService.post<ApiResponse<string>>('/auth/resend-verification');
  },
  
  async verifyEmail(token: string): Promise<ApiResponse<string>> {
    return apiService.post<ApiResponse<string>>('/auth/verify-email', { token });
  },
  
  // Multi-factor authentication
  async setupMFA(): Promise<MFASetupResponse> {
    return apiService.post<MFASetupResponse>('/auth/mfa/setup');
  },
  
  async verifyMFA(data: MFAVerifyRequest): Promise<ApiResponse<string>> {
    return apiService.post<ApiResponse<string>>('/auth/mfa/verify', data);
  },
  
  async disableMFA(data: MFAVerifyRequest): Promise<ApiResponse<string>> {
    return apiService.post<ApiResponse<string>>('/auth/mfa/disable', data);
  },
  
  async generateBackupCodes(): Promise<{ backup_codes: string[] }> {
    return apiService.post<{ backup_codes: string[] }>('/auth/mfa/backup-codes');
  },
  
  // OAuth integrations
  async getOAuthURL(platform: string): Promise<OAuthURLResponse> {
    return apiService.get<OAuthURLResponse>(`/auth/oauth/${platform}/authorize`);
  },
  
  async handleOAuthCallback(data: OAuthCallbackRequest): Promise<ApiResponse<string>> {
    return apiService.post<ApiResponse<string>>('/auth/oauth/callback', data);
  },
  
  // Session management
  async getActiveSessions(): Promise<Array<{
    id: string;
    ip_address: string;
    user_agent: string;
    created_at: string;
    last_activity: string;
    is_current: boolean;
  }>> {
    return apiService.get<Array<any>>('/auth/sessions');
  },
  
  async terminateSession(sessionId: string): Promise<ApiResponse<string>> {
    return apiService.delete<ApiResponse<string>>(`/auth/sessions/${sessionId}`);
  },
  
  async terminateAllSessions(): Promise<ApiResponse<string>> {
    return apiService.delete<ApiResponse<string>>('/auth/sessions/all');
  },
  
  // Account security
  async getSecurityLog(): Promise<Array<{
    id: string;
    event_type: string;
    ip_address: string;
    user_agent: string;
    success: boolean;
    created_at: string;
    details?: any;
  }>> {
    return apiService.get<Array<any>>('/users/security-log');
  },
  
  async enableTwoFactorAuth(method: 'sms' | 'email' | 'app'): Promise<ApiResponse<any>> {
    return apiService.post<ApiResponse<any>>('/auth/2fa/enable', { method });
  },
  
  async disableTwoFactorAuth(): Promise<ApiResponse<string>> {
    return apiService.post<ApiResponse<string>>('/auth/2fa/disable');
  },
  
  // Account deletion
  async deleteAccount(password: string): Promise<ApiResponse<string>> {
    return apiService.delete<ApiResponse<string>>('/users/me', {
      data: { password }
    });
  },
  
  // Utility methods
  isTokenExpired(token: string): boolean {
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      return Date.now() >= payload.exp * 1000;
    } catch {
      return true;
    }
  },
  
  getTokenClaims(token: string): any {
    try {
      return JSON.parse(atob(token.split('.')[1]));
    } catch {
      return null;
    }
  },
};

export default authService;