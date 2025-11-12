import { createSlice, createAsyncThunk, PayloadAction } from '@reduxjs/toolkit';
import type { AuthState, LoginCredentials, RegisterCredentials, User, AuthTokens } from '@/types';
import authService from '@/services/auth';
import { setAuthTokens } from '@/services/api';

// Initial state
const initialState: AuthState = {
  user: null,
  tokens: null,
  isAuthenticated: false,
  isLoading: false,
  error: null,
};

// Async thunks
export const loginAsync = createAsyncThunk(
  'auth/login',
  async (credentials: LoginCredentials, { rejectWithValue }: any) => {
    try {
      const tokens = await authService.login(credentials);
      setAuthTokens(tokens);
      
      // Get user profile after successful login
      const user = await authService.getProfile();
      
      return { tokens, user };
    } catch (error: any) {
      return rejectWithValue(error.response?.data?.detail || 'Login failed');
    }
  }
);

export const registerAsync = createAsyncThunk(
  'auth/register',
  async (credentials: RegisterCredentials, { rejectWithValue }: any) => {
    try {
      const response = await authService.register(credentials);
      return response.data;
    } catch (error: any) {
      return rejectWithValue(error.response?.data?.detail || 'Registration failed');
    }
  }
);

export const refreshTokenAsync = createAsyncThunk(
  'auth/refreshToken',
  async (refreshToken: string, { rejectWithValue }: any) => {
    try {
      const tokens = await authService.refreshToken(refreshToken);
      setAuthTokens(tokens);
      
      // Get updated user profile
      const user = await authService.getProfile();
      
      return { tokens, user };
    } catch (error: any) {
      return rejectWithValue(error.response?.data?.detail || 'Token refresh failed');
    }
  }
);

export const loadUserAsync = createAsyncThunk(
  'auth/loadUser',
  async (_: void, { rejectWithValue }: any) => {
    try {
      const user = await authService.getProfile();
      return user;
    } catch (error: any) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to load user');
    }
  }
);

export const logoutAsync = createAsyncThunk(
  'auth/logout',
  async () => {
    try {
      await authService.logout();
      setAuthTokens(null);
    } catch (error: any) {
      // Even if logout fails on server, clear local state
      setAuthTokens(null);
      console.warn('Logout request failed, but tokens cleared locally');
    }
  }
);

export const updateProfileAsync = createAsyncThunk(
  'auth/updateProfile',
  async (data: Partial<User>, { rejectWithValue }: any) => {
    try {
      const user = await authService.updateProfile(data);
      return user;
    } catch (error: any) {
      return rejectWithValue(error.response?.data?.detail || 'Profile update failed');
    }
  }
);

export const changePasswordAsync = createAsyncThunk(
  'auth/changePassword',
  async (data: { current_password: string; new_password: string }, { rejectWithValue }: any) => {
    try {
      await authService.changePassword({
        current_password: data.current_password,
        new_password: data.new_password,
        confirm_password: data.new_password,
      });
      return 'Password changed successfully';
    } catch (error: any) {
      return rejectWithValue(error.response?.data?.detail || 'Password change failed');
    }
  }
);

// Auth slice
const authSlice = createSlice({
  name: 'auth',
  initialState,
  reducers: {
    clearError: (state: AuthState) => {
      state.error = null;
    },
    
    setTokens: (state: AuthState, action: PayloadAction<AuthTokens>) => {
      state.tokens = action.payload;
      state.isAuthenticated = true;
      setAuthTokens(action.payload);
    },
    
    clearAuth: (state: AuthState) => {
      state.user = null;
      state.tokens = null;
      state.isAuthenticated = false;
      state.error = null;
      setAuthTokens(null);
    },
    
    updateUser: (state: AuthState, action: PayloadAction<Partial<User>>) => {
      if (state.user) {
        state.user = { ...state.user, ...action.payload };
      }
    },
  },
  extraReducers: (builder: any) => {
    builder
      // Login
      .addCase(loginAsync.pending, (state: AuthState) => {
        state.isLoading = true;
        state.error = null;
      })
      .addCase(loginAsync.fulfilled, (state: AuthState, action: any) => {
        state.isLoading = false;
        state.isAuthenticated = true;
        state.tokens = action.payload.tokens;
        state.user = action.payload.user;
        state.error = null;
      })
      .addCase(loginAsync.rejected, (state: AuthState, action: any) => {
        state.isLoading = false;
        state.isAuthenticated = false;
        state.error = action.payload as string;
      })
      
      // Register
      .addCase(registerAsync.pending, (state: AuthState) => {
        state.isLoading = true;
        state.error = null;
      })
      .addCase(registerAsync.fulfilled, (state: AuthState) => {
        state.isLoading = false;
        state.error = null;
      })
      .addCase(registerAsync.rejected, (state: AuthState, action: any) => {
        state.isLoading = false;
        state.error = action.payload as string;
      })
      
      // Refresh token
      .addCase(refreshTokenAsync.pending, (state: AuthState) => {
        state.isLoading = true;
      })
      .addCase(refreshTokenAsync.fulfilled, (state: AuthState, action: any) => {
        state.isLoading = false;
        state.isAuthenticated = true;
        state.tokens = action.payload.tokens;
        state.user = action.payload.user;
        state.error = null;
      })
      .addCase(refreshTokenAsync.rejected, (state: AuthState, action: any) => {
        state.isLoading = false;
        state.isAuthenticated = false;
        state.user = null;
        state.tokens = null;
        state.error = action.payload as string;
      })
      
      // Load user
      .addCase(loadUserAsync.pending, (state: AuthState) => {
        state.isLoading = true;
      })
      .addCase(loadUserAsync.fulfilled, (state: AuthState, action: any) => {
        state.isLoading = false;
        state.user = action.payload;
        state.isAuthenticated = true;
      })
      .addCase(loadUserAsync.rejected, (state: AuthState, action: any) => {
        state.isLoading = false;
        state.error = action.payload as string;
      })
      
      // Logout
      .addCase(logoutAsync.fulfilled, (state: AuthState) => {
        state.user = null;
        state.tokens = null;
        state.isAuthenticated = false;
        state.isLoading = false;
        state.error = null;
      })
      
      // Update profile
      .addCase(updateProfileAsync.pending, (state: AuthState) => {
        state.isLoading = true;
        state.error = null;
      })
      .addCase(updateProfileAsync.fulfilled, (state: AuthState, action: any) => {
        state.isLoading = false;
        state.user = action.payload;
      })
      .addCase(updateProfileAsync.rejected, (state: AuthState, action: any) => {
        state.isLoading = false;
        state.error = action.payload as string;
      })
      
      // Change password
      .addCase(changePasswordAsync.pending, (state: AuthState) => {
        state.isLoading = true;
        state.error = null;
      })
      .addCase(changePasswordAsync.fulfilled, (state: AuthState) => {
        state.isLoading = false;
      })
      .addCase(changePasswordAsync.rejected, (state: AuthState, action: any) => {
        state.isLoading = false;
        state.error = action.payload as string;
      });
  },
});

export const { clearError, setTokens, clearAuth, updateUser } = authSlice.actions;
export default authSlice.reducer;