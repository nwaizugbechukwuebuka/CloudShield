import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios';
import { AuthTokens } from '@/types';
import { toast } from 'react-hot-toast';

// API Configuration
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
const REQUEST_TIMEOUT = 30000;

// Create axios instance
const apiClient: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  timeout: REQUEST_TIMEOUT,
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
  },
});

// Token management
let authTokens: AuthTokens | null = null;
let refreshPromise: Promise<AuthTokens> | null = null;

export const setAuthTokens = (tokens: AuthTokens | null) => {
  authTokens = tokens;
  
  if (tokens) {
    localStorage.setItem('cloudshield_tokens', JSON.stringify(tokens));
    apiClient.defaults.headers.common['Authorization'] = `Bearer ${tokens.access_token}`;
  } else {
    localStorage.removeItem('cloudshield_tokens');
    delete apiClient.defaults.headers.common['Authorization'];
  }
};

export const getStoredTokens = (): AuthTokens | null => {
  try {
    const stored = localStorage.getItem('cloudshield_tokens');
    return stored ? JSON.parse(stored) : null;
  } catch {
    return null;
  }
};

// Initialize tokens from localStorage
const storedTokens = getStoredTokens();
if (storedTokens) {
  setAuthTokens(storedTokens);
}

// Request interceptor
apiClient.interceptors.request.use(
  (config) => {
    // Add timestamp to prevent caching
    if (config.method === 'get') {
      config.params = {
        ...config.params,
        _t: Date.now(),
      };
    }
    
    // Add request ID for tracking
    config.headers['X-Request-ID'] = `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor
apiClient.interceptors.response.use(
  (response: AxiosResponse) => {
    return response;
  },
  async (error) => {
    const originalRequest = error.config;
    
    // Handle token refresh on 401 errors
    if (error.response?.status === 401 && !originalRequest._retry && authTokens?.refresh_token) {
      originalRequest._retry = true;
      
      try {
        // Prevent multiple simultaneous refresh requests
        if (!refreshPromise) {
          refreshPromise = refreshAccessToken();
        }
        
        const newTokens = await refreshPromise;
        refreshPromise = null;
        
        setAuthTokens(newTokens);
        
        // Retry the original request with new token
        originalRequest.headers['Authorization'] = `Bearer ${newTokens.access_token}`;
        return apiClient(originalRequest);
        
      } catch (refreshError) {
        refreshPromise = null;
        // Redirect to login on refresh failure
        setAuthTokens(null);
        window.location.href = '/login';
        return Promise.reject(refreshError);
      }
    }
    
    // Handle other HTTP errors
    if (error.response) {
      const { status, data } = error.response;
      
      switch (status) {
        case 400:
          toast.error(data.detail || 'Bad request. Please check your input.');
          break;
        case 403:
          toast.error('You do not have permission to perform this action.');
          break;
        case 404:
          toast.error('The requested resource was not found.');
          break;
        case 409:
          toast.error(data.detail || 'Conflict. The resource already exists.');
          break;
        case 422:
          toast.error('Validation error. Please check your input.');
          break;
        case 429:
          toast.error('Too many requests. Please try again later.');
          break;
        case 500:
          toast.error('Internal server error. Please try again later.');
          break;
        default:
          toast.error(`An error occurred: ${data.detail || 'Unknown error'}`);
      }
    } else if (error.request) {
      // Network error
      toast.error('Network error. Please check your connection.');
    } else {
      // Other errors
      toast.error('An unexpected error occurred.');
    }
    
    return Promise.reject(error);
  }
);

// Refresh token function
const refreshAccessToken = async (): Promise<AuthTokens> => {
  if (!authTokens?.refresh_token) {
    throw new Error('No refresh token available');
  }
  
  const response = await axios.post(`${API_BASE_URL}/auth/refresh`, {
    refresh_token: authTokens.refresh_token,
  });
  
  return response.data;
};

// Generic API methods
export const apiService = {
  // GET request
  async get<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
    const response = await apiClient.get<T>(url, config);
    return response.data;
  },
  
  // POST request
  async post<T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    const response = await apiClient.post<T>(url, data, config);
    return response.data;
  },
  
  // PUT request
  async put<T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    const response = await apiClient.put<T>(url, data, config);
    return response.data;
  },
  
  // PATCH request
  async patch<T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    const response = await apiClient.patch<T>(url, data, config);
    return response.data;
  },
  
  // DELETE request
  async delete<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
    const response = await apiClient.delete<T>(url, config);
    return response.data;
  },
  
  // Upload file
  async upload<T>(url: string, file: File, onProgress?: (progress: number) => void): Promise<T> {
    const formData = new FormData();
    formData.append('file', file);
    
    const config: AxiosRequestConfig = {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    };
    
    if (onProgress) {
      config.onUploadProgress = (progressEvent) => {
        const progress = progressEvent.total 
          ? Math.round((progressEvent.loaded * 100) / progressEvent.total)
          : 0;
        onProgress(progress);
      };
    }
    
    const response = await apiClient.post<T>(url, formData, config);
    return response.data;
  },
  
  // Download file
  async download(url: string, filename?: string): Promise<void> {
    const response = await apiClient.get(url, {
      responseType: 'blob',
    });
    
    const blob = new Blob([response.data]);
    const downloadUrl = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.download = filename || 'download';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(downloadUrl);
  },
};

// Health check
export const healthCheck = async (): Promise<boolean> => {
  try {
    await apiService.get('/health');
    return true;
  } catch {
    return false;
  }
};

// Export the configured axios instance for custom usage
export { apiClient };
export default apiService;