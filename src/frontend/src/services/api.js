/**
 * API client for CloudShield backend
 */
import axios from 'axios'
import toast from 'react-hot-toast'

// Create axios instance
const api = axios.create({
  baseURL: '/api',
  timeout: 30000,
})

// Request interceptor to add auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('access_token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Response interceptor to handle errors
api.interceptors.response.use(
  (response) => {
    return response
  },
  async (error) => {
    const originalRequest = error.config

    // Handle 401 errors (unauthorized)
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true
      
      // Try to refresh token
      const refreshToken = localStorage.getItem('refresh_token')
      if (refreshToken) {
        try {
          const response = await axios.post('/api/auth/refresh', {}, {
            headers: { Authorization: `Bearer ${refreshToken}` }
          })
          
          const { access_token } = response.data
          localStorage.setItem('access_token', access_token)
          
          // Retry original request
          originalRequest.headers.Authorization = `Bearer ${access_token}`
          return api(originalRequest)
        } catch (refreshError) {
          // Refresh failed, redirect to login
          localStorage.removeItem('access_token')
          localStorage.removeItem('refresh_token')
          window.location.href = '/login'
        }
      } else {
        // No refresh token, redirect to login
        window.location.href = '/login'
      }
    }

    // Handle other errors
    if (error.response?.data?.detail) {
      toast.error(error.response.data.detail)
    } else if (error.message) {
      toast.error(error.message)
    } else {
      toast.error('An unexpected error occurred')
    }

    return Promise.reject(error)
  }
)

// API endpoints
export const authAPI = {
  login: (email, password) => 
    api.post('/auth/login', { email, password }),
  
  register: (email, password, full_name) => 
    api.post('/auth/register', { email, password, full_name }),
  
  refresh: () => 
    api.post('/auth/refresh'),
  
  logout: () => 
    api.post('/auth/logout'),
  
  getUser: () => 
    api.get('/auth/me')
}

export const integrationsAPI = {
  list: () => 
    api.get('/integrations'),
  
  get: (id) => 
    api.get(`/integrations/${id}`),
  
  startOAuth: (provider, name) => 
    api.post(`/integrations/oauth/${provider}/authorize?integration_name=${encodeURIComponent(name)}`),
  
  update: (id, data) => 
    api.put(`/integrations/${id}`, data),
  
  delete: (id) => 
    api.delete(`/integrations/${id}`),
  
  test: (id) => 
    api.post(`/integrations/${id}/test`)
}

export const scansAPI = {
  start: (integrationId) => 
    api.post(`/scans/${integrationId}/start`),
  
  getStatus: (scanId) => 
    api.get(`/scans/${scanId}/status`),
  
  getFindings: (params = {}) => {
    const searchParams = new URLSearchParams()
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null && value !== '') {
        searchParams.append(key, value)
      }
    })
    return api.get(`/scans/findings?${searchParams.toString()}`)
  },
  
  getFinding: (id) => 
    api.get(`/scans/findings/${id}`),
  
  updateFinding: (id, data) => 
    api.put(`/scans/findings/${id}`, data),
  
  getStats: () => 
    api.get('/scans/stats')
}

export default api
