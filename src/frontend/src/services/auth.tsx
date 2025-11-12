/**
 * Authentication service and context
 */
import React, { createContext, useContext, useState, useEffect } from 'react'
import { authAPI } from './api'
import toast from 'react-hot-toast'

const AuthContext = createContext({})

export const useAuth = () => {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)

  // Check for existing auth on mount
  useEffect(() => {
    const token = localStorage.getItem('access_token')
    if (token) {
      // Verify token and get user info
      authAPI.getUser()
        .then(response => {
          setUser(response.data)
        })
        .catch(() => {
          // Invalid token, clear storage
          localStorage.removeItem('access_token')
          localStorage.removeItem('refresh_token')
        })
        .finally(() => {
          setLoading(false)
        })
    } else {
      setLoading(false)
    }
  }, [])

  const login = async (email, password) => {
    try {
      const response = await authAPI.login(email, password)
      const { access_token, refresh_token } = response.data
      
      // Store tokens
      localStorage.setItem('access_token', access_token)
      localStorage.setItem('refresh_token', refresh_token)
      
      // Get user info
      const userResponse = await authAPI.getUser()
      setUser(userResponse.data)
      
      toast.success('Successfully logged in!')
      return { success: true }
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.detail || 'Login failed' 
      }
    }
  }

  const register = async (email, password, fullName) => {
    try {
      await authAPI.register(email, password, fullName)
      
      // Auto-login after registration
      const loginResult = await login(email, password)
      if (loginResult.success) {
        toast.success('Account created successfully!')
      }
      
      return { success: true }
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.detail || 'Registration failed' 
      }
    }
  }

  const logout = async () => {
    try {
      await authAPI.logout()
    } catch (error) {
      // Ignore logout errors
    } finally {
      // Clear local storage and state
      localStorage.removeItem('access_token')
      localStorage.removeItem('refresh_token')
      setUser(null)
      toast.success('Successfully logged out!')
    }
  }

  const value = {
    user,
    loading,
    login,
    register,
    logout,
    isAuthenticated: !!user
  }

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  )
}
