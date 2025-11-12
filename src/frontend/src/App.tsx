import React, { useEffect } from 'react';
import { Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { Box, CircularProgress, Backdrop } from '@mui/material';
import { AnimatePresence } from 'framer-motion';

// Redux
import { useAppDispatch, useAppSelector } from '@/store';
import { loadUserAsync } from '@/store/slices/authSlice';

// Components
import Layout from '@/components/Layout';
import ProtectedRoute from '@/components/ProtectedRoute';
import PublicRoute from '@/components/PublicRoute';
import NotificationManager from '@/components/NotificationManager';
import WebSocketManager from '@/components/WebSocketManager';

// Pages - Public
import LandingPage from '@/pages/LandingPage';
import LoginPage from '@/pages/LoginPage';
import RegisterPage from '@/pages/RegisterPage';
import ForgotPasswordPage from '@/pages/ForgotPasswordPage';
import ResetPasswordPage from '@/pages/ResetPasswordPage';
import VerifyEmailPage from '@/pages/VerifyEmailPage';

// Pages - Protected
import DashboardPage from '@/pages/DashboardPage';
import IntegrationsPage from '@/pages/IntegrationsPage';
import FindingsPage from '@/pages/FindingsPage';
import AlertsPage from '@/pages/AlertsPage';
import SettingsPage from '@/pages/SettingsPage';
import UsersPage from '@/pages/UsersPage';
import ProfilePage from '@/pages/ProfilePage';
import SecurityPage from '@/pages/SecurityPage';
import CompliancePage from '@/pages/CompliancePage';
import ReportsPage from '@/pages/ReportsPage';

// Error pages
import NotFoundPage from '@/pages/NotFoundPage';
import ErrorPage from '@/pages/ErrorPage';

// Utils
import { getStoredTokens } from '@/services/api';

function App() {
  const dispatch = useAppDispatch();
  const location = useLocation();
  
  const { user, isAuthenticated, isLoading } = useAppSelector((state) => state.auth);
  const { loading: uiLoading } = useAppSelector((state) => state.ui);

  // Initialize app
  useEffect(() => {
    const initializeApp = async () => {
      const tokens = getStoredTokens();
      if (tokens && !user) {
        try {
          await dispatch(loadUserAsync()).unwrap();
        } catch (error) {
          console.error('Failed to load user:', error);
          // Token might be expired, redirect to login
        }
      }
    };

    initializeApp();
  }, [dispatch, user]);

  // Show loading screen on initial load
  if (isLoading) {
    return (
      <Backdrop open={true} sx={{ zIndex: (theme) => theme.zIndex.drawer + 1 }}>
        <CircularProgress color="primary" size={60} />
      </Backdrop>
    );
  }

  return (
    <Box sx={{ display: 'flex', minHeight: '100vh' }}>
      <AnimatePresence mode="wait">
        <Routes location={location} key={location.pathname}>
          {/* Public Routes */}
          <Route
            path="/"
            element={
              <PublicRoute>
                <LandingPage />
              </PublicRoute>
            }
          />
          <Route
            path="/login"
            element={
              <PublicRoute>
                <LoginPage />
              </PublicRoute>
            }
          />
          <Route
            path="/register"
            element={
              <PublicRoute>
                <RegisterPage />
              </PublicRoute>
            }
          />
          <Route
            path="/forgot-password"
            element={
              <PublicRoute>
                <ForgotPasswordPage />
              </PublicRoute>
            }
          />
          <Route
            path="/reset-password"
            element={
              <PublicRoute>
                <ResetPasswordPage />
              </PublicRoute>
            }
          />
          <Route
            path="/verify-email"
            element={
              <PublicRoute>
                <VerifyEmailPage />
              </PublicRoute>
            }
          />

          {/* Protected Routes - All wrapped in Layout */}
          <Route
            path="/dashboard"
            element={
              <ProtectedRoute>
                <Layout>
                  <DashboardPage />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/integrations/*"
            element={
              <ProtectedRoute>
                <Layout>
                  <IntegrationsPage />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/findings/*"
            element={
              <ProtectedRoute>
                <Layout>
                  <FindingsPage />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/alerts"
            element={
              <ProtectedRoute>
                <Layout>
                  <AlertsPage />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/compliance"
            element={
              <ProtectedRoute>
                <Layout>
                  <CompliancePage />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/reports"
            element={
              <ProtectedRoute>
                <Layout>
                  <ReportsPage />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/users"
            element={
              <ProtectedRoute requiredRole="admin">
                <Layout>
                  <UsersPage />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/profile"
            element={
              <ProtectedRoute>
                <Layout>
                  <ProfilePage />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/security"
            element={
              <ProtectedRoute>
                <Layout>
                  <SecurityPage />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/settings"
            element={
              <ProtectedRoute>
                <Layout>
                  <SettingsPage />
                </Layout>
              </ProtectedRoute>
            }
          />

          {/* Error Routes */}
          <Route path="/error" element={<ErrorPage />} />
          <Route path="/404" element={<NotFoundPage />} />

          {/* Catch-all Route */}
          <Route path="*" element={<Navigate to="/404" replace />} />
        </Routes>
      </AnimatePresence>

      {/* Global Components */}
      <NotificationManager />
      {isAuthenticated && <WebSocketManager />}

      {/* Global Loading Overlay */}
      <Backdrop
        open={uiLoading}
        sx={{ zIndex: (theme) => theme.zIndex.drawer + 1 }}
      >
        <CircularProgress color="primary" />
      </Backdrop>
    </Box>
  )
}

export default App
