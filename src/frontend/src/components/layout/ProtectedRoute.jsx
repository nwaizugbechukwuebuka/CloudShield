import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useSelector } from 'react-redux';
import { Box, CircularProgress } from '@mui/material';

import { selectAuth } from '@/store/slices/authSlice';

export function ProtectedRoute({ children, requiredRole }) {
  const location = useLocation();
  const { isAuthenticated, user, loading } = useSelector(selectAuth);

  // Show loading spinner while checking authentication
  if (loading) {
    return (
      <Box 
        display="flex" 
        justifyContent="center" 
        alignItems="center" 
        minHeight="100vh"
      >
        <CircularProgress />
      </Box>
    );
  }

  // Redirect to login if not authenticated
  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // Check role-based access
  if (requiredRole && user?.role !== requiredRole) {
    return <Navigate to="/unauthorized" replace />;
  }

  return <>{children}</>;
}

export function PublicRoute({ children }) {
  const { isAuthenticated, loading } = useSelector(selectAuth);

  // Show loading spinner while checking authentication
  if (loading) {
    return (
      <Box 
        display="flex" 
        justifyContent="center" 
        alignItems="center" 
        minHeight="100vh"
      >
        <CircularProgress />
      </Box>
    );
  }

  // Redirect to dashboard if already authenticated
  if (isAuthenticated) {
    return <Navigate to="/" replace />;
  }

  return <>{children}</>;
}