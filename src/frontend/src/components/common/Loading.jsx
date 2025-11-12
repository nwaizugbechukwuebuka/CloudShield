import React from 'react';
import PropTypes from 'prop-types';
import {
  Box,
  CircularProgress,
  LinearProgress,
  Skeleton,
  Typography,
  Backdrop,
} from '@mui/material';

export function LoadingSpinner({ size = 40, color = 'primary', thickness = 3.6 }) {
  return (
    <Box display="flex" justifyContent="center" alignItems="center" p={2}>
      <CircularProgress size={size} color={color} thickness={thickness} />
    </Box>
  );
}

export function LoadingOverlay({ open, message = 'Loading...' }) {
  return (
    <Backdrop
      sx={{
        color: '#fff',
        zIndex: (theme) => theme.zIndex.drawer + 1,
        display: 'flex',
        flexDirection: 'column',
        gap: 2,
      }}
      open={open}
    >
      <CircularProgress color="inherit" size={60} />
      {message && (
        <Typography variant="h6" color="inherit">
          {message}
        </Typography>
      )}
    </Backdrop>
  );
}
export function LoadingProgress({ value, message }) {
  return (
    <Box sx={{ width: '100%', p: 2 }}>
      {message && (
        <Typography variant="body2" sx={{ mb: 1 }}>
          {message}
        </Typography>
      )}
      <LinearProgress
        variant={value !== undefined ? 'determinate' : 'indeterminate'}
        value={value}
      />
      {value !== undefined && (
        <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5, display: 'block' }}>
          {Math.round(value)}%
        </Typography>
      )}
    </Box>
  );
}

export function LoadingSkeleton({ 
  variant = 'text', 
  width = '100%', 
  height, 
  count = 1,
  spacing = 1,
}) {
  return (
    <>
      {Array.from({ length: count }).map((_, index) => (
        <Skeleton 
          key={index} 
          variant={variant} 
          width={width} 
          height={height}
          sx={{ mb: spacing }}
        />
      ))}
    </>
  );
}

export function TableLoading({ rows = 5, columns = 4 }) {
  return (
    <>
      {Array.from({ length: rows }).map((_, rowIndex) => (
        <Box key={rowIndex} sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
          {Array.from({ length: columns }).map((_, colIndex) => (
            <Skeleton key={colIndex} variant="rectangular" width="100%" height={40} sx={{ mr: 1 }} />
          ))}
        </Box>
      ))}
    </>
  );
}

export function CardLoading({ count = 3 }) {
  return (
    <>
      {Array.from({ length: count }).map((_, index) => (
        <Box key={index} sx={{ p: 2, border: '1px solid #e0e0e0', borderRadius: 1, mb: 2 }}>
          <Skeleton variant="text" width="80%" />
          <Skeleton variant="text" width="60%" />
          <Skeleton variant="rectangular" width="100%" height={100} sx={{ mt: 1 }} />
        </Box>
      ))}
    </>
  );
}

export function FullPageLoading({ message = 'Loading...' }) {
  return (
    <Box 
      display="flex" 
      flexDirection="column" 
      justifyContent="center" 
      alignItems="center"
      minHeight="100vh"
    >
      <CircularProgress size={60} />
      <Typography variant="h6" sx={{ mt: 2 }}>
        {message}
      </Typography>
    </Box>
  );
}

// Component loading states for lazy-loaded routes
export function PageLoading() {
  return (
    <Box sx={{ p: 3 }}>
      <Skeleton variant="rectangular" width="100%" height={60} sx={{ mb: 3 }} />
      <Box sx={{ display: 'flex', gap: 2, mb: 3 }}>
        {Array.from({ length: 4 }).map((_, index) => (
          <Skeleton key={index} variant="rectangular" width="25%" height={100} />
        ))}
      </Box>
      <Skeleton variant="rectangular" width="100%" height={400} />
    </Box>
  );
}
