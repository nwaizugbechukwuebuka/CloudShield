import React from 'react';
import {
  Box,
  CircularProgress,
  LinearProgress,
  Skeleton,
  Typography,
  Backdrop,
} from '@mui/material';

interface LoadingSpinnerProps {
  size?: number | string;
  color?: 'primary' | 'secondary' | 'error' | 'info' | 'success' | 'warning' | 'inherit';
  thickness?: number;
}

export function LoadingSpinner({ size = 40, color = 'primary', thickness = 3.6 }: LoadingSpinnerProps) {
  return (
    <Box display="flex" justifyContent="center" alignItems="center" p={2}>
      <CircularProgress size={size} color={color} thickness={thickness} />
    </Box>
  );
}

interface LoadingOverlayProps {
  open: boolean;
  message?: string;
}

export function LoadingOverlay({ open, message = 'Loading...' }: LoadingOverlayProps) {
  return (
    <Backdrop
      sx={{ 
        color: '#fff', 
        zIndex: (theme) => theme.zIndex.drawer + 1,
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

interface LoadingProgressProps {
  value?: number;
  message?: string;
}

export function LoadingProgress({ value, message }: LoadingProgressProps) {
  return (
    <Box sx={{ width: '100%', p: 2 }}>
      {message && (
        <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
          {message}
        </Typography>
      )}
      <LinearProgress 
        variant={value !== undefined ? 'determinate' : 'indeterminate'} 
        value={value}
        sx={{ height: 6, borderRadius: 3 }}
      />
      {value !== undefined && (
        <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5, display: 'block' }}>
          {Math.round(value)}%
        </Typography>
      )}
    </Box>
  );
}

interface LoadingSkeletonProps {
  variant?: 'text' | 'rectangular' | 'circular';
  width?: number | string;
  height?: number | string;
  count?: number;
  spacing?: number;
}

export function LoadingSkeleton({ 
  variant = 'text', 
  width = '100%', 
  height, 
  count = 1,
  spacing = 1,
}: LoadingSkeletonProps) {
  if (count === 1) {
    return <Skeleton variant={variant} width={width} height={height} />;
  }

  return (
    <Box>
      {Array.from({ length: count }).map((_, index) => (
        <Skeleton 
          key={index}
          variant={variant} 
          width={width} 
          height={height} 
          sx={{ mb: spacing }}
        />
      ))}
    </Box>
  );
}

interface TableLoadingProps {
  rows?: number;
  columns?: number;
}

export function TableLoading({ rows = 5, columns = 4 }: TableLoadingProps) {
  return (
    <>
      {Array.from({ length: rows }).map((_, rowIndex) => (
        <tr key={rowIndex}>
          {Array.from({ length: columns }).map((_, colIndex) => (
            <td key={colIndex} style={{ padding: '16px' }}>
              <Skeleton variant="text" width="80%" />
            </td>
          ))}
        </tr>
      ))}
    </>
  );
}

interface CardLoadingProps {
  count?: number;
}

export function CardLoading({ count = 3 }: CardLoadingProps) {
  return (
    <>
      {Array.from({ length: count }).map((_, index) => (
        <Box key={index} sx={{ p: 2, border: 1, borderColor: 'divider', borderRadius: 1, mb: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
            <Skeleton variant="circular" width={40} height={40} sx={{ mr: 2 }} />
            <Box sx={{ flexGrow: 1 }}>
              <Skeleton variant="text" width="60%" />
              <Skeleton variant="text" width="40%" />
            </Box>
          </Box>
          <Skeleton variant="rectangular" height={60} sx={{ mb: 1 }} />
          <Skeleton variant="text" width="80%" />
        </Box>
      ))}
    </>
  );
}

interface FullPageLoadingProps {
  message?: string;
}

export function FullPageLoading({ message = 'Loading...' }: FullPageLoadingProps) {
  return (
    <Box 
      display="flex" 
      flexDirection="column"
      justifyContent="center" 
      alignItems="center" 
      minHeight="100vh"
      gap={2}
    >
      <CircularProgress size={60} />
      <Typography variant="h6" color="text.secondary">
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

export default LoadingSpinner;