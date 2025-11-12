import React from 'react';
import {
  Box,
  Container,
  Typography,
  Button,
  Card,
  CardContent,
  Alert,
  Stack,
  Divider,
} from '@mui/material';
import {
  Error as ErrorIcon,
  Refresh as RefreshIcon,
  Home as HomeIcon,
  BugReport as BugReportIcon,
} from '@mui/icons-material';

export class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
    };
  }

  static getDerivedStateFromError(error) {
    return {
      hasError: true,
      error,
    };
  }

  componentDidCatch(error, errorInfo) {
    console.error('ErrorBoundary caught an error:', error, errorInfo);
    
    this.setState({
      error,
      errorInfo,
    });

    // Log error to monitoring service
    if (import.meta.env.PROD) {
      // TODO: Send to error monitoring service (Sentry, LogRocket, etc.)
    }
  }

  handleReload = () => {
    window.location.reload();
  };

  handleGoHome = () => {
    window.location.href = '/';
  };

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback;
      }

      return (
        <Container maxWidth="md" sx={{ py: 8 }}>
          <Card>
            <CardContent sx={{ textAlign: 'center', py: 6 }}>
              <ErrorIcon sx={{ fontSize: 80, color: 'error.main', mb: 2 }} />
              
              <Typography variant="h4" gutterBottom>
                Oops! Something went wrong
              </Typography>
              
              <Typography variant="body1" color="text.secondary" sx={{ mb: 4 }}>
                We're sorry, but something unexpected happened. Our team has been notified and is working on a fix.
              </Typography>

              <Stack spacing={2} direction="row" justifyContent="center" sx={{ mb: 4 }}>
                <Button
                  variant="contained"
                  startIcon={<RefreshIcon />}
                  onClick={this.handleReload}
                >
                  Reload Page
                </Button>
                <Button
                  variant="outlined"
                  startIcon={<HomeIcon />}
                  onClick={this.handleGoHome}
                >
                  Go Home
                </Button>
              </Stack>

              {import.meta.env.DEV && this.state.error && (
                <>
                  <Divider sx={{ mb: 3 }} />
                  
                  <Alert severity="error" sx={{ textAlign: 'left', mb: 2 }}>
                    <Typography variant="h6" gutterBottom>
                      Error Details (Development Mode)
                    </Typography>
                    <Typography variant="body2" component="pre" sx={{ 
                      whiteSpace: 'pre-wrap',
                      fontSize: '0.75rem',
                      fontFamily: 'monospace',
                    }}>
                      {this.state.error.toString()}
                    </Typography>
                  </Alert>

                  {this.state.errorInfo && (
                    <Alert severity="warning" sx={{ textAlign: 'left' }}>
                      <Typography variant="h6" gutterBottom>
                        Component Stack
                      </Typography>
                      <Typography variant="body2" component="pre" sx={{ 
                        whiteSpace: 'pre-wrap',
                        fontSize: '0.75rem',
                        fontFamily: 'monospace',
                      }}>
                        {this.state.errorInfo.componentStack}
                      </Typography>
                    </Alert>
                  )}
                </>
              )}
            </CardContent>
          </Card>
        </Container>
      );
    }

    return this.props.children;
  }
}

// Higher-order component for error boundaries
export function withErrorBoundary(
  Component,
  fallback
) {
  return function WithErrorBoundaryComponent(props) {
    return (
      <ErrorBoundary fallback={fallback}>
        <Component {...props} />
      </ErrorBoundary>
    );
  };
}

// Hook for error boundary context
export function useErrorHandler() {
  return (error, errorInfo) => {
    console.error('Manual error report:', error, errorInfo);
    
    // In production, send to monitoring service
    if (import.meta.env.PROD) {
      // TODO: Send to error monitoring service
    }
  };
}
