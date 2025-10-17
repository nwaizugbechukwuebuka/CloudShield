/**
 * CloudShield Security Dashboard
 * Main dashboard component with real-time security metrics, alerts overview,
 * compliance status, and integration management.
 * 
 * Author: Chukwuebuka Tobiloba Nwaizugbe
 * Copyright (c) 2025 CloudShield Security Systems
 */

import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Grid,
  Card,
  CardContent,
  Typography,
  Box,
  Alert,
  Skeleton,
  Fab,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Chip,
  IconButton,
  Tooltip,
  CircularProgress,
  LinearProgress,
  Divider,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  useTheme,
  useMediaQuery
} from '@mui/material';
import {
  Security as SecurityIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  CheckCircle as CheckCircleIcon,
  Refresh as RefreshIcon,
  Settings as SettingsIcon,
  Notifications as NotificationsIcon,
  TrendingUp as TrendingUpIcon,
  TrendingDown as TrendingDownIcon,
  Assessment as AssessmentIcon,
  Shield as ShieldIcon,
  BugReport as BugReportIcon,
  Speed as SpeedIcon,
  Storage as StorageIcon,
  Cloud as CloudIcon,
  Integration as IntegrationIcon
} from '@mui/icons-material';
import { Line, Doughnut, Bar } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip as ChartTooltip,
  Legend,
  ArcElement,
  BarElement
} from 'chart.js';

import { api } from '../services/api';
import { useAuth } from '../services/auth';
import RiskChart from './RiskChart';
import AlertTable from './AlertTable';
import IntegrationCard from './IntegrationCard';

// Register Chart.js components
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  ChartTooltip,
  Legend,
  ArcElement,
  BarElement
);

const Dashboard = () => {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  const { user } = useAuth();

  // State management
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [refreshing, setRefreshing] = useState(false);
  const [dashboardData, setDashboardData] = useState({
    overview: {},
    alerts: [],
    findings: [],
    integrations: [],
    compliance: {},
    metrics: {},
    trends: {}
  });
  const [lastUpdated, setLastUpdated] = useState(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [refreshInterval, setRefreshInterval] = useState(30000); // 30 seconds

  // Load dashboard data
  const loadDashboardData = useCallback(async (showLoading = true) => {
    try {
      if (showLoading) setRefreshing(true);
      
      const [
        overviewResponse,
        alertsResponse,
        findingsResponse,
        integrationsResponse,
        complianceResponse,
        metricsResponse
      ] = await Promise.all([
        api.get('/dashboard/overview'),
        api.get('/alerts?limit=10&status=active'),
        api.get('/findings?limit=10&severity=HIGH,CRITICAL'),
        api.get('/integrations?status=active'),
        api.get('/dashboard/compliance'),
        api.get('/dashboard/metrics')
      ]);

      setDashboardData({
        overview: overviewResponse.data,
        alerts: alertsResponse.data.items || alertsResponse.data,
        findings: findingsResponse.data.items || findingsResponse.data,
        integrations: integrationsResponse.data.items || integrationsResponse.data,
        compliance: complianceResponse.data,
        metrics: metricsResponse.data,
        trends: metricsResponse.data.trends || {}
      });

      setLastUpdated(new Date());
      setError(null);
    } catch (err) {
      console.error('Failed to load dashboard data:', err);
      setError('Failed to load dashboard data. Please try again.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  // Auto-refresh effect
  useEffect(() => {
    let interval;
    if (autoRefresh && refreshInterval > 0) {
      interval = setInterval(() => {
        loadDashboardData(false);
      }, refreshInterval);
    }
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [autoRefresh, refreshInterval, loadDashboardData]);

  // Initial load
  useEffect(() => {
    loadDashboardData();
  }, [loadDashboardData]);

  // Manual refresh handler
  const handleRefresh = useCallback(() => {
    loadDashboardData(true);
  }, [loadDashboardData]);

  // Memoized computed values
  const securityScore = useMemo(() => {
    const { overview } = dashboardData;
    if (!overview.total_findings) return 100;
    
    const criticalWeight = 10;
    const highWeight = 5;
    const mediumWeight = 2;
    const lowWeight = 1;
    
    const weightedScore = 
      (overview.critical_findings || 0) * criticalWeight +
      (overview.high_findings || 0) * highWeight +
      (overview.medium_findings || 0) * mediumWeight +
      (overview.low_findings || 0) * lowWeight;
    
    const maxPossibleScore = overview.total_findings * criticalWeight;
    const score = Math.max(0, 100 - (weightedScore / maxPossibleScore * 100));
    
    return Math.round(score);
  }, [dashboardData.overview]);

  const riskTrend = useMemo(() => {
    const { trends } = dashboardData;
    if (!trends.risk_score) return 'stable';
    
    const current = trends.risk_score.current || 0;
    const previous = trends.risk_score.previous || 0;
    
    if (current > previous + 5) return 'increasing';
    if (current < previous - 5) return 'decreasing';
    return 'stable';
  }, [dashboardData.trends]);

  const complianceStatus = useMemo(() => {
    const { compliance } = dashboardData;
    if (!compliance.frameworks) return {};
    
    return Object.entries(compliance.frameworks).map(([framework, data]) => ({
      name: framework,
      score: data.compliance_percentage || 0,
      status: data.status || 'unknown',
      controls: data.total_controls || 0,
      compliant: data.compliant_controls || 0
    }));
  }, [dashboardData.compliance]);

  // Chart configurations
  const alertsTrendData = {
    labels: dashboardData.trends.labels || [],
    datasets: [
      {
        label: 'Critical Alerts',
        data: dashboardData.trends.critical_alerts || [],
        borderColor: theme.palette.error.main,
        backgroundColor: theme.palette.error.light,
        tension: 0.1
      },
      {
        label: 'High Alerts',
        data: dashboardData.trends.high_alerts || [],
        borderColor: theme.palette.warning.main,
        backgroundColor: theme.palette.warning.light,
        tension: 0.1
      },
      {
        label: 'Medium Alerts',
        data: dashboardData.trends.medium_alerts || [],
        borderColor: theme.palette.info.main,
        backgroundColor: theme.palette.info.light,
        tension: 0.1
      }
    ]
  };

  const severityDistributionData = {
    labels: ['Critical', 'High', 'Medium', 'Low'],
    datasets: [
      {
        data: [
          dashboardData.overview.critical_findings || 0,
          dashboardData.overview.high_findings || 0,
          dashboardData.overview.medium_findings || 0,
          dashboardData.overview.low_findings || 0
        ],
        backgroundColor: [
          theme.palette.error.main,
          theme.palette.warning.main,
          theme.palette.info.main,
          theme.palette.success.main
        ],
        borderWidth: 2,
        borderColor: theme.palette.background.paper
      }
    ]
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: isMobile ? 'bottom' : 'top'
      }
    },
    scales: {
      y: {
        beginAtZero: true,
        grid: {
          color: theme.palette.divider
        }
      },
      x: {
        grid: {
          color: theme.palette.divider
        }
      }
    }
  };

  if (loading) {
    return (
      <Box sx={{ p: 3 }}>
        <Grid container spacing={3}>
          {[...Array(8)].map((_, index) => (
            <Grid item xs={12} md={6} lg={3} key={index}>
              <Card>
                <CardContent>
                  <Skeleton variant="text" width="60%" />
                  <Skeleton variant="rectangular" width="100%" height={60} />
                  <Skeleton variant="text" width="40%" />
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3, minHeight: '100vh', backgroundColor: theme.palette.background.default }}>
      {/* Header */}
      <Box sx={{ mb: 4, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Box>
          <Typography variant="h4" component="h1" gutterBottom>
            Security Dashboard
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Welcome back, {user?.full_name || 'User'}
            {lastUpdated && (
              <> • Last updated: {lastUpdated.toLocaleTimeString()}</>
            )}
          </Typography>
        </Box>
        
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Tooltip title="Refresh Dashboard">
            <IconButton onClick={handleRefresh} disabled={refreshing}>
              {refreshing ? <CircularProgress size={20} /> : <RefreshIcon />}
            </IconButton>
          </Tooltip>
          <Tooltip title="Dashboard Settings">
            <IconButton onClick={() => setSettingsOpen(true)}>
              <SettingsIcon />
            </IconButton>
          </Tooltip>
        </Box>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* Key Metrics Row */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        {/* Security Score */}
        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ height: '100%' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <ShieldIcon sx={{ mr: 1, color: theme.palette.primary.main }} />
                <Typography variant="h6">Security Score</Typography>
              </Box>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Typography variant="h3" color="primary">
                  {securityScore}
                </Typography>
                <Box sx={{ textAlign: 'right' }}>
                  <Typography variant="body2" color="text.secondary">
                    {riskTrend === 'increasing' && (
                      <Chip
                        icon={<TrendingUpIcon />}
                        label="Increasing Risk"
                        color="error"
                        size="small"
                      />
                    )}
                    {riskTrend === 'decreasing' && (
                      <Chip
                        icon={<TrendingDownIcon />}
                        label="Improving"
                        color="success"
                        size="small"
                      />
                    )}
                    {riskTrend === 'stable' && (
                      <Chip
                        label="Stable"
                        color="default"
                        size="small"
                      />
                    )}
                  </Typography>
                </Box>
              </Box>
              <LinearProgress
                variant="determinate"
                value={securityScore}
                sx={{ mt: 2 }}
                color={securityScore >= 80 ? 'success' : securityScore >= 60 ? 'warning' : 'error'}
              />
            </CardContent>
          </Card>
        </Grid>

        {/* Active Alerts */}
        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ height: '100%' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <NotificationsIcon sx={{ mr: 1, color: theme.palette.warning.main }} />
                <Typography variant="h6">Active Alerts</Typography>
              </Box>
              <Typography variant="h3" color="warning.main">
                {dashboardData.overview.active_alerts || 0}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {dashboardData.overview.new_alerts_today || 0} new today
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        {/* Total Findings */}
        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ height: '100%' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <BugReportIcon sx={{ mr: 1, color: theme.palette.error.main }} />
                <Typography variant="h6">Total Findings</Typography>
              </Box>
              <Typography variant="h3" color="error.main">
                {dashboardData.overview.total_findings || 0}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {dashboardData.overview.critical_findings || 0} critical
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        {/* Active Integrations */}
        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ height: '100%' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <IntegrationIcon sx={{ mr: 1, color: theme.palette.success.main }} />
                <Typography variant="h6">Integrations</Typography>
              </Box>
              <Typography variant="h3" color="success.main">
                {dashboardData.overview.active_integrations || 0}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {dashboardData.overview.total_integrations || 0} total configured
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Charts Row */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        {/* Alerts Trend Chart */}
        <Grid item xs={12} lg={8}>
          <Card sx={{ height: 400 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Security Alerts Trend
              </Typography>
              <Box sx={{ height: 320, mt: 2 }}>
                <Line data={alertsTrendData} options={chartOptions} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        {/* Severity Distribution */}
        <Grid item xs={12} lg={4}>
          <Card sx={{ height: 400 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Findings by Severity
              </Typography>
              <Box sx={{ height: 320, mt: 2, display: 'flex', justifyContent: 'center' }}>
                <Doughnut 
                  data={severityDistributionData} 
                  options={{
                    ...chartOptions,
                    plugins: {
                      ...chartOptions.plugins,
                      legend: {
                        position: 'bottom'
                      }
                    }
                  }} 
                />
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Compliance Status */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Compliance Status
              </Typography>
              <Grid container spacing={2}>
                {complianceStatus.map((framework) => (
                  <Grid item xs={12} sm={6} md={3} key={framework.name}>
                    <Box sx={{ textAlign: 'center' }}>
                      <Typography variant="subtitle1" gutterBottom>
                        {framework.name}
                      </Typography>
                      <Box sx={{ position: 'relative', display: 'inline-flex' }}>
                        <CircularProgress
                          variant="determinate"
                          value={framework.score}
                          size={80}
                          thickness={4}
                          color={framework.score >= 80 ? 'success' : framework.score >= 60 ? 'warning' : 'error'}
                        />
                        <Box
                          sx={{
                            top: 0,
                            left: 0,
                            bottom: 0,
                            right: 0,
                            position: 'absolute',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                          }}
                        >
                          <Typography variant="caption" component="div" color="text.secondary">
                            {`${Math.round(framework.score)}%`}
                          </Typography>
                        </Box>
                      </Box>
                      <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                        {framework.compliant}/{framework.controls} controls
                      </Typography>
                    </Box>
                  </Grid>
                ))}
              </Grid>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Recent Alerts and Findings */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        {/* Recent Alerts */}
        <Grid item xs={12} lg={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Recent Alerts
              </Typography>
              <AlertTable 
                alerts={dashboardData.alerts} 
                compact={true}
                maxHeight={300}
              />
            </CardContent>
          </Card>
        </Grid>

        {/* Recent Findings */}
        <Grid item xs={12} lg={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Critical Findings
              </Typography>
              <List sx={{ maxHeight: 300, overflow: 'auto' }}>
                {dashboardData.findings.slice(0, 5).map((finding, index) => (
                  <React.Fragment key={finding.id || index}>
                    <ListItem>
                      <ListItemIcon>
                        {finding.severity === 'CRITICAL' && <ErrorIcon color="error" />}
                        {finding.severity === 'HIGH' && <WarningIcon color="warning" />}
                        {finding.severity === 'MEDIUM' && <SecurityIcon color="info" />}
                        {finding.severity === 'LOW' && <CheckCircleIcon color="success" />}
                      </ListItemIcon>
                      <ListItemText
                        primary={finding.title}
                        secondary={
                          <Box>
                            <Typography variant="body2" color="text.secondary">
                              {finding.resource_name} • {finding.category}
                            </Typography>
                            <Chip 
                              label={finding.severity} 
                              size="small" 
                              color={finding.severity === 'CRITICAL' ? 'error' : 
                                     finding.severity === 'HIGH' ? 'warning' : 
                                     finding.severity === 'MEDIUM' ? 'info' : 'success'}
                              sx={{ mt: 0.5 }}
                            />
                          </Box>
                        }
                      />
                    </ListItem>
                    {index < dashboardData.findings.length - 1 && <Divider />}
                  </React.Fragment>
                ))}
              </List>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Integration Status */}
      <Grid container spacing={3}>
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Integration Status
              </Typography>
              <Grid container spacing={2}>
                {dashboardData.integrations.map((integration) => (
                  <Grid item xs={12} sm={6} md={4} lg={3} key={integration.id}>
                    <IntegrationCard integration={integration} compact={true} />
                  </Grid>
                ))}
              </Grid>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Settings Dialog */}
      <Dialog open={settingsOpen} onClose={() => setSettingsOpen(false)}>
        <DialogTitle>Dashboard Settings</DialogTitle>
        <DialogContent>
          <Box sx={{ p: 1 }}>
            <Typography variant="subtitle1" gutterBottom>
              Auto Refresh
            </Typography>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
              <Button
                variant={autoRefresh ? 'contained' : 'outlined'}
                onClick={() => setAutoRefresh(!autoRefresh)}
              >
                {autoRefresh ? 'Enabled' : 'Disabled'}
              </Button>
            </Box>
            
            {autoRefresh && (
              <Box>
                <Typography variant="subtitle2" gutterBottom>
                  Refresh Interval
                </Typography>
                <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                  {[15000, 30000, 60000, 300000].map((interval) => (
                    <Button
                      key={interval}
                      variant={refreshInterval === interval ? 'contained' : 'outlined'}
                      size="small"
                      onClick={() => setRefreshInterval(interval)}
                    >
                      {interval < 60000 ? `${interval / 1000}s` : `${interval / 60000}m`}
                    </Button>
                  ))}
                </Box>
              </Box>
            )}
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setSettingsOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* Floating Refresh Button (Mobile) */}
      {isMobile && (
        <Fab
          color="primary"
          sx={{ position: 'fixed', bottom: 16, right: 16 }}
          onClick={handleRefresh}
          disabled={refreshing}
        >
          {refreshing ? <CircularProgress size={24} color="inherit" /> : <RefreshIcon />}
        </Fab>
      )}
    </Box>
  );
};

export default Dashboard;
