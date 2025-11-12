import React, { useState, useEffect } from 'react';
import {
  Box,
  Container,
  Grid,
  Card,
  CardContent,
  Typography,
  Avatar,
  Button,
  Tabs,
  Tab,
  LinearProgress,
  Chip,
  Alert,
  Divider,
} from '@mui/material';
import {
  Person as PersonIcon,
  Security as SecurityIcon,
  Notifications as NotificationsIcon,
  Business as BusinessIcon,
  Edit as EditIcon,
  CheckCircle as CheckCircleIcon,
  Warning as WarningIcon,
} from '@mui/icons-material';
import { useSelector, useDispatch } from 'react-redux';
import { toast } from 'react-hot-toast';

import { selectUser, fetchProfile, updateProfile } from '@/store/slices/authSlice';
import { selectDashboard } from '@/store/slices/dashboardSlice';
import { ProfileForm } from '@/components/forms/ProfileForm';
import { SecuritySettings } from '@/components/security/SecuritySettings';
import { NotificationSettings } from '@/components/notifications/NotificationSettings';
import { BillingSection } from '@/components/billing/BillingSection';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`profile-tabpanel-${index}`}
      aria-labelledby={`profile-tab-${index}`}
      {...other}
    >
      {value === index && (
        <Box sx={{ pt: 3 }}>
          {children}
        </Box>
      )}
    </div>
  );
}

function a11yProps(index: number) {
  return {
    id: `profile-tab-${index}`,
    'aria-controls': `profile-tabpanel-${index}`,
  };
}

export default function Profile() {
  const [activeTab, setActiveTab] = useState(0);
  const [isEditing, setIsEditing] = useState(false);
  
  const dispatch = useDispatch();
  const user = useSelector(selectUser);
  const dashboard = useSelector(selectDashboard);
  
  const isLoading = user?.loading || false;

  useEffect(() => {
    if (user?.id) {
      dispatch(fetchProfile(user.id));
    }
  }, [dispatch, user?.id]);

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setActiveTab(newValue);
  };

  const handleProfileUpdate = async (data: any) => {
    try {
      await dispatch(updateProfile(data)).unwrap();
      setIsEditing(false);
      toast.success('Profile updated successfully!');
    } catch (error: any) {
      toast.error(error.message || 'Failed to update profile');
    }
  };

  const getSecurityScore = () => {
    if (!user) return 0;
    
    let score = 0;
    if (user.email) score += 20;
    if (user.mfa_enabled) score += 30;
    if (user.profile?.two_factor_enabled) score += 25;
    if (user.profile?.backup_codes_generated) score += 15;
    if (user.last_login && new Date(user.last_login) > new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)) score += 10;
    
    return Math.min(score, 100);
  };

  const securityScore = getSecurityScore();

  if (isLoading && !user) {
    return (
      <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
        <Box sx={{ width: '100%' }}>
          <LinearProgress />
        </Box>
      </Container>
    );
  }

  return (
    <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
      {/* Profile Header */}
      <Card sx={{ mb: 4 }}>
        <CardContent sx={{ p: 4 }}>
          <Grid container spacing={3} alignItems="center">
            <Grid item>
              <Avatar
                sx={{
                  width: 120,
                  height: 120,
                  bgcolor: 'primary.main',
                  fontSize: '3rem',
                }}
              >
                {user?.name ? user.name.charAt(0).toUpperCase() : user?.email?.charAt(0).toUpperCase() || 'U'}
              </Avatar>
            </Grid>
            <Grid item xs>
              <Box sx={{ mb: 2 }}>
                <Typography variant="h4" component="h1" gutterBottom>
                  {user?.name || 'Unnamed User'}
                </Typography>
                <Typography variant="body1" color="text.secondary" gutterBottom>
                  {user?.email}
                </Typography>
                <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mt: 1 }}>
                  <Chip
                    label={user?.role || 'User'}
                    color="primary"
                    size="small"
                  />
                  {user?.mfa_enabled && (
                    <Chip
                      label="MFA Enabled"
                      color="success"
                      size="small"
                      icon={<CheckCircleIcon />}
                    />
                  )}
                  <Chip
                    label={`Security Score: ${securityScore}%`}
                    color={securityScore >= 80 ? 'success' : securityScore >= 60 ? 'warning' : 'error'}
                    size="small"
                  />
                </Box>
              </Box>
              <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
                <Typography variant="body2" color="text.secondary">
                  <strong>Last Login:</strong> {user?.last_login ? new Date(user.last_login).toLocaleString() : 'Never'}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  <strong>Member Since:</strong> {user?.created_at ? new Date(user.created_at).toLocaleDateString() : 'Unknown'}
                </Typography>
              </Box>
            </Grid>
            <Grid item>
              <Button
                variant="outlined"
                startIcon={<EditIcon />}
                onClick={() => setIsEditing(true)}
              >
                Edit Profile
              </Button>
            </Grid>
          </Grid>

          {/* Quick Stats */}
          <Divider sx={{ my: 3 }} />
          <Grid container spacing={3}>
            <Grid item xs={12} sm={6} md={3}>
              <Box sx={{ textAlign: 'center' }}>
                <Typography variant="h3" color="primary">
                  {dashboard?.stats?.total_integrations || 0}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Active Integrations
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Box sx={{ textAlign: 'center' }}>
                <Typography variant="h3" color="warning.main">
                  {dashboard?.stats?.total_findings || 0}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Total Findings
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Box sx={{ textAlign: 'center' }}>
                <Typography variant="h3" color="error.main">
                  {dashboard?.stats?.critical_alerts || 0}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Critical Alerts
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Box sx={{ textAlign: 'center' }}>
                <LinearProgress
                  variant="determinate"
                  value={securityScore}
                  sx={{ height: 8, borderRadius: 4, mb: 1 }}
                  color={securityScore >= 80 ? 'success' : securityScore >= 60 ? 'warning' : 'error'}
                />
                <Typography variant="body2" color="text.secondary">
                  Security Score
                </Typography>
              </Box>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Security Alerts */}
      {securityScore < 60 && (
        <Alert 
          severity="warning" 
          sx={{ mb: 3 }}
          action={
            <Button 
              color="inherit" 
              size="small"
              onClick={() => setActiveTab(1)}
            >
              Improve Security
            </Button>
          }
        >
          Your security score is below recommended levels. Consider enabling two-factor authentication and reviewing your security settings.
        </Alert>
      )}

      {/* Profile Tabs */}
      <Card>
        <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tabs 
            value={activeTab} 
            onChange={handleTabChange} 
            aria-label="profile tabs"
            variant="scrollable"
            scrollButtons="auto"
          >
            <Tab 
              icon={<PersonIcon />} 
              label="General" 
              {...a11yProps(0)} 
            />
            <Tab 
              icon={<SecurityIcon />} 
              label="Security" 
              {...a11yProps(1)} 
            />
            <Tab 
              icon={<NotificationsIcon />} 
              label="Notifications" 
              {...a11yProps(2)} 
            />
            <Tab 
              icon={<BusinessIcon />} 
              label="Billing" 
              {...a11yProps(3)} 
            />
          </Tabs>
        </Box>

        <TabPanel value={activeTab} index={0}>
          <ProfileForm
            user={user}
            isEditing={isEditing}
            onSave={handleProfileUpdate}
            onCancel={() => setIsEditing(false)}
          />
        </TabPanel>

        <TabPanel value={activeTab} index={1}>
          <SecuritySettings user={user} />
        </TabPanel>

        <TabPanel value={activeTab} index={2}>
          <NotificationSettings user={user} />
        </TabPanel>

        <TabPanel value={activeTab} index={3}>
          <BillingSection user={user} />
        </TabPanel>
      </Card>
    </Container>
  );
}