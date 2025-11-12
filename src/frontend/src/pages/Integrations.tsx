import React, { useState, useEffect } from 'react';
import {
  Box,
  Container,
  Grid,
  Card,
  CardContent,
  CardHeader,
  Typography,
  Button,
  IconButton,
  Chip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Alert,
  Skeleton,
  Tooltip,
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText,
  Fab,
} from '@mui/material';
import {
  Add as AddIcon,
  MoreVert as MoreVertIcon,
  Refresh as RefreshIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Settings as SettingsIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  CloudSync as CloudSyncIcon,
  GitHub as GitHubIcon,
  Google as GoogleIcon,
  Microsoft as MicrosoftIcon,
} from '@mui/icons-material';
import { useSelector, useDispatch } from 'react-redux';
import { toast } from 'react-hot-toast';

import {
  selectIntegrations,
  fetchIntegrations,
  createIntegration,
  updateIntegration,
  deleteIntegration,
  testIntegrationConnection,
} from '@/store/slices/integrationSlice';
import { IntegrationForm } from '@/components/forms/IntegrationForm';
import { ConnectionTestDialog } from '@/components/integrations/ConnectionTestDialog';

const integrationIcons = {
  github: GitHubIcon,
  google_workspace: GoogleIcon,
  microsoft_365: MicrosoftIcon,
  slack: CloudSyncIcon,
  notion: CloudSyncIcon,
  default: CloudSyncIcon,
};

const getStatusColor = (status) => {
  switch (status) {
    case 'active':
      return 'success';
    case 'error':
      return 'error';
    case 'warning':
      return 'warning';
    default:
      return 'default';
  }
};

const getStatusIcon = (status) => {
  switch (status) {
    case 'active':
      return <CheckCircleIcon />;
    case 'error':
      return <ErrorIcon />;
    case 'warning':
      return <WarningIcon />;
    default:
      return <CloudSyncIcon />;
  }
};

export default function Integrations() {
  const [formOpen, setFormOpen] = useState(false);
  const [selectedIntegration, setSelectedIntegration] = useState(null);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [testDialogOpen, setTestDialogOpen] = useState(false);
  const [anchorEl, setAnchorEl] = useState(null);
  const [menuIntegration, setMenuIntegration] = useState(null);

  const dispatch = useDispatch();
  const { items: integrations, loading, error } = useSelector(selectIntegrations);

  useEffect(() => {
    dispatch(fetchIntegrations());
  }, [dispatch]);

  const handleAddIntegration = () => {
    setSelectedIntegration(null);
    setFormOpen(true);
  };

  const handleEditIntegration = (integration) => {
    setSelectedIntegration(integration);
    setFormOpen(true);
    handleMenuClose();
  };

  const handleDeleteClick = (integration) => {
    setSelectedIntegration(integration);
    setDeleteDialogOpen(true);
    handleMenuClose();
  };

  const handleTestConnection = (integration) => {
    setSelectedIntegration(integration);
    setTestDialogOpen(true);
    handleMenuClose();
  };

  const handleMenuClick = (event, integration) => {
    setAnchorEl(event.currentTarget);
    setMenuIntegration(integration);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
    setMenuIntegration(null);
  };

  const handleFormSubmit = async (formData) => {
    try {
      if (selectedIntegration) {
        await dispatch(updateIntegration({
          id: selectedIntegration.id,
          ...formData,
        })).unwrap();
        toast.success('Integration updated successfully!');
      } else {
        await dispatch(createIntegration(formData)).unwrap();
        toast.success('Integration added successfully!');
      }
      setFormOpen(false);
    } catch (error) {
      toast.error(error.message || 'Failed to save integration');
    }
  };

  const handleDeleteConfirm = async () => {
    try {
      await dispatch(deleteIntegration(selectedIntegration.id)).unwrap();
      toast.success('Integration deleted successfully!');
      setDeleteDialogOpen(false);
      setSelectedIntegration(null);
    } catch (error) {
      toast.error(error.message || 'Failed to delete integration');
    }
  };

  const handleRefresh = () => {
    dispatch(fetchIntegrations());
    toast.success('Integrations refreshed');
  };

  const renderIntegrationCard = (integration) => {
    const IconComponent = integrationIcons[integration.type] || integrationIcons.default;
    
    return (
      <Grid item xs={12} sm={6} md={4} key={integration.id}>
        <Card 
          sx={{ 
            height: '100%',
            display: 'flex',
            flexDirection: 'column',
            position: 'relative',
            '&:hover': {
              boxShadow: (theme) => theme.shadows[4],
              transform: 'translateY(-2px)',
            },
            transition: 'all 0.2s ease-in-out',
          }}
        >
          <CardHeader
            avatar={
              <IconComponent 
                sx={{ 
                  fontSize: 40,
                  color: integration.status === 'active' ? 'success.main' : 'text.secondary'
                }} 
              />
            }
            action={
              <IconButton
                onClick={(e) => handleMenuClick(e, integration)}
                size="small"
              >
                <MoreVertIcon />
              </IconButton>
            }
            title={
              <Typography variant="h6" component="div" noWrap>
                {integration.name}
              </Typography>
            }
            subheader={
              <Typography variant="body2" color="text.secondary" sx={{ textTransform: 'capitalize' }}>
                {integration.type.replace('_', ' ')}
              </Typography>
            }
            sx={{ pb: 1 }}
          />
          
          <CardContent sx={{ flexGrow: 1, pt: 0 }}>
            <Box sx={{ mb: 2 }}>
              <Chip
                icon={getStatusIcon(integration.status)}
                label={integration.status?.charAt(0).toUpperCase() + integration.status?.slice(1)}
                color={getStatusColor(integration.status)}
                size="small"
                sx={{ mb: 1 }}
              />
            </Box>
            
            <Typography variant="body2" color="text.secondary" paragraph>
              {integration.description || 'No description provided'}
            </Typography>
            
            <Box sx={{ mt: 'auto' }}>
              <Typography variant="caption" display="block" color="text.secondary">
                Last Sync: {integration.last_sync ? new Date(integration.last_sync).toLocaleString() : 'Never'}
              </Typography>
              <Typography variant="caption" display="block" color="text.secondary">
                Created: {new Date(integration.created_at).toLocaleDateString()}
              </Typography>
            </Box>
          </CardContent>
        </Card>
      </Grid>
    );
  };

  const renderSkeleton = () => (
    <Grid container spacing={3}>
      {[1, 2, 3, 4, 5, 6].map((item) => (
        <Grid item xs={12} sm={6} md={4} key={item}>
          <Card>
            <CardHeader
              avatar={<Skeleton variant="circular" width={40} height={40} />}
              title={<Skeleton variant="text" width="60%" />}
              subheader={<Skeleton variant="text" width="40%" />}
            />
            <CardContent>
              <Skeleton variant="rectangular" height={60} />
            </CardContent>
          </Card>
        </Grid>
      ))}
    </Grid>
  );

  if (error) {
    return (
      <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
        <Button variant="contained" onClick={handleRefresh}>
          Retry
        </Button>
      </Container>
    );
  }

  return (
    <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 4 }}>
        <Box>
          <Typography variant="h4" component="h1" gutterBottom>
            Integrations
          </Typography>
          <Typography variant="body1" color="text.secondary">
            Connect and manage your external services
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Tooltip title="Refresh">
            <IconButton onClick={handleRefresh} disabled={loading}>
              <RefreshIcon />
            </IconButton>
          </Tooltip>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={handleAddIntegration}
          >
            Add Integration
          </Button>
        </Box>
      </Box>

      {/* Stats */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent sx={{ textAlign: 'center' }}>
              <Typography variant="h3" color="primary">
                {integrations?.length || 0}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Total Integrations
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent sx={{ textAlign: 'center' }}>
              <Typography variant="h3" color="success.main">
                {integrations?.filter(i => i.status === 'active')?.length || 0}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Active
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent sx={{ textAlign: 'center' }}>
              <Typography variant="h3" color="warning.main">
                {integrations?.filter(i => i.status === 'warning')?.length || 0}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Warning
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent sx={{ textAlign: 'center' }}>
              <Typography variant="h3" color="error.main">
                {integrations?.filter(i => i.status === 'error')?.length || 0}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Error
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Integrations Grid */}
      {loading ? (
        renderSkeleton()
      ) : integrations?.length > 0 ? (
        <Grid container spacing={3}>
          {integrations.map(renderIntegrationCard)}
        </Grid>
      ) : (
        <Card sx={{ textAlign: 'center', py: 8 }}>
          <CardContent>
            <CloudSyncIcon sx={{ fontSize: 80, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h5" gutterBottom>
              No integrations yet
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              Connect your first service to start monitoring your cloud security
            </Typography>
            <Button
              variant="contained"
              startIcon={<AddIcon />}
              onClick={handleAddIntegration}
              size="large"
            >
              Add Your First Integration
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Floating Action Button for Mobile */}
      <Fab
        color="primary"
        aria-label="add integration"
        sx={{
          position: 'fixed',
          bottom: 16,
          right: 16,
          display: { xs: 'flex', sm: 'none' }
        }}
        onClick={handleAddIntegration}
      >
        <AddIcon />
      </Fab>

      {/* Context Menu */}
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleMenuClose}
        transformOrigin={{ horizontal: 'right', vertical: 'top' }}
        anchorOrigin={{ horizontal: 'right', vertical: 'bottom' }}
      >
        <MenuItem onClick={() => handleEditIntegration(menuIntegration)}>
          <ListItemIcon>
            <EditIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Edit</ListItemText>
        </MenuItem>
        <MenuItem onClick={() => handleTestConnection(menuIntegration)}>
          <ListItemIcon>
            <SettingsIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Test Connection</ListItemText>
        </MenuItem>
        <MenuItem onClick={() => handleDeleteClick(menuIntegration)} sx={{ color: 'error.main' }}>
          <ListItemIcon>
            <DeleteIcon fontSize="small" color="error" />
          </ListItemIcon>
          <ListItemText>Delete</ListItemText>
        </MenuItem>
      </Menu>

      {/* Integration Form Dialog */}
      <IntegrationForm
        open={formOpen}
        onClose={() => setFormOpen(false)}
        onSubmit={handleFormSubmit}
        integration={selectedIntegration}
        loading={loading}
      />

      {/* Delete Confirmation Dialog */}
      <Dialog
        open={deleteDialogOpen}
        onClose={() => setDeleteDialogOpen(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>
          Delete Integration
        </DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to delete the integration "{selectedIntegration?.name}"? 
            This action cannot be undone and will remove all associated scan data.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteDialogOpen(false)}>
            Cancel
          </Button>
          <Button
            onClick={handleDeleteConfirm}
            color="error"
            variant="contained"
            disabled={loading}
          >
            Delete
          </Button>
        </DialogActions>
      </Dialog>

      {/* Connection Test Dialog */}
      <ConnectionTestDialog
        open={testDialogOpen}
        onClose={() => setTestDialogOpen(false)}
        integration={selectedIntegration}
      />
    </Container>
  );

}
