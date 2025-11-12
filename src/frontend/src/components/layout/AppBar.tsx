import React from 'react';
import {
  AppBar as MuiAppBar,
  Toolbar,
  IconButton,
  Typography,
  Box,
  Badge,
  Avatar,
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText,
  Divider,
  Switch,
  FormControlLabel,
  Tooltip,
} from '@mui/material';
import {
  Menu as MenuIcon,
  Notifications as NotificationsIcon,
  AccountCircle as AccountIcon,
  Settings as SettingsIcon,
  Logout as LogoutIcon,
  DarkMode as DarkModeIcon,
  LightMode as LightModeIcon,
  Person as PersonIcon,
} from '@mui/icons-material';
import { useState } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { useNavigate } from 'react-router-dom';

import { selectUser, logout } from '@/store/slices/authSlice';
import { selectUI, toggleSidebar, toggleTheme } from '@/store/slices/uiSlice';
import { selectNotifications } from '@/store/slices/notificationSlice';

interface AppBarProps {
  position?: 'fixed' | 'absolute' | 'relative' | 'static' | 'sticky';
  drawerWidth?: number;
  sx?: any;
}

export function AppBar({ position = 'fixed', drawerWidth = 0, sx = {} }: AppBarProps) {
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [notificationsAnchorEl, setNotificationsAnchorEl] = useState<null | HTMLElement>(null);
  
  const dispatch = useDispatch();
  const navigate = useNavigate();
  
  const user = useSelector(selectUser);
  const { darkMode } = useSelector(selectUI);
  const { unreadCount } = useSelector(selectNotifications);
  
  const isMenuOpen = Boolean(anchorEl);
  const isNotificationsOpen = Boolean(notificationsAnchorEl);

  const handleProfileMenuOpen = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleNotificationsOpen = (event: React.MouseEvent<HTMLElement>) => {
    setNotificationsAnchorEl(event.currentTarget);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
    setNotificationsAnchorEl(null);
  };

  const handleProfile = () => {
    navigate('/profile');
    handleMenuClose();
  };

  const handleSettings = () => {
    navigate('/settings');
    handleMenuClose();
  };

  const handleLogout = () => {
    dispatch(logout());
    handleMenuClose();
  };

  const handleThemeToggle = () => {
    dispatch(toggleTheme());
  };

  const handleMenuToggle = () => {
    dispatch(toggleSidebar());
  };

  return (
    <>
      <MuiAppBar 
        position={position} 
        sx={{
          width: drawerWidth > 0 ? `calc(100% - ${drawerWidth}px)` : '100%',
          ml: drawerWidth > 0 ? `${drawerWidth}px` : 0,
          ...sx,
        }}
      >
        <Toolbar>
          {/* Menu Toggle */}
          <IconButton
            edge="start"
            color="inherit"
            aria-label="open drawer"
            onClick={handleMenuToggle}
            sx={{ mr: 2 }}
          >
            <MenuIcon />
          </IconButton>

          {/* App Title */}
          <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
            CloudShield
          </Typography>

          {/* Actions */}
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            {/* Theme Toggle */}
            <Tooltip title={`Switch to ${darkMode ? 'light' : 'dark'} mode`}>
              <IconButton color="inherit" onClick={handleThemeToggle}>
                {darkMode ? <LightModeIcon /> : <DarkModeIcon />}
              </IconButton>
            </Tooltip>

            {/* Notifications */}
            <Tooltip title="Notifications">
              <IconButton
                color="inherit"
                onClick={handleNotificationsOpen}
                aria-label={`show ${unreadCount} new notifications`}
              >
                <Badge badgeContent={unreadCount} color="error">
                  <NotificationsIcon />
                </Badge>
              </IconButton>
            </Tooltip>

            {/* Profile Menu */}
            <Tooltip title="Account">
              <IconButton
                edge="end"
                aria-label="account of current user"
                aria-controls="primary-search-account-menu"
                aria-haspopup="true"
                onClick={handleProfileMenuOpen}
                color="inherit"
              >
                {user?.avatar_url ? (
                  <Avatar 
                    src={user.avatar_url} 
                    sx={{ width: 32, height: 32 }}
                    alt={user.name || user.email}
                  />
                ) : (
                  <Avatar sx={{ width: 32, height: 32, bgcolor: 'primary.main' }}>
                    {user?.name ? user.name.charAt(0).toUpperCase() : user?.email?.charAt(0).toUpperCase() || 'U'}
                  </Avatar>
                )}
              </IconButton>
            </Tooltip>
          </Box>
        </Toolbar>
      </MuiAppBar>

      {/* Profile Menu */}
      <Menu
        anchorEl={anchorEl}
        anchorOrigin={{
          vertical: 'top',
          horizontal: 'right',
        }}
        id="primary-search-account-menu"
        keepMounted
        transformOrigin={{
          vertical: 'top',
          horizontal: 'right',
        }}
        open={isMenuOpen}
        onClose={handleMenuClose}
        PaperProps={{
          sx: { width: 280, maxWidth: '100%' }
        }}
      >
        {/* User Info */}
        <Box sx={{ px: 2, py: 1.5, borderBottom: 1, borderColor: 'divider' }}>
          <Typography variant="subtitle1" noWrap>
            {user?.name || 'User'}
          </Typography>
          <Typography variant="body2" color="text.secondary" noWrap>
            {user?.email}
          </Typography>
        </Box>

        {/* Theme Toggle in Menu */}
        <MenuItem>
          <FormControlLabel
            control={
              <Switch
                checked={darkMode}
                onChange={handleThemeToggle}
                size="small"
              />
            }
            label={
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                {darkMode ? <DarkModeIcon fontSize="small" /> : <LightModeIcon fontSize="small" />}
                Dark Mode
              </Box>
            }
            sx={{ m: 0 }}
          />
        </MenuItem>

        <Divider />

        {/* Menu Items */}
        <MenuItem onClick={handleProfile}>
          <ListItemIcon>
            <PersonIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Profile</ListItemText>
        </MenuItem>

        <MenuItem onClick={handleSettings}>
          <ListItemIcon>
            <SettingsIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Settings</ListItemText>
        </MenuItem>

        <Divider />

        <MenuItem onClick={handleLogout}>
          <ListItemIcon>
            <LogoutIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Logout</ListItemText>
        </MenuItem>
      </Menu>

      {/* Notifications Menu */}
      <Menu
        anchorEl={notificationsAnchorEl}
        anchorOrigin={{
          vertical: 'top',
          horizontal: 'right',
        }}
        transformOrigin={{
          vertical: 'top',
          horizontal: 'right',
        }}
        open={isNotificationsOpen}
        onClose={handleMenuClose}
        PaperProps={{
          sx: { width: 360, maxWidth: '100%', maxHeight: 400 }
        }}
      >
        <Box sx={{ px: 2, py: 1.5, borderBottom: 1, borderColor: 'divider' }}>
          <Typography variant="h6">
            Notifications
          </Typography>
        </Box>
        
        {unreadCount === 0 ? (
          <MenuItem disabled>
            <Typography variant="body2" color="text.secondary">
              No new notifications
            </Typography>
          </MenuItem>
        ) : (
          // TODO: Map through actual notifications
          <MenuItem>
            <Typography variant="body2">
              You have {unreadCount} new notifications
            </Typography>
          </MenuItem>
        )}
      </Menu>
    </>
  );
}