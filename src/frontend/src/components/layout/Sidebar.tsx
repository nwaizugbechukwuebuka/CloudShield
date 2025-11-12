import React from 'react';
import {
  Drawer,
  List,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Box,
  Typography,
  Divider,
  Collapse,
  Badge,
  Tooltip,
  useTheme,
} from '@mui/material';
import {
  Dashboard as DashboardIcon,
  Security as SecurityIcon,
  IntegrationInstructions as IntegrationsIcon,
  FindInPage as FindingsIcon,
  Notifications as AlertsIcon,
  Settings as SettingsIcon,
  Person as UsersIcon,
  AccountCircle as ProfileIcon,
  ExpandLess,
  ExpandMore,
  Analytics as AnalyticsIcon,
  Report as ReportsIcon,
  Help as HelpIcon,
  Policy as ComplianceIcon,
} from '@mui/icons-material';
import { useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useSelector } from 'react-redux';

import { selectUser } from '@/store/slices/authSlice';
import { selectDashboard } from '@/store/slices/dashboardSlice';
import { selectNotifications } from '@/store/slices/notificationSlice';

interface SidebarProps {
  variant?: 'permanent' | 'persistent' | 'temporary';
  open?: boolean;
  width?: number;
  collapsed?: boolean;
}

const navigationItems = [
  {
    id: 'dashboard',
    label: 'Dashboard',
    icon: DashboardIcon,
    path: '/',
  },
  {
    id: 'security',
    label: 'Security',
    icon: SecurityIcon,
    children: [
      {
        id: 'findings',
        label: 'Findings',
        icon: FindingsIcon,
        path: '/findings',
      },
      {
        id: 'alerts',
        label: 'Alerts',
        icon: AlertsIcon,
        path: '/alerts',
        badge: 'unreadAlertsCount',
      },
      {
        id: 'compliance',
        label: 'Compliance',
        icon: ComplianceIcon,
        path: '/compliance',
      },
    ],
  },
  {
    id: 'integrations',
    label: 'Integrations',
    icon: IntegrationsIcon,
    path: '/integrations',
  },
  {
    id: 'analytics',
    label: 'Analytics',
    icon: AnalyticsIcon,
    children: [
      {
        id: 'reports',
        label: 'Reports',
        icon: ReportsIcon,
        path: '/reports',
      },
    ],
  },
];

const bottomNavItems = [
  {
    id: 'users',
    label: 'Users',
    icon: UsersIcon,
    path: '/users',
    adminOnly: true,
  },
  {
    id: 'settings',
    label: 'Settings',
    icon: SettingsIcon,
    path: '/settings',
  },
  {
    id: 'profile',
    label: 'Profile',
    icon: ProfileIcon,
    path: '/profile',
  },
  {
    id: 'help',
    label: 'Help & Support',
    icon: HelpIcon,
    path: '/help',
  },
];

export function Sidebar({ variant = 'permanent', open = true, width = 280, collapsed = false }: SidebarProps) {
  const theme = useTheme();
  const location = useLocation();
  const navigate = useNavigate();
  
  const user = useSelector(selectUser);
  const dashboard = useSelector(selectDashboard);
  const notifications = useSelector(selectNotifications);
  
  const [expandedSections, setExpandedSections] = useState<string[]>(['security']);

  const handleSectionToggle = (sectionId: string) => {
    setExpandedSections(prev => 
      prev.includes(sectionId) 
        ? prev.filter(id => id !== sectionId)
        : [...prev, sectionId]
    );
  };

  const handleNavigate = (path: string) => {
    navigate(path);
  };

  const getBadgeCount = (badgeKey: string) => {
    switch (badgeKey) {
      case 'unreadAlertsCount':
        return notifications?.unreadCount || 0;
      default:
        return 0;
    }
  };

  const isActive = (path: string) => {
    if (path === '/') {
      return location.pathname === '/';
    }
    return location.pathname.startsWith(path);
  };

  const isUserAuthorized = (item: any) => {
    if (item.adminOnly && user?.role !== 'admin') {
      return false;
    }
    return true;
  };

  const renderNavItem = (item: any, level = 0) => {
    if (!isUserAuthorized(item)) {
      return null;
    }

    const hasChildren = item.children && item.children.length > 0;
    const isExpanded = expandedSections.includes(item.id);
    const active = item.path ? isActive(item.path) : false;
    const badgeCount = item.badge ? getBadgeCount(item.badge) : 0;

    if (hasChildren) {
      return (
        <React.Fragment key={item.id}>
          <ListItem disablePadding sx={{ display: 'block' }}>
            <ListItemButton
              onClick={() => handleSectionToggle(item.id)}
              sx={{
                minHeight: 48,
                justifyContent: collapsed ? 'center' : 'initial',
                px: 2.5,
                pl: level > 0 ? 4 + level * 2 : 2.5,
              }}
            >
              <ListItemIcon
                sx={{
                  minWidth: 0,
                  mr: collapsed ? 0 : 3,
                  justifyContent: 'center',
                }}
              >
                <item.icon />
              </ListItemIcon>
              {!collapsed && (
                <>
                  <ListItemText 
                    primary={item.label}
                    sx={{ opacity: 1 }}
                  />
                  {isExpanded ? <ExpandLess /> : <ExpandMore />}
                </>
              )}
            </ListItemButton>
          </ListItem>
          
          {!collapsed && (
            <Collapse in={isExpanded} timeout="auto" unmountOnExit>
              <List component="div" disablePadding>
                {item.children.map((child: any) => renderNavItem(child, level + 1))}
              </List>
            </Collapse>
          )}
        </React.Fragment>
      );
    }

    const listItemContent = (
      <ListItemButton
        onClick={() => item.path && handleNavigate(item.path)}
        selected={active}
        sx={{
          minHeight: 48,
          justifyContent: collapsed ? 'center' : 'initial',
          px: 2.5,
          pl: level > 0 ? 4 + level * 2 : 2.5,
          '&.Mui-selected': {
            backgroundColor: theme.palette.primary.main,
            color: theme.palette.primary.contrastText,
            '&:hover': {
              backgroundColor: theme.palette.primary.dark,
            },
            '& .MuiListItemIcon-root': {
              color: theme.palette.primary.contrastText,
            },
          },
        }}
      >
        <ListItemIcon
          sx={{
            minWidth: 0,
            mr: collapsed ? 0 : 3,
            justifyContent: 'center',
            color: active ? 'inherit' : 'inherit',
          }}
        >
          {badgeCount > 0 && !collapsed ? (
            <Badge badgeContent={badgeCount} color="error">
              <item.icon />
            </Badge>
          ) : (
            <item.icon />
          )}
        </ListItemIcon>
        {!collapsed && (
          <ListItemText 
            primary={item.label}
            sx={{ opacity: 1 }}
          />
        )}
        {!collapsed && badgeCount > 0 && (
          <Badge badgeContent={badgeCount} color="error" />
        )}
      </ListItemButton>
    );

    return (
      <ListItem key={item.id} disablePadding sx={{ display: 'block' }}>
        {collapsed ? (
          <Tooltip title={item.label} placement="right">
            {listItemContent}
          </Tooltip>
        ) : (
          listItemContent
        )}
      </ListItem>
    );
  };

  const drawerContent = (
    <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      {/* Header */}
      {!collapsed && (
        <Box sx={{ p: 2, borderBottom: 1, borderColor: 'divider' }}>
          <Typography variant="h6" noWrap component="div" color="primary.main" fontWeight="bold">
            CloudShield
          </Typography>
          <Typography variant="caption" color="text.secondary">
            Security Platform
          </Typography>
        </Box>
      )}

      {/* Main Navigation */}
      <Box sx={{ flexGrow: 1, overflow: 'auto' }}>
        <List>
          {navigationItems.map((item) => renderNavItem(item))}
        </List>
      </Box>

      {/* Bottom Navigation */}
      <Box>
        <Divider />
        <List>
          {bottomNavItems.map((item) => renderNavItem(item))}
        </List>
      </Box>

      {/* User Info */}
      {!collapsed && (
        <Box sx={{ p: 2, borderTop: 1, borderColor: 'divider' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Box 
              sx={{ 
                width: 8, 
                height: 8, 
                borderRadius: '50%', 
                backgroundColor: 'success.main',
              }} 
            />
            <Typography variant="caption" color="text.secondary">
              {dashboard?.stats?.total_integrations || 0} integrations active
            </Typography>
          </Box>
          <Typography variant="caption" color="text.secondary" display="block">
            Last scan: {dashboard?.lastScanTime ? new Date(dashboard.lastScanTime).toLocaleTimeString() : 'Never'}
          </Typography>
        </Box>
      )}
    </Box>
  );

  return (
    <Drawer
      variant={variant}
      open={open}
      sx={{
        width: width,
        flexShrink: 0,
        '& .MuiDrawer-paper': {
          width: width,
          boxSizing: 'border-box',
          transition: theme.transitions.create('width', {
            easing: theme.transitions.easing.sharp,
            duration: theme.transitions.duration.enteringScreen,
          }),
        },
      }}
    >
      {drawerContent}
    </Drawer>
  );
}