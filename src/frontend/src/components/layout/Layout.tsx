import React from 'react';
import { Outlet } from 'react-router-dom';
import { 
  Box,
  CssBaseline,
  useMediaQuery,
  useTheme,
} from '@mui/material';
import { useSelector } from 'react-redux';

import { AppBar } from '@/components/layout/AppBar';
import { Sidebar } from '@/components/layout/Sidebar';
import { selectUI } from '@/store/slices/uiSlice';

const DRAWER_WIDTH = 280;
const DRAWER_WIDTH_COLLAPSED = 64;

export default function Layout() {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('lg'));
  const { sidebarOpen, sidebarCollapsed } = useSelector(selectUI);
  
  const drawerWidth = sidebarCollapsed ? DRAWER_WIDTH_COLLAPSED : DRAWER_WIDTH;
  const shouldOpenDrawer = isMobile ? sidebarOpen : true;

  return (
    <Box sx={{ display: 'flex' }}>
      <CssBaseline />
      
      {/* App Bar */}
      <AppBar 
        position="fixed" 
        drawerWidth={isMobile ? 0 : drawerWidth}
        sx={{
          zIndex: theme.zIndex.drawer + 1,
          transition: theme.transitions.create(['width', 'margin'], {
            easing: theme.transitions.easing.sharp,
            duration: theme.transitions.duration.leavingScreen,
          }),
        }}
      />

      {/* Sidebar */}
      <Sidebar
        variant={isMobile ? 'temporary' : 'permanent'}
        open={shouldOpenDrawer}
        width={drawerWidth}
        collapsed={sidebarCollapsed}
      />

      {/* Main Content */}
      <Box
        component="main"
        sx={{
          flexGrow: 1,
          transition: theme.transitions.create('margin', {
            easing: theme.transitions.easing.sharp,
            duration: theme.transitions.duration.leavingScreen,
          }),
          marginLeft: isMobile ? 0 : `${drawerWidth}px`,
          minHeight: '100vh',
          backgroundColor: 'background.default',
        }}
      >
        {/* Toolbar spacer */}
        <Box sx={{ height: theme.mixins.toolbar.minHeight }} />
        
        {/* Page Content */}
        <Box sx={{ p: { xs: 2, sm: 3 } }}>
          <Outlet />
        </Box>
      </Box>
    </Box>
  );
}