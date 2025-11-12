import { createSlice, PayloadAction } from '@reduxjs/toolkit';
import { ThemeSettings } from '@/types';

interface UIState {
  theme: ThemeSettings;
  sidebarOpen: boolean;
  sidebarCollapsed: boolean;
  loading: boolean;
  pageTitle: string;
  breadcrumbs: Array<{ label: string; path?: string }>;
  mobileMenuOpen: boolean;
  searchQuery: string;
  tablePageSize: number;
  tableFilters: Record<string, any>;
}

const initialState: UIState = {
  theme: {
    mode: 'light',
    primaryColor: '#1976d2',
    fontSize: 'medium',
    density: 'comfortable',
  },
  sidebarOpen: true,
  sidebarCollapsed: false,
  loading: false,
  pageTitle: 'Dashboard',
  breadcrumbs: [{ label: 'Dashboard', path: '/' }],
  mobileMenuOpen: false,
  searchQuery: '',
  tablePageSize: 25,
  tableFilters: {},
};

const uiSlice = createSlice({
  name: 'ui',
  initialState,
  reducers: {
    // Theme management
    setThemeMode: (state: UIState, action: PayloadAction<'light' | 'dark'>) => {
      state.theme.mode = action.payload;
    },
    
    setThemeSettings: (state: UIState, action: PayloadAction<Partial<ThemeSettings>>) => {
      state.theme = { ...state.theme, ...action.payload };
    },
    
    // Sidebar management
    toggleSidebar: (state: UIState) => {
      state.sidebarOpen = !state.sidebarOpen;
    },
    
    setSidebarOpen: (state: UIState, action: PayloadAction<boolean>) => {
      state.sidebarOpen = action.payload;
    },
    
    toggleSidebarCollapsed: (state) => {
      state.sidebarCollapsed = !state.sidebarCollapsed;
    },
    
    setSidebarCollapsed: (state, action: PayloadAction<boolean>) => {
      state.sidebarCollapsed = action.payload;
    },
    
    // Mobile menu
    setMobileMenuOpen: (state, action: PayloadAction<boolean>) => {
      state.mobileMenuOpen = action.payload;
    },
    
    toggleMobileMenu: (state) => {
      state.mobileMenuOpen = !state.mobileMenuOpen;
    },
    
    // Loading state
    setLoading: (state, action: PayloadAction<boolean>) => {
      state.loading = action.payload;
    },
    
    // Page navigation
    setPageTitle: (state, action: PayloadAction<string>) => {
      state.pageTitle = action.payload;
    },
    
    setBreadcrumbs: (state, action: PayloadAction<Array<{ label: string; path?: string }>>) => {
      state.breadcrumbs = action.payload;
    },
    
    // Search
    setSearchQuery: (state, action: PayloadAction<string>) => {
      state.searchQuery = action.payload;
    },
    
    // Table preferences
    setTablePageSize: (state, action: PayloadAction<number>) => {
      state.tablePageSize = action.payload;
    },
    
    setTableFilters: (state, action: PayloadAction<Record<string, any>>) => {
      state.tableFilters = action.payload;
    },
    
    updateTableFilter: (state, action: PayloadAction<{ key: string; value: any }>) => {
      state.tableFilters[action.payload.key] = action.payload.value;
    },
    
    clearTableFilters: (state) => {
      state.tableFilters = {};
    },
  },
});

export const {
  setThemeMode,
  setThemeSettings,
  toggleSidebar,
  setSidebarOpen,
  toggleSidebarCollapsed,
  setSidebarCollapsed,
  setMobileMenuOpen,
  toggleMobileMenu,
  setLoading,
  setPageTitle,
  setBreadcrumbs,
  setSearchQuery,
  setTablePageSize,
  setTableFilters,
  updateTableFilter,
  clearTableFilters,
} = uiSlice.actions;

export default uiSlice.reducer;