import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import { DashboardStats, SecurityMetrics, ComplianceStatus } from '@/types';
import { apiService } from '@/services/api';

interface DashboardState {
  stats: DashboardStats | null;
  securityMetrics: SecurityMetrics | null;
  complianceStatus: ComplianceStatus | null;
  loading: boolean;
  error: string | null;
  lastUpdated: string | null;
}

const initialState: DashboardState = {
  stats: null,
  securityMetrics: null,
  complianceStatus: null,
  loading: false,
  error: null,
  lastUpdated: null,
};

// Async thunks
export const fetchDashboardStatsAsync = createAsyncThunk(
  'dashboard/fetchStats',
  async (_, { rejectWithValue }) => {
    try {
      const response = await apiService.get<DashboardStats>('/dashboard/stats');
      return response;
    } catch (error: any) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to fetch dashboard stats');
    }
  }
);

export const fetchSecurityMetricsAsync = createAsyncThunk(
  'dashboard/fetchSecurityMetrics',
  async (params: { timeframe?: '24h' | '7d' | '30d' | '90d' } = {}, { rejectWithValue }: any) => {
    try {
      const response = await apiService.get<SecurityMetrics>('/dashboard/security-metrics', { params });
      return response;
    } catch (error: any) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to fetch security metrics');
    }
  }
);

export const fetchComplianceStatusAsync = createAsyncThunk(
  'dashboard/fetchComplianceStatus',
  async (_, { rejectWithValue }) => {
    try {
      const response = await apiService.get<ComplianceStatus>('/dashboard/compliance');
      return response;
    } catch (error: any) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to fetch compliance status');
    }
  }
);

export const refreshDashboardAsync = createAsyncThunk(
  'dashboard/refresh',
  async (_, { dispatch, rejectWithValue }) => {
    try {
      await Promise.all([
        dispatch(fetchDashboardStatsAsync()),
        dispatch(fetchSecurityMetricsAsync()),
        dispatch(fetchComplianceStatusAsync()),
      ]);
    } catch (error: any) {
      return rejectWithValue('Failed to refresh dashboard data');
    }
  }
);

const dashboardSlice = createSlice({
  name: 'dashboard',
  initialState,
  reducers: {
    clearError: (state) => {
      state.error = null;
    },
    
    setLastUpdated: (state) => {
      state.lastUpdated = new Date().toISOString();
    },
  },
  extraReducers: (builder) => {
    builder
      // Fetch dashboard stats
      .addCase(fetchDashboardStatsAsync.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchDashboardStatsAsync.fulfilled, (state, action) => {
        state.loading = false;
        state.stats = action.payload;
        state.lastUpdated = new Date().toISOString();
      })
      .addCase(fetchDashboardStatsAsync.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload as string;
      })
      
      // Fetch security metrics
      .addCase(fetchSecurityMetricsAsync.fulfilled, (state, action) => {
        state.securityMetrics = action.payload;
        state.lastUpdated = new Date().toISOString();
      })
      
      // Fetch compliance status
      .addCase(fetchComplianceStatusAsync.fulfilled, (state, action) => {
        state.complianceStatus = action.payload;
        state.lastUpdated = new Date().toISOString();
      })
      
      // Refresh dashboard
      .addCase(refreshDashboardAsync.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(refreshDashboardAsync.fulfilled, (state) => {
        state.loading = false;
        state.lastUpdated = new Date().toISOString();
      })
      .addCase(refreshDashboardAsync.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload as string;
      });
  },
});

export const { clearError, setLastUpdated } = dashboardSlice.actions;

export default dashboardSlice.reducer;