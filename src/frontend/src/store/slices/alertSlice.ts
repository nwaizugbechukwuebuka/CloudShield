import { createSlice, createAsyncThunk, PayloadAction } from '@reduxjs/toolkit';
import { Alert, AlertType, Severity, ListResponse } from '@/types';
import { apiService } from '@/services/api';

interface AlertsState {
  alerts: Alert[];
  selectedAlert: Alert | null;
  loading: boolean;
  error: string | null;
  pagination: {
    total: number;
    page: number;
    size: number;
    pages: number;
  };
  filters: {
    type?: AlertType;
    severity?: Severity;
    is_read?: boolean;
    search?: string;
    date_from?: string;
    date_to?: string;
  };
  unreadCount: number;
}

const initialState: AlertsState = {
  alerts: [],
  selectedAlert: null,
  loading: false,
  error: null,
  pagination: {
    total: 0,
    page: 1,
    size: 25,
    pages: 0,
  },
  filters: {},
  unreadCount: 0,
};

// Async thunks
export const fetchAlertsAsync = createAsyncThunk(
  'alerts/fetchAlerts',
  async (params: AlertsState['filters'] & { page?: number; size?: number }, { rejectWithValue }) => {
    try {
      const response = await apiService.get<ListResponse<Alert>>('/alerts', { params });
      return response;
    } catch (error: any) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to fetch alerts');
    }
  }
);

export const fetchUnreadCountAsync = createAsyncThunk(
  'alerts/fetchUnreadCount',
  async (_, { rejectWithValue }) => {
    try {
      const response = await apiService.get<{ unread_count: number }>('/alerts/unread-count');
      return response.unread_count;
    } catch (error: any) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to fetch unread count');
    }
  }
);

export const markAlertReadAsync = createAsyncThunk(
  'alerts/markAlertRead',
  async (id: number, { rejectWithValue }) => {
    try {
      const response = await apiService.patch<Alert>(`/alerts/${id}/read`);
      return response;
    } catch (error: any) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to mark alert as read');
    }
  }
);

export const markAllAlertsReadAsync = createAsyncThunk(
  'alerts/markAllAlertsRead',
  async (_, { rejectWithValue }) => {
    try {
      await apiService.patch('/alerts/mark-all-read');
    } catch (error: any) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to mark all alerts as read');
    }
  }
);

export const deleteAlertAsync = createAsyncThunk(
  'alerts/deleteAlert',
  async (id: number, { rejectWithValue }) => {
    try {
      await apiService.delete(`/alerts/${id}`);
      return id;
    } catch (error: any) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to delete alert');
    }
  }
);

export const bulkDeleteAlertsAsync = createAsyncThunk(
  'alerts/bulkDeleteAlerts',
  async (ids: number[], { rejectWithValue }) => {
    try {
      await apiService.delete('/alerts/bulk', { data: { ids } });
      return ids;
    } catch (error: any) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to delete alerts');
    }
  }
);

const alertsSlice = createSlice({
  name: 'alerts',
  initialState,
  reducers: {
    clearError: (state) => {
      state.error = null;
    },
    
    setSelectedAlert: (state, action: PayloadAction<Alert | null>) => {
      state.selectedAlert = action.payload;
    },
    
    setFilters: (state, action: PayloadAction<Partial<AlertsState['filters']>>) => {
      state.filters = { ...state.filters, ...action.payload };
    },
    
    clearFilters: (state) => {
      state.filters = {};
    },
    
    setPagination: (state, action: PayloadAction<Partial<AlertsState['pagination']>>) => {
      state.pagination = { ...state.pagination, ...action.payload };
    },
    
    // Real-time alert updates
    addAlert: (state, action: PayloadAction<Alert>) => {
      state.alerts.unshift(action.payload);
      if (!action.payload.is_read) {
        state.unreadCount += 1;
      }
    },
    
    updateAlert: (state, action: PayloadAction<Alert>) => {
      const index = state.alerts.findIndex(alert => alert.id === action.payload.id);
      if (index !== -1) {
        const wasUnread = !state.alerts[index].is_read;
        const isUnread = !action.payload.is_read;
        
        state.alerts[index] = action.payload;
        
        // Update unread count
        if (wasUnread && !isUnread) {
          state.unreadCount = Math.max(0, state.unreadCount - 1);
        } else if (!wasUnread && isUnread) {
          state.unreadCount += 1;
        }
      }
      
      if (state.selectedAlert?.id === action.payload.id) {
        state.selectedAlert = action.payload;
      }
    },
  },
  extraReducers: (builder) => {
    builder
      // Fetch alerts
      .addCase(fetchAlertsAsync.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchAlertsAsync.fulfilled, (state, action) => {
        state.loading = false;
        state.alerts = action.payload.data.items;
        state.pagination = {
          total: action.payload.data.total,
          page: action.payload.data.page,
          size: action.payload.data.size,
          pages: action.payload.data.pages,
        };
      })
      .addCase(fetchAlertsAsync.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload as string;
      })
      
      // Fetch unread count
      .addCase(fetchUnreadCountAsync.fulfilled, (state, action) => {
        state.unreadCount = action.payload;
      })
      
      // Mark alert as read
      .addCase(markAlertReadAsync.fulfilled, (state, action) => {
        const index = state.alerts.findIndex(alert => alert.id === action.payload.id);
        if (index !== -1) {
          const wasUnread = !state.alerts[index].is_read;
          state.alerts[index] = action.payload;
          
          if (wasUnread && action.payload.is_read) {
            state.unreadCount = Math.max(0, state.unreadCount - 1);
          }
        }
        
        if (state.selectedAlert?.id === action.payload.id) {
          state.selectedAlert = action.payload;
        }
      })
      
      // Mark all alerts as read
      .addCase(markAllAlertsReadAsync.fulfilled, (state) => {
        state.alerts = state.alerts.map(alert => ({ ...alert, is_read: true }));
        state.unreadCount = 0;
      })
      
      // Delete alert
      .addCase(deleteAlertAsync.fulfilled, (state, action) => {
        const deletedAlert = state.alerts.find(alert => alert.id === action.payload);
        state.alerts = state.alerts.filter(alert => alert.id !== action.payload);
        
        if (deletedAlert && !deletedAlert.is_read) {
          state.unreadCount = Math.max(0, state.unreadCount - 1);
        }
        
        if (state.selectedAlert?.id === action.payload) {
          state.selectedAlert = null;
        }
      })
      
      // Bulk delete alerts
      .addCase(bulkDeleteAlertsAsync.fulfilled, (state, action) => {
        const deletedUnreadCount = state.alerts
          .filter(alert => action.payload.includes(alert.id) && !alert.is_read)
          .length;
        
        state.alerts = state.alerts.filter(alert => !action.payload.includes(alert.id));
        state.unreadCount = Math.max(0, state.unreadCount - deletedUnreadCount);
      });
  },
});

export const {
  clearError,
  setSelectedAlert,
  setFilters,
  clearFilters,
  setPagination,
  addAlert,
  updateAlert,
} = alertsSlice.actions;

export default alertsSlice.reducer;