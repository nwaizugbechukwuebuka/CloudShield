import { createSlice, createAsyncThunk, PayloadAction } from '@reduxjs/toolkit';
import { Integration, Platform, SyncStatus, ListResponse } from '@/types';
import { apiService } from '@/services/api';

interface IntegrationsState {
  integrations: Integration[];
  selectedIntegration: Integration | null;
  loading: boolean;
  error: string | null;
  pagination: {
    total: number;
    page: number;
    size: number;
    pages: number;
  };
  filters: {
    platform?: Platform;
    status?: SyncStatus;
    search?: string;
  };
}

const initialState: IntegrationsState = {
  integrations: [],
  selectedIntegration: null,
  loading: false,
  error: null,
  pagination: {
    total: 0,
    page: 1,
    size: 25,
    pages: 0,
  },
  filters: {},
};

// Async thunks
export const fetchIntegrationsAsync = createAsyncThunk(
  'integrations/fetchIntegrations',
  async (params: { page?: number; size?: number; platform?: Platform; status?: SyncStatus; search?: string }, { rejectWithValue }) => {
    try {
      const response = await apiService.get<ListResponse<Integration>>('/integrations', { params });
      return response;
    } catch (error: any) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to fetch integrations');
    }
  }
);

export const createIntegrationAsync = createAsyncThunk(
  'integrations/createIntegration',
  async (data: { platform: Platform; authorization_code: string }, { rejectWithValue }) => {
    try {
      const response = await apiService.post<Integration>('/integrations', data);
      return response;
    } catch (error: any) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to create integration');
    }
  }
);

export const deleteIntegrationAsync = createAsyncThunk(
  'integrations/deleteIntegration',
  async (id: number, { rejectWithValue }) => {
    try {
      await apiService.delete(`/integrations/${id}`);
      return id;
    } catch (error: any) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to delete integration');
    }
  }
);

export const syncIntegrationAsync = createAsyncThunk(
  'integrations/syncIntegration',
  async (id: number, { rejectWithValue }) => {
    try {
      const response = await apiService.post<Integration>(`/integrations/${id}/sync`);
      return response;
    } catch (error: any) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to sync integration');
    }
  }
);

export const fetchIntegrationAsync = createAsyncThunk(
  'integrations/fetchIntegration',
  async (id: number, { rejectWithValue }) => {
    try {
      const response = await apiService.get<Integration>(`/integrations/${id}`);
      return response;
    } catch (error: any) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to fetch integration');
    }
  }
);

const integrationsSlice = createSlice({
  name: 'integrations',
  initialState,
  reducers: {
    clearError: (state) => {
      state.error = null;
    },
    
    setSelectedIntegration: (state, action: PayloadAction<Integration | null>) => {
      state.selectedIntegration = action.payload;
    },
    
    setFilters: (state, action: PayloadAction<Partial<IntegrationsState['filters']>>) => {
      state.filters = { ...state.filters, ...action.payload };
    },
    
    clearFilters: (state) => {
      state.filters = {};
    },
    
    setPagination: (state, action: PayloadAction<Partial<IntegrationsState['pagination']>>) => {
      state.pagination = { ...state.pagination, ...action.payload };
    },
  },
  extraReducers: (builder) => {
    builder
      // Fetch integrations
      .addCase(fetchIntegrationsAsync.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchIntegrationsAsync.fulfilled, (state, action) => {
        state.loading = false;
        state.integrations = action.payload.data.items;
        state.pagination = {
          total: action.payload.data.total,
          page: action.payload.data.page,
          size: action.payload.data.size,
          pages: action.payload.data.pages,
        };
      })
      .addCase(fetchIntegrationsAsync.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload as string;
      })
      
      // Create integration
      .addCase(createIntegrationAsync.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(createIntegrationAsync.fulfilled, (state, action) => {
        state.loading = false;
        state.integrations.unshift(action.payload);
      })
      .addCase(createIntegrationAsync.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload as string;
      })
      
      // Delete integration
      .addCase(deleteIntegrationAsync.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(deleteIntegrationAsync.fulfilled, (state, action) => {
        state.loading = false;
        state.integrations = state.integrations.filter(integration => integration.id !== action.payload);
        if (state.selectedIntegration?.id === action.payload) {
          state.selectedIntegration = null;
        }
      })
      .addCase(deleteIntegrationAsync.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload as string;
      })
      
      // Sync integration
      .addCase(syncIntegrationAsync.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(syncIntegrationAsync.fulfilled, (state, action) => {
        state.loading = false;
        const index = state.integrations.findIndex(integration => integration.id === action.payload.id);
        if (index !== -1) {
          state.integrations[index] = action.payload;
        }
        if (state.selectedIntegration?.id === action.payload.id) {
          state.selectedIntegration = action.payload;
        }
      })
      .addCase(syncIntegrationAsync.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload as string;
      })
      
      // Fetch single integration
      .addCase(fetchIntegrationAsync.fulfilled, (state, action) => {
        state.selectedIntegration = action.payload;
      });
  },
});

export const {
  clearError,
  setSelectedIntegration,
  setFilters,
  clearFilters,
  setPagination,
} = integrationsSlice.actions;

export default integrationsSlice.reducer;