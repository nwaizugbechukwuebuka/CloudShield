import { createSlice, createAsyncThunk, PayloadAction } from '@reduxjs/toolkit';
import { Finding, Severity, FindingStatus, Platform, ListResponse } from '@/types';
import { apiService } from '@/services/api';

interface FindingsState {
  findings: Finding[];
  selectedFinding: Finding | null;
  loading: boolean;
  error: string | null;
  pagination: {
    total: number;
    page: number;
    size: number;
    pages: number;
  };
  filters: {
    severity?: Severity;
    status?: FindingStatus;
    platform?: Platform;
    search?: string;
    date_from?: string;
    date_to?: string;
  };
  stats: {
    total: number;
    by_severity: Record<Severity, number>;
    by_status: Record<FindingStatus, number>;
    by_platform: Record<Platform, number>;
  };
}

const initialState: FindingsState = {
  findings: [],
  selectedFinding: null,
  loading: false,
  error: null,
  pagination: {
    total: 0,
    page: 1,
    size: 25,
    pages: 0,
  },
  filters: {},
  stats: {
    total: 0,
    by_severity: {
      [Severity.LOW]: 0,
      [Severity.MEDIUM]: 0,
      [Severity.HIGH]: 0,
      [Severity.CRITICAL]: 0,
    },
    by_status: {
      [FindingStatus.OPEN]: 0,
      [FindingStatus.IN_PROGRESS]: 0,
      [FindingStatus.RESOLVED]: 0,
      [FindingStatus.DISMISSED]: 0,
    },
    by_platform: {
      [Platform.GOOGLE_WORKSPACE]: 0,
      [Platform.MICROSOFT_365]: 0,
      [Platform.SLACK]: 0,
      [Platform.GITHUB]: 0,
      [Platform.NOTION]: 0,
    },
  },
};

// Async thunks
export const fetchFindingsAsync = createAsyncThunk(
  'findings/fetchFindings',
  async (params: FindingsState['filters'] & { page?: number; size?: number }, { rejectWithValue }) => {
    try {
      const response = await apiService.get<ListResponse<Finding>>('/findings', { params });
      return response;
    } catch (error: any) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to fetch findings');
    }
  }
);

export const fetchFindingAsync = createAsyncThunk(
  'findings/fetchFinding',
  async (id: number, { rejectWithValue }) => {
    try {
      const response = await apiService.get<Finding>(`/findings/${id}`);
      return response;
    } catch (error: any) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to fetch finding');
    }
  }
);

export const updateFindingStatusAsync = createAsyncThunk(
  'findings/updateFindingStatus',
  async ({ id, status, comment }: { id: number; status: FindingStatus; comment?: string }, { rejectWithValue }) => {
    try {
      const response = await apiService.patch<Finding>(`/findings/${id}`, { status, comment });
      return response;
    } catch (error: any) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to update finding status');
    }
  }
);

export const bulkUpdateFindingsAsync = createAsyncThunk(
  'findings/bulkUpdateFindings',
  async ({ ids, status, comment }: { ids: number[]; status: FindingStatus; comment?: string }, { rejectWithValue }) => {
    try {
      const response = await apiService.patch<Finding[]>('/findings/bulk', { ids, status, comment });
      return response;
    } catch (error: any) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to update findings');
    }
  }
);

export const exportFindingsAsync = createAsyncThunk(
  'findings/exportFindings',
  async (params: { format: 'csv' | 'json' | 'pdf'; filters?: FindingsState['filters'] }, { rejectWithValue }) => {
    try {
      await apiService.download(`/findings/export?format=${params.format}`, `findings_export.${params.format}`);
    } catch (error: any) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to export findings');
    }
  }
);

export const fetchFindingStatsAsync = createAsyncThunk(
  'findings/fetchFindingStats',
  async (params: FindingsState['filters'] = {}, { rejectWithValue }: any) => {
    try {
      const response = await apiService.get<FindingsState['stats']>('/findings/stats', { params });
      return response;
    } catch (error: any) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to fetch finding stats');
    }
  }
);

const findingsSlice = createSlice({
  name: 'findings',
  initialState,
  reducers: {
    clearError: (state) => {
      state.error = null;
    },
    
    setSelectedFinding: (state, action: PayloadAction<Finding | null>) => {
      state.selectedFinding = action.payload;
    },
    
    setFilters: (state, action: PayloadAction<Partial<FindingsState['filters']>>) => {
      state.filters = { ...state.filters, ...action.payload };
    },
    
    clearFilters: (state) => {
      state.filters = {};
    },
    
    setPagination: (state, action: PayloadAction<Partial<FindingsState['pagination']>>) => {
      state.pagination = { ...state.pagination, ...action.payload };
    },
    
    updateFindingInList: (state, action: PayloadAction<Finding>) => {
      const index = state.findings.findIndex(finding => finding.id === action.payload.id);
      if (index !== -1) {
        state.findings[index] = action.payload;
      }
    },
  },
  extraReducers: (builder) => {
    builder
      // Fetch findings
      .addCase(fetchFindingsAsync.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchFindingsAsync.fulfilled, (state, action) => {
        state.loading = false;
        state.findings = action.payload.data.items;
        state.pagination = {
          total: action.payload.data.total,
          page: action.payload.data.page,
          size: action.payload.data.size,
          pages: action.payload.data.pages,
        };
      })
      .addCase(fetchFindingsAsync.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload as string;
      })
      
      // Fetch single finding
      .addCase(fetchFindingAsync.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchFindingAsync.fulfilled, (state, action) => {
        state.loading = false;
        state.selectedFinding = action.payload;
      })
      .addCase(fetchFindingAsync.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload as string;
      })
      
      // Update finding status
      .addCase(updateFindingStatusAsync.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(updateFindingStatusAsync.fulfilled, (state, action) => {
        state.loading = false;
        const index = state.findings.findIndex(finding => finding.id === action.payload.id);
        if (index !== -1) {
          state.findings[index] = action.payload;
        }
        if (state.selectedFinding?.id === action.payload.id) {
          state.selectedFinding = action.payload;
        }
      })
      .addCase(updateFindingStatusAsync.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload as string;
      })
      
      // Bulk update findings
      .addCase(bulkUpdateFindingsAsync.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(bulkUpdateFindingsAsync.fulfilled, (state, action) => {
        state.loading = false;
        // Update findings in the list
        action.payload.forEach(updatedFinding => {
          const index = state.findings.findIndex(finding => finding.id === updatedFinding.id);
          if (index !== -1) {
            state.findings[index] = updatedFinding;
          }
        });
      })
      .addCase(bulkUpdateFindingsAsync.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload as string;
      })
      
      // Export findings
      .addCase(exportFindingsAsync.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(exportFindingsAsync.fulfilled, (state) => {
        state.loading = false;
      })
      .addCase(exportFindingsAsync.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload as string;
      })
      
      // Fetch finding stats
      .addCase(fetchFindingStatsAsync.fulfilled, (state, action) => {
        state.stats = action.payload;
      });
  },
});

export const {
  clearError,
  setSelectedFinding,
  setFilters,
  clearFilters,
  setPagination,
  updateFindingInList,
} = findingsSlice.actions;

export default findingsSlice.reducer;