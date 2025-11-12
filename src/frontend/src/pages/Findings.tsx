import React, { useState, useEffect } from 'react';
import api from '../services/api';
import LoadingSpinner from '../components/LoadingSpinner';

const Findings = () => {
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState({
    risk_level: 'all',
    provider: 'all',
    finding_type: 'all'
  });
  const [pagination, setPagination] = useState({
    page: 1,
    limit: 20,
    total: 0,
    pages: 0
  });

  useEffect(() => {
    fetchFindings();
  }, [filters, pagination.page]);

  const fetchFindings = async () => {
    try {
      setLoading(true);
      const params = new URLSearchParams({
        page: pagination.page,
        limit: pagination.limit,
        ...(filters.risk_level !== 'all' && { risk_level: filters.risk_level }),
        ...(filters.provider !== 'all' && { provider: filters.provider }),
        ...(filters.finding_type !== 'all' && { finding_type: filters.finding_type })
      });

      const response = await api.get(`/api/scan/findings?${params}`);
      setFindings(response.data.findings);
      setPagination(prev => ({
        ...prev,
        total: response.data.total,
        pages: response.data.pages
      }));
    } catch (error) {
      console.error('Failed to fetch findings:', error);
    } finally {
      setLoading(false);
    }
  };

  const getRiskBadgeColor = (risk) => {
    const colors = {
      low: 'bg-green-100 text-green-800 border-green-200',
      medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
      high: 'bg-orange-100 text-orange-800 border-orange-200',
      critical: 'bg-red-100 text-red-800 border-red-200'
    };
    return colors[risk] || 'bg-gray-100 text-gray-800 border-gray-200';
  };

  const getRiskIcon = (risk) => {
    switch (risk) {
      case 'critical':
        return '🔴';
      case 'high':
        return '🟠';
      case 'medium':
        return '🟡';
      case 'low':
        return '🟢';
      default:
        return '⚪';
    }
  };

  const getFindingTypeIcon = (type) => {
    const icons = {
      misconfiguration: '⚙️',
      inactive_user: '👤',
      public_share: '🌐',
      overprivileged_token: '🔑',
      suspicious_activity: '🚨',
      compliance_violation: '📋'
    };
    return icons[type] || '📋';
  };

  const handleFilterChange = (key, value) => {
    setFilters(prev => ({ ...prev, [key]: value }));
    setPagination(prev => ({ ...prev, page: 1 }));
  };

  const handlePageChange = (newPage) => {
    setPagination(prev => ({ ...prev, page: newPage }));
  };

  if (loading && findings.length === 0) {
    return (
      <div className="flex justify-center items-center h-96">
        <LoadingSpinner />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-white shadow rounded-lg">
        <div className="px-6 py-4">
          <h1 className="text-2xl font-bold text-gray-900">Security Findings</h1>
          <p className="text-gray-600">
            Review and manage security issues discovered across your connected services.
          </p>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white shadow rounded-lg">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900">Filters</h2>
        </div>
        <div className="p-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Risk Level
              </label>
              <select
                value={filters.risk_level}
                onChange={(e) => handleFilterChange('risk_level', e.target.value)}
                className="block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
              >
                <option value="all">All Risk Levels</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Service Provider
              </label>
              <select
                value={filters.provider}
                onChange={(e) => handleFilterChange('provider', e.target.value)}
                className="block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
              >
                <option value="all">All Providers</option>
                <option value="google">Google Workspace</option>
                <option value="microsoft">Microsoft 365</option>
                <option value="slack">Slack</option>
                <option value="github">GitHub</option>
                <option value="notion">Notion</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Finding Type
              </label>
              <select
                value={filters.finding_type}
                onChange={(e) => handleFilterChange('finding_type', e.target.value)}
                className="block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
              >
                <option value="all">All Types</option>
                <option value="misconfiguration">Misconfiguration</option>
                <option value="inactive_user">Inactive User</option>
                <option value="public_share">Public Share</option>
                <option value="overprivileged_token">Overprivileged Token</option>
                <option value="suspicious_activity">Suspicious Activity</option>
                <option value="compliance_violation">Compliance Violation</option>
              </select>
            </div>
          </div>
        </div>
      </div>

      {/* Findings List */}
      <div className="bg-white shadow rounded-lg">
        <div className="px-6 py-4 border-b border-gray-200 flex justify-between items-center">
          <h2 className="text-lg font-semibold text-gray-900">
            Findings ({pagination.total})
          </h2>
          {loading && (
            <LoadingSpinner size="sm" />
          )}
        </div>
        
        <div className="divide-y divide-gray-200">
          {findings.length > 0 ? (
            findings.map((finding) => (
              <div key={finding.id} className="p-6 hover:bg-gray-50 transition-colors">
                <div className="flex items-start justify-between">
                  <div className="flex items-start space-x-4 flex-1">
                    <div className="text-2xl mt-1">
                      {getFindingTypeIcon(finding.finding_type)}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center space-x-2 mb-2">
                        <h3 className="text-lg font-semibold text-gray-900">
                          {finding.title}
                        </h3>
                        <span className="text-lg">
                          {getRiskIcon(finding.risk_level)}
                        </span>
                        <span className={`inline-flex items-center px-2 py-1 rounded-md text-xs font-medium border ${getRiskBadgeColor(finding.risk_level)}`}>
                          {finding.risk_level.toUpperCase()}
                        </span>
                      </div>
                      
                      <p className="text-gray-700 mb-3">
                        {finding.description}
                      </p>
                      
                      <div className="flex items-center space-x-4 text-sm text-gray-500">
                        <span className="flex items-center">
                          <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-6m-2-5h6m-6 0V9a2 2 0 012-2h2a2 2 0 012 2v6z" />
                          </svg>
                          {finding.integration?.provider || 'Unknown Provider'}
                        </span>
                        <span className="flex items-center">
                          <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A1.99 1.99 0 013 12V7a4 4 0 014-4z" />
                          </svg>
                          {finding.finding_type.replace('_', ' ')}
                        </span>
                        <span className="flex items-center">
                          <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                          </svg>
                          {new Date(finding.created_at).toLocaleDateString()}
                        </span>
                        {finding.risk_score && (
                          <span className="flex items-center">
                            <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                            </svg>
                            Score: {finding.risk_score}
                          </span>
                        )}
                      </div>
                      
                      {finding.remediation && (
                        <div className="mt-3 p-3 bg-blue-50 rounded-lg border border-blue-200">
                          <div className="flex items-start">
                            <svg className="w-5 h-5 text-blue-600 mt-0.5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                            <div>
                              <h4 className="text-sm font-medium text-blue-900 mb-1">
                                Recommended Action
                              </h4>
                              <p className="text-sm text-blue-800">
                                {finding.remediation}
                              </p>
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            ))
          ) : (
            <div className="text-center py-12">
              <svg className="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <h3 className="mt-2 text-sm font-medium text-gray-900">No findings</h3>
              <p className="mt-1 text-sm text-gray-500">
                {Object.values(filters).some(f => f !== 'all') 
                  ? 'No findings match your current filters' 
                  : 'No security findings have been detected yet'}
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Pagination */}
      {pagination.pages > 1 && (
        <div className="bg-white px-4 py-3 border-t border-gray-200 sm:px-6 rounded-lg shadow">
          <div className="flex items-center justify-between">
            <div className="flex-1 flex justify-between sm:hidden">
              <button
                onClick={() => handlePageChange(pagination.page - 1)}
                disabled={pagination.page <= 1}
                className="relative inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Previous
              </button>
              <button
                onClick={() => handlePageChange(pagination.page + 1)}
                disabled={pagination.page >= pagination.pages}
                className="ml-3 relative inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Next
              </button>
            </div>
            <div className="hidden sm:flex-1 sm:flex sm:items-center sm:justify-between">
              <div>
                <p className="text-sm text-gray-700">
                  Showing{' '}
                  <span className="font-medium">
                    {((pagination.page - 1) * pagination.limit) + 1}
                  </span>{' '}
                  to{' '}
                  <span className="font-medium">
                    {Math.min(pagination.page * pagination.limit, pagination.total)}
                  </span>{' '}
                  of{' '}
                  <span className="font-medium">{pagination.total}</span>{' '}
                  results
                </p>
              </div>
              <div>
                <nav className="relative z-0 inline-flex rounded-md shadow-sm -space-x-px">
                  <button
                    onClick={() => handlePageChange(pagination.page - 1)}
                    disabled={pagination.page <= 1}
                    className="relative inline-flex items-center px-2 py-2 rounded-l-md border border-gray-300 bg-white text-sm font-medium text-gray-500 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    Previous
                  </button>
                  {Array.from({ length: Math.min(5, pagination.pages) }, (_, i) => {
                    const pageNum = i + 1;
                    return (
                      <button
                        key={pageNum}
                        onClick={() => handlePageChange(pageNum)}
                        className={`relative inline-flex items-center px-4 py-2 border text-sm font-medium ${
                          pageNum === pagination.page
                            ? 'z-10 bg-indigo-50 border-indigo-500 text-indigo-600'
                            : 'bg-white border-gray-300 text-gray-500 hover:bg-gray-50'
                        }`}
                      >
                        {pageNum}
                      </button>
                    );
                  })}
                  <button
                    onClick={() => handlePageChange(pagination.page + 1)}
                    disabled={pagination.page >= pagination.pages}
                    className="relative inline-flex items-center px-2 py-2 rounded-r-md border border-gray-300 bg-white text-sm font-medium text-gray-500 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    Next
                  </button>
                </nav>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Findings;
