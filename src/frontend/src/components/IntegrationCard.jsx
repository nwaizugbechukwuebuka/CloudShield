import React, { useState } from 'react';
import LoadingSpinner from './LoadingSpinner';

const IntegrationCard = ({ integration, onDisconnect, onScan }) => {
  const [isScanning, setIsScanning] = useState(false);
  const [isDisconnecting, setIsDisconnecting] = useState(false);

  const getProviderIcon = (provider) => {
    const icons = {
      google: '🔵',
      microsoft: '🔷',
      slack: '💬',
      github: '🐙',
      notion: '📝'
    };
    return icons[provider] || '🔗';
  };

  const getProviderName = (provider) => {
    const names = {
      google: 'Google Workspace',
      microsoft: 'Microsoft 365',
      slack: 'Slack',
      github: 'GitHub',
      notion: 'Notion'
    };
    return names[provider] || provider;
  };

  const getStatusColor = (status) => {
    const colors = {
      active: 'bg-green-100 text-green-800 border-green-200',
      inactive: 'bg-gray-100 text-gray-800 border-gray-200',
      error: 'bg-red-100 text-red-800 border-red-200',
      pending: 'bg-yellow-100 text-yellow-800 border-yellow-200'
    };
    return colors[status] || 'bg-gray-100 text-gray-800 border-gray-200';
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'active':
        return (
          <svg className="w-4 h-4 text-green-600" fill="currentColor" viewBox="0 0 20 20">
            <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
          </svg>
        );
      case 'error':
        return (
          <svg className="w-4 h-4 text-red-600" fill="currentColor" viewBox="0 0 20 20">
            <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
          </svg>
        );
      case 'pending':
        return (
          <svg className="w-4 h-4 text-yellow-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        );
      default:
        return (
          <svg className="w-4 h-4 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20 12H4" />
          </svg>
        );
    }
  };

  const handleScan = async () => {
    setIsScanning(true);
    try {
      await onScan(integration.id);
    } finally {
      setIsScanning(false);
    }
  };

  const handleDisconnect = async () => {
    setIsDisconnecting(true);
    try {
      await onDisconnect(integration.id);
    } finally {
      setIsDisconnecting(false);
    }
  };

  const formatDate = (dateString) => {
    if (!dateString) return 'Never';
    return new Date(dateString).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  return (
    <div className="bg-white border border-gray-200 rounded-lg p-6 shadow-sm hover:shadow-md transition-shadow duration-200">
      {/* Header */}
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center space-x-3">
          <div className="text-2xl">
            {getProviderIcon(integration.provider)}
          </div>
          <div>
            <h3 className="text-lg font-semibold text-gray-900">
              {getProviderName(integration.provider)}
            </h3>
            <p className="text-sm text-gray-600">
              {integration.config?.account_name || integration.config?.workspace_name || 'Connected Account'}
            </p>
          </div>
        </div>
        
        <div className={`flex items-center space-x-1 px-2 py-1 rounded-full text-xs font-medium border ${getStatusColor(integration.status)}`}>
          {getStatusIcon(integration.status)}
          <span className="capitalize">{integration.status}</span>
        </div>
      </div>

      {/* Statistics */}
      <div className="grid grid-cols-3 gap-4 mb-4 p-3 bg-gray-50 rounded-lg">
        <div className="text-center">
          <div className="text-lg font-semibold text-gray-900">
            {integration.scan_count || 0}
          </div>
          <div className="text-xs text-gray-600">Scans</div>
        </div>
        <div className="text-center">
          <div className="text-lg font-semibold text-gray-900">
            {integration.findings_count || 0}
          </div>
          <div className="text-xs text-gray-600">Findings</div>
        </div>
        <div className="text-center">
          <div className="text-lg font-semibold text-gray-900">
            {integration.risk_score || 0}
          </div>
          <div className="text-xs text-gray-600">Risk Score</div>
        </div>
      </div>

      {/* Last Scan Info */}
      <div className="mb-4 text-sm text-gray-600">
        <div className="flex items-center justify-between">
          <span>Last Scan:</span>
          <span className="font-medium">
            {formatDate(integration.last_scan)}
          </span>
        </div>
        <div className="flex items-center justify-between mt-1">
          <span>Next Scan:</span>
          <span className="font-medium">
            {integration.next_scan ? formatDate(integration.next_scan) : 'Scheduled'}
          </span>
        </div>
      </div>

      {/* Error Display */}
      {integration.status === 'error' && integration.error_message && (
        <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg">
          <div className="flex items-start">
            <svg className="w-5 h-5 text-red-600 mt-0.5 mr-2" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
            </svg>
            <div>
              <h4 className="text-sm font-medium text-red-800 mb-1">Connection Error</h4>
              <p className="text-sm text-red-700">{integration.error_message}</p>
            </div>
          </div>
        </div>
      )}

      {/* Actions */}
      <div className="flex space-x-2">
        <button
          onClick={handleScan}
          disabled={isScanning || integration.status === 'error'}
          className="flex-1 bg-indigo-600 text-white px-3 py-2 rounded-md text-sm font-medium hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed transition-colors duration-200"
        >
          {isScanning ? (
            <div className="flex items-center justify-center">
              <LoadingSpinner size="sm" />
              <span className="ml-2">Scanning...</span>
            </div>
          ) : (
            <div className="flex items-center justify-center">
              <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
              Scan Now
            </div>
          )}
        </button>

        <button
          onClick={handleDisconnect}
          disabled={isDisconnecting}
          className="px-3 py-2 border border-red-300 text-red-700 rounded-md text-sm font-medium hover:bg-red-50 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed transition-colors duration-200"
        >
          {isDisconnecting ? (
            <div className="flex items-center">
              <LoadingSpinner size="sm" />
              <span className="ml-2">Removing...</span>
            </div>
          ) : (
            <div className="flex items-center">
              <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
              Disconnect
            </div>
          )}
        </button>
      </div>

      {/* Additional Info */}
      <div className="mt-3 pt-3 border-t border-gray-100">
        <div className="flex items-center justify-between text-xs text-gray-500">
          <span>Connected: {formatDate(integration.created_at)}</span>
          {integration.config?.permissions && (
            <span className="flex items-center">
              <svg className="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
              {Array.isArray(integration.config.permissions) 
                ? integration.config.permissions.length 
                : Object.keys(integration.config.permissions || {}).length} permissions
            </span>
          )}
        </div>
      </div>
    </div>
  );
};

export default IntegrationCard;
