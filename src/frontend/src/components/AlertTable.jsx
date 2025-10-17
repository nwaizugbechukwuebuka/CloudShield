import React, { useState } from 'react';

const AlertTable = ({ alerts = [], onDismiss, onMarkRead }) => {
  const [selectedAlerts, setSelectedAlerts] = useState(new Set());

  if (!alerts || alerts.length === 0) {
    return (
      <div className="text-center py-8">
        <svg className="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 17h5l-5 5-5-5h5v-6h5v6z" />
        </svg>
        <h3 className="mt-2 text-sm font-medium text-gray-900">No alerts</h3>
        <p className="mt-1 text-sm text-gray-500">
          You're all caught up! No security alerts at this time.
        </p>
      </div>
    );
  }

  const handleSelectAlert = (alertId) => {
    const newSelected = new Set(selectedAlerts);
    if (newSelected.has(alertId)) {
      newSelected.delete(alertId);
    } else {
      newSelected.add(alertId);
    }
    setSelectedAlerts(newSelected);
  };

  const handleSelectAll = () => {
    if (selectedAlerts.size === alerts.length) {
      setSelectedAlerts(new Set());
    } else {
      setSelectedAlerts(new Set(alerts.map(alert => alert.id)));
    }
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: 'bg-red-100 text-red-800 border-red-200',
      high: 'bg-orange-100 text-orange-800 border-orange-200',
      medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
      low: 'bg-green-100 text-green-800 border-green-200',
      info: 'bg-blue-100 text-blue-800 border-blue-200'
    };
    return colors[severity] || 'bg-gray-100 text-gray-800 border-gray-200';
  };

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case 'critical':
        return '🔴';
      case 'high':
        return '🟠';
      case 'medium':
        return '🟡';
      case 'low':
        return '🟢';
      case 'info':
        return 'ℹ️';
      default:
        return '📋';
    }
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  return (
    <div className="bg-white shadow rounded-lg overflow-hidden">
      {/* Header with bulk actions */}
      <div className="px-6 py-4 border-b border-gray-200 bg-gray-50">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <label className="flex items-center">
              <input
                type="checkbox"
                checked={selectedAlerts.size === alerts.length}
                onChange={handleSelectAll}
                className="h-4 w-4 text-indigo-600 focus:ring-indigo-500 border-gray-300 rounded"
              />
              <span className="ml-2 text-sm text-gray-700">
                {selectedAlerts.size > 0 
                  ? `${selectedAlerts.size} selected`
                  : 'Select all'
                }
              </span>
            </label>
            
            {selectedAlerts.size > 0 && (
              <div className="flex space-x-2">
                <button
                  onClick={() => {
                    Array.from(selectedAlerts).forEach(alertId => {
                      onMarkRead && onMarkRead(alertId);
                    });
                    setSelectedAlerts(new Set());
                  }}
                  className="px-3 py-1 text-sm bg-blue-100 text-blue-700 rounded hover:bg-blue-200"
                >
                  Mark as Read
                </button>
                <button
                  onClick={() => {
                    Array.from(selectedAlerts).forEach(alertId => {
                      onDismiss && onDismiss(alertId);
                    });
                    setSelectedAlerts(new Set());
                  }}
                  className="px-3 py-1 text-sm bg-red-100 text-red-700 rounded hover:bg-red-200"
                >
                  Dismiss
                </button>
              </div>
            )}
          </div>
          
          <div className="text-sm text-gray-500">
            {alerts.length} alert{alerts.length !== 1 ? 's' : ''}
          </div>
        </div>
      </div>

      {/* Alert list */}
      <div className="divide-y divide-gray-200">
        {alerts.map((alert) => (
          <div key={alert.id} className={`p-6 hover:bg-gray-50 transition-colors ${alert.read ? 'opacity-75' : ''}`}>
            <div className="flex items-start space-x-4">
              <label className="flex items-center mt-1">
                <input
                  type="checkbox"
                  checked={selectedAlerts.has(alert.id)}
                  onChange={() => handleSelectAlert(alert.id)}
                  className="h-4 w-4 text-indigo-600 focus:ring-indigo-500 border-gray-300 rounded"
                />
              </label>
              
              <div className="text-2xl mt-1">
                {getSeverityIcon(alert.severity)}
              </div>
              
              <div className="flex-1 min-w-0">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center space-x-2 mb-1">
                      <h3 className={`text-lg font-medium ${alert.read ? 'text-gray-600' : 'text-gray-900'}`}>
                        {alert.title}
                      </h3>
                      <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium border ${getSeverityColor(alert.severity)}`}>
                        {alert.severity.toUpperCase()}
                      </span>
                      {!alert.read && (
                        <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                          NEW
                        </span>
                      )}
                    </div>
                    
                    <p className={`text-sm mb-2 ${alert.read ? 'text-gray-500' : 'text-gray-700'}`}>
                      {alert.message}
                    </p>
                    
                    <div className="flex items-center space-x-4 text-xs text-gray-500">
                      <span className="flex items-center">
                        <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        {formatDate(alert.created_at)}
                      </span>
                      
                      {alert.source && (
                        <span className="flex items-center">
                          <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-6m-2-5h6m-6 0V9a2 2 0 012-2h2a2 2 0 012 2v6z" />
                          </svg>
                          {alert.source}
                        </span>
                      )}
                      
                      {alert.finding_id && (
                        <span className="flex items-center">
                          <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                          </svg>
                          Finding #{alert.finding_id.slice(-8)}
                        </span>
                      )}
                    </div>
                    
                    {alert.action_required && (
                      <div className="mt-3 p-2 bg-yellow-50 border border-yellow-200 rounded">
                        <div className="flex items-start">
                          <svg className="w-5 h-5 text-yellow-600 mt-0.5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
                          </svg>
                          <div>
                            <h4 className="text-sm font-medium text-yellow-800">Action Required</h4>
                            <p className="text-sm text-yellow-700 mt-1">{alert.action_required}</p>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                  
                  <div className="flex flex-col space-y-1 ml-4">
                    {!alert.read && onMarkRead && (
                      <button
                        onClick={() => onMarkRead(alert.id)}
                        className="text-xs text-blue-600 hover:text-blue-700 hover:underline"
                      >
                        Mark as read
                      </button>
                    )}
                    {onDismiss && (
                      <button
                        onClick={() => onDismiss(alert.id)}
                        className="text-xs text-red-600 hover:text-red-700 hover:underline"
                      >
                        Dismiss
                      </button>
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
      
      {/* Footer */}
      <div className="px-6 py-3 bg-gray-50 border-t border-gray-200">
        <div className="flex items-center justify-between text-sm text-gray-600">
          <span>
            Showing {alerts.filter(a => !a.read).length} unread of {alerts.length} total alerts
          </span>
          <span>
            Last updated: {formatDate(new Date().toISOString())}
          </span>
        </div>
      </div>
    </div>
  );
};

export default AlertTable;
