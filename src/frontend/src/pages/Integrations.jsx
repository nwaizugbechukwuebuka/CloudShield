import React, { useState, useEffect } from 'react';
import api from '../services/api';
import LoadingSpinner from '../components/LoadingSpinner';
import IntegrationCard from '../components/IntegrationCard';

const Integrations = () => {
  const [integrations, setIntegrations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [connecting, setConnecting] = useState(null);

  const availableProviders = [
    {
      id: 'google',
      name: 'Google Workspace',
      description: 'Monitor Google Drive, Gmail, and Workspace settings',
      icon: '🔵',
      color: 'bg-blue-50 border-blue-200',
    },
    {
      id: 'microsoft',
      name: 'Microsoft 365',
      description: 'Secure OneDrive, Outlook, and Teams configuration',
      icon: '🔷',
      color: 'bg-indigo-50 border-indigo-200',
    },
    {
      id: 'slack',
      name: 'Slack',
      description: 'Audit channels, users, and workspace permissions',
      icon: '💬',
      color: 'bg-purple-50 border-purple-200',
    },
    {
      id: 'github',
      name: 'GitHub',
      description: 'Review repository access and organization settings',
      icon: '🐙',
      color: 'bg-gray-50 border-gray-200',
    },
    {
      id: 'notion',
      name: 'Notion',
      description: 'Check page permissions and workspace sharing',
      icon: '📝',
      color: 'bg-yellow-50 border-yellow-200',
    },
  ];

  useEffect(() => {
    fetchIntegrations();
  }, []);

  const fetchIntegrations = async () => {
    try {
      setLoading(true);
      const response = await api.get('/api/integrations');
      setIntegrations(response.data);
    } catch (error) {
      console.error('Failed to fetch integrations:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleConnect = async (provider) => {
    try {
      setConnecting(provider);
      
      // Redirect to OAuth flow
      const response = await api.get(`/api/auth/${provider}/login`);
      if (response.data.auth_url) {
        window.location.href = response.data.auth_url;
      }
    } catch (error) {
      console.error('Failed to initiate OAuth:', error);
      setConnecting(null);
    }
  };

  const handleDisconnect = async (integrationId) => {
    if (!confirm('Are you sure you want to disconnect this integration?')) {
      return;
    }

    try {
      await api.delete(`/api/integrations/${integrationId}`);
      setIntegrations(prev => prev.filter(int => int.id !== integrationId));
    } catch (error) {
      console.error('Failed to disconnect integration:', error);
    }
  };

  const handleScan = async (integrationId) => {
    try {
      await api.post(`/api/scan/integration/${integrationId}`);
      // Refresh integrations to get updated scan status
      fetchIntegrations();
    } catch (error) {
      console.error('Failed to start scan:', error);
    }
  };

  const getConnectedIntegration = (providerId) => {
    return integrations.find(int => int.provider === providerId);
  };

  if (loading) {
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
          <h1 className="text-2xl font-bold text-gray-900">Integrations</h1>
          <p className="text-gray-600">
            Connect your SaaS applications to monitor their security configuration.
          </p>
        </div>
      </div>

      {/* Connected Integrations */}
      {integrations.length > 0 && (
        <div className="bg-white shadow rounded-lg">
          <div className="px-6 py-4 border-b border-gray-200">
            <h2 className="text-lg font-semibold text-gray-900">Connected Services</h2>
          </div>
          <div className="p-6">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {integrations.map((integration) => (
                <IntegrationCard
                  key={integration.id}
                  integration={integration}
                  onDisconnect={handleDisconnect}
                  onScan={handleScan}
                />
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Available Integrations */}
      <div className="bg-white shadow rounded-lg">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900">Available Integrations</h2>
        </div>
        <div className="p-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {availableProviders.map((provider) => {
              const connectedIntegration = getConnectedIntegration(provider.id);
              const isConnected = !!connectedIntegration;
              const isConnecting = connecting === provider.id;

              return (
                <div
                  key={provider.id}
                  className={`border-2 border-dashed rounded-lg p-6 text-center transition-colors duration-200 ${
                    isConnected ? 'border-green-300 bg-green-50' : provider.color
                  }`}
                >
                  <div className="text-4xl mb-3">{provider.icon}</div>
                  <h3 className="text-lg font-semibold text-gray-900 mb-2">
                    {provider.name}
                  </h3>
                  <p className="text-sm text-gray-600 mb-4">
                    {provider.description}
                  </p>

                  {isConnected ? (
                    <div className="space-y-2">
                      <div className="flex items-center justify-center text-green-600 mb-2">
                        <svg className="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
                          <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                        </svg>
                        Connected
                      </div>
                      <p className="text-xs text-gray-500">
                        {connectedIntegration.config?.account_name || 'Connected Account'}
                      </p>
                    </div>
                  ) : (
                    <button
                      onClick={() => handleConnect(provider.id)}
                      disabled={isConnecting}
                      className="w-full bg-indigo-600 text-white px-4 py-2 rounded-md hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed transition-colors duration-200"
                    >
                      {isConnecting ? (
                        <div className="flex items-center justify-center">
                          <LoadingSpinner size="sm" />
                          <span className="ml-2">Connecting...</span>
                        </div>
                      ) : (
                        'Connect'
                      )}
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Integration Status Help */}
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-6">
        <div className="flex items-start">
          <svg className="w-6 h-6 text-blue-600 mt-0.5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <div>
            <h3 className="text-sm font-semibold text-blue-900 mb-1">About Integrations</h3>
            <div className="text-sm text-blue-800">
              <ul className="list-disc list-inside space-y-1">
                <li>Each integration requires OAuth authentication with the respective service</li>
                <li>CloudShield only requests read-only permissions to analyze your security configuration</li>
                <li>Scans run automatically every 24 hours or can be triggered manually</li>
                <li>You can disconnect any integration at any time from the connected services section</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Integrations;
