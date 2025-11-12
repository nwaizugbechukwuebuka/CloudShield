import React, { useState, useEffect } from 'react';
import { useAuth } from '../services/auth.jsx';
import api from '../services/api';
import LoadingSpinner from '../components/LoadingSpinner';
import RiskChart from '../components/RiskChart';

const Dashboard = () => {
  const { user } = useAuth();
  const [stats, setStats] = useState(null);
  const [recentFindings, setRecentFindings] = useState([]);
  const [integrations, setIntegrations] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      
      // Fetch dashboard statistics
      const [statsRes, findingsRes, integrationsRes] = await Promise.all([
        api.get('/api/scan/stats'),
        api.get('/api/scan/findings?limit=5'),
        api.get('/api/integrations')
      ]);

      setStats(statsRes.data);
      setRecentFindings(findingsRes.data.findings || []);
      setIntegrations(integrationsRes.data);
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  const getRiskBadgeColor = (risk) => {
    const colors = {
      low: 'bg-green-100 text-green-800',
      medium: 'bg-yellow-100 text-yellow-800',
      high: 'bg-orange-100 text-orange-800',
      critical: 'bg-red-100 text-red-800'
    };
    return colors[risk] || 'bg-gray-100 text-gray-800';
  };

  const getStatusBadgeColor = (status) => {
    const colors = {
      active: 'bg-green-100 text-green-800',
      inactive: 'bg-gray-100 text-gray-800',
      error: 'bg-red-100 text-red-800',
      pending: 'bg-yellow-100 text-yellow-800'
    };
    return colors[status] || 'bg-gray-100 text-gray-800';
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
          <h1 className="text-2xl font-bold text-gray-900">
            Welcome back, {user?.username || 'User'}!
          </h1>
          <p className="text-gray-600">
            Here's an overview of your security posture across all connected services.
          </p>
        </div>
      </div>

      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-white p-6 rounded-lg shadow">
          <div className="flex items-center">
            <div className="p-2 bg-blue-100 rounded-lg">
              <svg className="w-6 h-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Total Integrations</p>
              <p className="text-2xl font-semibold text-gray-900">{integrations?.length || 0}</p>
            </div>
          </div>
        </div>

        <div className="bg-white p-6 rounded-lg shadow">
          <div className="flex items-center">
            <div className="p-2 bg-red-100 rounded-lg">
              <svg className="w-6 h-6 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 15.5c-.77.833.192 2.5 1.732 2.5z" />
              </svg>
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Critical Issues</p>
              <p className="text-2xl font-semibold text-gray-900">{stats?.critical_count || 0}</p>
            </div>
          </div>
        </div>

        <div className="bg-white p-6 rounded-lg shadow">
          <div className="flex items-center">
            <div className="p-2 bg-yellow-100 rounded-lg">
              <svg className="w-6 h-6 text-yellow-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
              </svg>
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">High Priority</p>
              <p className="text-2xl font-semibold text-gray-900">{stats?.high_count || 0}</p>
            </div>
          </div>
        </div>

        <div className="bg-white p-6 rounded-lg shadow">
          <div className="flex items-center">
            <div className="p-2 bg-green-100 rounded-lg">
              <svg className="w-6 h-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Total Findings</p>
              <p className="text-2xl font-semibold text-gray-900">{stats?.total_findings || 0}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Charts and Recent Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Risk Distribution Chart */}
        <div className="bg-white p-6 rounded-lg shadow">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Risk Distribution</h3>
          <RiskChart data={stats} />
        </div>

        {/* Recent Findings */}
        <div className="bg-white p-6 rounded-lg shadow">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Recent Security Findings</h3>
          <div className="space-y-4">
            {recentFindings.length > 0 ? (
              recentFindings.map((finding) => (
                <div key={finding.id} className="flex items-start space-x-3 p-3 bg-gray-50 rounded-lg">
                  <div className="flex-shrink-0">
                    <div className={`w-3 h-3 rounded-full ${
                      finding.risk_level === 'critical' ? 'bg-red-500' :
                      finding.risk_level === 'high' ? 'bg-orange-500' :
                      finding.risk_level === 'medium' ? 'bg-yellow-500' : 'bg-green-500'
                    }`}></div>
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-gray-900 truncate">
                      {finding.title}
                    </p>
                    <p className="text-sm text-gray-500 truncate">
                      {finding.description}
                    </p>
                    <div className="flex items-center mt-1 space-x-2">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${getRiskBadgeColor(finding.risk_level)}`}>
                        {finding.risk_level}
                      </span>
                      <span className="text-xs text-gray-400">
                        {new Date(finding.created_at).toLocaleDateString()}
                      </span>
                    </div>
                  </div>
                </div>
              ))
            ) : (
              <div className="text-center py-8">
                <svg className="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <p className="mt-2 text-sm text-gray-500">No security findings yet</p>
                <p className="text-sm text-gray-400">Connect your services to start monitoring</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Active Integrations */}
      <div className="bg-white shadow rounded-lg">
        <div className="px-6 py-4 border-b border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900">Active Integrations</h3>
        </div>
        <div className="p-6">
          {integrations.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {integrations.map((integration) => (
                <div key={integration.id} className="border border-gray-200 rounded-lg p-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="text-sm font-medium text-gray-900 capitalize">
                        {integration.provider}
                      </h4>
                      <p className="text-sm text-gray-500">
                        {integration.config?.account_name || 'Connected Account'}
                      </p>
                    </div>
                    <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getStatusBadgeColor(integration.status)}`}>
                      {integration.status}
                    </span>
                  </div>
                  <div className="mt-2 text-xs text-gray-400">
                    Last scan: {integration.last_scan ? new Date(integration.last_scan).toLocaleDateString() : 'Never'}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8">
              <svg className="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
              <p className="mt-2 text-sm text-gray-500">No integrations configured</p>
              <p className="text-sm text-gray-400">Connect your SaaS services to get started</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;