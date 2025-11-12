import React, { useState, useEffect } from 'react';
import { useAuth } from '../services/auth.jsx';
import api from '../services/api';
import LoadingSpinner from '../components/LoadingSpinner';

const Settings = () => {
  const { user, logout } = useAuth();
  const [settings, setSettings] = useState({
    notifications: {
      email_alerts: true,
      slack_alerts: false,
      scan_completion: true,
      weekly_reports: true
    },
    scanning: {
      auto_scan_interval: '24',
      scan_depth: 'standard',
      include_low_risk: false
    },
    alerts: {
      slack_webhook_url: '',
      email_recipients: ''
    }
  });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState(null);

  useEffect(() => {
    fetchSettings();
  }, []);

  const fetchSettings = async () => {
    try {
      setLoading(true);
      // In a real implementation, this would fetch user-specific settings
      // For now, we'll use default values
      setLoading(false);
    } catch (error) {
      console.error('Failed to fetch settings:', error);
      setLoading(false);
    }
  };

  const handleSettingChange = (section, key, value) => {
    setSettings(prev => ({
      ...prev,
      [section]: {
        ...prev[section],
        [key]: value
      }
    }));
  };

  const handleSaveSettings = async () => {
    try {
      setSaving(true);
      
      // In a real implementation, this would save to the backend
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      setMessage({ type: 'success', text: 'Settings saved successfully!' });
      setTimeout(() => setMessage(null), 3000);
    } catch (error) {
      console.error('Failed to save settings:', error);
      setMessage({ type: 'error', text: 'Failed to save settings. Please try again.' });
      setTimeout(() => setMessage(null), 3000);
    } finally {
      setSaving(false);
    }
  };

  const handleLogout = async () => {
    if (confirm('Are you sure you want to sign out?')) {
      await logout();
    }
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
          <h1 className="text-2xl font-bold text-gray-900">Settings</h1>
          <p className="text-gray-600">
            Manage your account preferences and system configuration.
          </p>
        </div>
      </div>

      {/* Success/Error Messages */}
      {message && (
        <div className={`rounded-lg p-4 ${
          message.type === 'success' 
            ? 'bg-green-50 border border-green-200 text-green-700' 
            : 'bg-red-50 border border-red-200 text-red-700'
        }`}>
          <div className="flex items-center">
            {message.type === 'success' ? (
              <svg className="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
              </svg>
            ) : (
              <svg className="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
              </svg>
            )}
            {message.text}
          </div>
        </div>
      )}

      {/* Profile Information */}
      <div className="bg-white shadow rounded-lg">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900">Profile Information</h2>
        </div>
        <div className="p-6">
          <div className="flex items-center space-x-4">
            <div className="w-16 h-16 bg-indigo-100 rounded-full flex items-center justify-center">
              <span className="text-xl font-semibold text-indigo-600">
                {user?.username?.charAt(0).toUpperCase() || 'U'}
              </span>
            </div>
            <div>
              <h3 className="text-lg font-medium text-gray-900">{user?.username}</h3>
              <p className="text-gray-600">{user?.email}</p>
              <p className="text-sm text-gray-500">
                Member since {user?.created_at ? new Date(user.created_at).toLocaleDateString() : 'Unknown'}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Notification Settings */}
      <div className="bg-white shadow rounded-lg">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900">Notification Preferences</h2>
        </div>
        <div className="p-6 space-y-4">
          {[
            { key: 'email_alerts', label: 'Email Alerts', description: 'Receive email notifications for critical security findings' },
            { key: 'slack_alerts', label: 'Slack Alerts', description: 'Send alerts to your Slack workspace' },
            { key: 'scan_completion', label: 'Scan Completion', description: 'Notify when scheduled scans are completed' },
            { key: 'weekly_reports', label: 'Weekly Reports', description: 'Receive weekly security summary reports' }
          ].map(({ key, label, description }) => (
            <div key={key} className="flex items-center justify-between">
              <div>
                <h4 className="text-sm font-medium text-gray-900">{label}</h4>
                <p className="text-sm text-gray-500">{description}</p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={settings.notifications[key]}
                  onChange={(e) => handleSettingChange('notifications', key, e.target.checked)}
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-indigo-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-indigo-600"></div>
              </label>
            </div>
          ))}
        </div>
      </div>

      {/* Scanning Settings */}
      <div className="bg-white shadow rounded-lg">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900">Scanning Configuration</h2>
        </div>
        <div className="p-6 space-y-6">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Auto Scan Interval (hours)
            </label>
            <select
              value={settings.scanning.auto_scan_interval}
              onChange={(e) => handleSettingChange('scanning', 'auto_scan_interval', e.target.value)}
              className="block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
            >
              <option value="6">Every 6 hours</option>
              <option value="12">Every 12 hours</option>
              <option value="24">Every 24 hours</option>
              <option value="48">Every 48 hours</option>
              <option value="168">Weekly</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Scan Depth
            </label>
            <select
              value={settings.scanning.scan_depth}
              onChange={(e) => handleSettingChange('scanning', 'scan_depth', e.target.value)}
              className="block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
            >
              <option value="quick">Quick Scan</option>
              <option value="standard">Standard Scan</option>
              <option value="deep">Deep Scan</option>
            </select>
            <p className="mt-1 text-sm text-gray-500">
              Deep scans take longer but provide more comprehensive security analysis
            </p>
          </div>

          <div className="flex items-center justify-between">
            <div>
              <h4 className="text-sm font-medium text-gray-900">Include Low Risk Findings</h4>
              <p className="text-sm text-gray-500">Show informational and low-priority security findings</p>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={settings.scanning.include_low_risk}
                onChange={(e) => handleSettingChange('scanning', 'include_low_risk', e.target.checked)}
                className="sr-only peer"
              />
              <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-indigo-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-indigo-600"></div>
            </label>
          </div>
        </div>
      </div>

      {/* Alert Configuration */}
      <div className="bg-white shadow rounded-lg">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900">Alert Configuration</h2>
        </div>
        <div className="p-6 space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Slack Webhook URL
            </label>
            <input
              type="url"
              value={settings.alerts.slack_webhook_url}
              onChange={(e) => handleSettingChange('alerts', 'slack_webhook_url', e.target.value)}
              placeholder="https://hooks.slack.com/services/..."
              className="block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Additional Email Recipients
            </label>
            <input
              type="text"
              value={settings.alerts.email_recipients}
              onChange={(e) => handleSettingChange('alerts', 'email_recipients', e.target.value)}
              placeholder="admin@company.com, security@company.com"
              className="block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
            />
            <p className="mt-1 text-sm text-gray-500">
              Comma-separated list of email addresses to receive security alerts
            </p>
          </div>
        </div>
      </div>

      {/* Actions */}
      <div className="flex justify-between items-center">
        <button
          onClick={handleLogout}
          className="px-4 py-2 border border-red-300 text-red-700 rounded-md hover:bg-red-50 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2 transition-colors duration-200"
        >
          Sign Out
        </button>

        <button
          onClick={handleSaveSettings}
          disabled={saving}
          className="px-6 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed transition-colors duration-200"
        >
          {saving ? (
            <div className="flex items-center">
              <LoadingSpinner size="sm" />
              <span className="ml-2">Saving...</span>
            </div>
          ) : (
            'Save Changes'
          )}
        </button>
      </div>
    </div>
  );
};

export default Settings;
