import React from 'react';

const RiskChart = ({ data }) => {
  if (!data) {
    return (
      <div className="flex items-center justify-center h-48 text-gray-500">
        No risk data available
      </div>
    );
  }

  const riskLevels = [
    { name: 'Critical', key: 'critical_count', color: 'bg-red-500', bgColor: 'bg-red-50', textColor: 'text-red-700' },
    { name: 'High', key: 'high_count', color: 'bg-orange-500', bgColor: 'bg-orange-50', textColor: 'text-orange-700' },
    { name: 'Medium', key: 'medium_count', color: 'bg-yellow-500', bgColor: 'bg-yellow-50', textColor: 'text-yellow-700' },
    { name: 'Low', key: 'low_count', color: 'bg-green-500', bgColor: 'bg-green-50', textColor: 'text-green-700' }
  ];

  const total = riskLevels.reduce((sum, level) => sum + (data[level.key] || 0), 0);

  if (total === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-48 text-gray-500">
        <svg className="w-12 h-12 mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        <p className="text-sm">No security findings</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Donut Chart */}
      <div className="relative h-48 flex items-center justify-center">
        <svg width="160" height="160" className="transform -rotate-90">
          <circle
            cx="80"
            cy="80"
            r="60"
            fill="none"
            stroke="#f3f4f6"
            strokeWidth="12"
          />
          {riskLevels.map((level, index) => {
            const count = data[level.key] || 0;
            if (count === 0) return null;

            const percentage = (count / total) * 100;
            const circumference = 2 * Math.PI * 60;
            const strokeDasharray = (percentage / 100) * circumference;
            const strokeDashoffset = -riskLevels
              .slice(0, index)
              .reduce((offset, prevLevel) => {
                const prevCount = data[prevLevel.key] || 0;
                const prevPercentage = (prevCount / total) * 100;
                return offset + (prevPercentage / 100) * circumference;
              }, 0);

            const strokeColor = {
              'bg-red-500': '#ef4444',
              'bg-orange-500': '#f97316',
              'bg-yellow-500': '#eab308',
              'bg-green-500': '#22c55e'
            }[level.color] || '#6b7280';

            return (
              <circle
                key={level.key}
                cx="80"
                cy="80"
                r="60"
                fill="none"
                stroke={strokeColor}
                strokeWidth="12"
                strokeDasharray={`${strokeDasharray} ${circumference - strokeDasharray}`}
                strokeDashoffset={strokeDashoffset}
                className="transition-all duration-300"
              />
            );
          })}
        </svg>
        
        {/* Center text */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-bold text-gray-900">{total}</span>
          <span className="text-sm text-gray-500">Total Findings</span>
        </div>
      </div>

      {/* Legend */}
      <div className="grid grid-cols-2 gap-3">
        {riskLevels.map((level) => {
          const count = data[level.key] || 0;
          const percentage = total > 0 ? ((count / total) * 100).toFixed(1) : 0;
          
          return (
            <div key={level.key} className={`p-3 rounded-lg ${level.bgColor} flex items-center justify-between`}>
              <div className="flex items-center space-x-2">
                <div className={`w-3 h-3 rounded-full ${level.color}`}></div>
                <span className={`text-sm font-medium ${level.textColor}`}>
                  {level.name}
                </span>
              </div>
              <div className="text-right">
                <div className={`text-sm font-semibold ${level.textColor}`}>
                  {count}
                </div>
                {total > 0 && (
                  <div className="text-xs text-gray-500">
                    {percentage}%
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Bar Chart Alternative */}
      <div className="mt-6">
        <h4 className="text-sm font-medium text-gray-700 mb-3">Risk Distribution</h4>
        <div className="space-y-2">
          {riskLevels.map((level) => {
            const count = data[level.key] || 0;
            const percentage = total > 0 ? (count / total) * 100 : 0;
            
            return (
              <div key={`bar-${level.key}`} className="flex items-center space-x-3">
                <div className="w-16 text-xs text-gray-600 text-right">
                  {level.name}
                </div>
                <div className="flex-1 bg-gray-200 rounded-full h-2">
                  <div
                    className={`h-2 rounded-full transition-all duration-500 ${level.color}`}
                    style={{ width: `${percentage}%` }}
                  ></div>
                </div>
                <div className="w-8 text-xs text-gray-900 font-medium">
                  {count}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

export default RiskChart;
