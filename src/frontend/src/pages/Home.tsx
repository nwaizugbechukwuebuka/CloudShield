import { Link } from 'react-router-dom'
import { 
  ShieldCheckIcon, 
  ChartBarIcon, 
  CogIcon, 
  BellIcon,
  CloudIcon,
  LockClosedIcon,
  EyeIcon,
  SparklesIcon,
  ArrowRightIcon
} from '@heroicons/react/24/outline'

const features = [
  {
    name: 'Multi-Platform Scanning',
    description: 'Connect and scan Google Workspace, Microsoft 365, Slack, GitHub, and Notion for security misconfigurations.',
    icon: ShieldCheckIcon,
  },
  {
    name: 'Risk Assessment',
    description: 'Advanced risk scoring engine identifies critical security issues and provides actionable remediation steps.',
    icon: ChartBarIcon,
  },
  {
    name: 'Automated Monitoring', 
    description: 'Continuous monitoring with scheduled scans and real-time alerts for new security findings.',
    icon: CogIcon,
  },
  {
    name: 'Smart Alerts',
    description: 'Get notified instantly about critical security findings via Slack, email, or in-app notifications.',
    icon: BellIcon,
  },
]

const integrations = [
  { name: 'Google Workspace', icon: '🏢', color: 'bg-blue-100 text-blue-800' },
  { name: 'Microsoft 365', icon: '📊', color: 'bg-orange-100 text-orange-800' },
  { name: 'Slack', icon: '💬', color: 'bg-purple-100 text-purple-800' },
  { name: 'GitHub', icon: '👨‍💻', color: 'bg-gray-100 text-gray-800' },
  { name: 'Notion', icon: '📝', color: 'bg-green-100 text-green-800' },
]

const stats = [
  { name: 'Security Issues Detected', value: '10,247' },
  { name: 'Platforms Monitored', value: '5' },
  { name: 'Response Time', value: '<30s' },
  { name: 'Uptime', value: '99.9%' },
]

export default function Home() {
  return (
    <div className="min-h-screen">
      {/* Hero section */}
      <div className="relative overflow-hidden bg-gradient-to-br from-primary-600 via-purple-700 to-indigo-800">
        {/* Background decoration */}
        <div className="absolute inset-0">
          <div className="absolute inset-0 bg-gradient-to-br from-primary-600/90 via-purple-700/90 to-indigo-800/90" />
          <div className="absolute top-0 left-0 right-0 h-20 bg-gradient-to-b from-black/10 to-transparent" />
        </div>
        
        {/* Floating icons animation */}
        <div className="absolute inset-0 overflow-hidden">
          <div className="absolute top-20 left-20 animate-bounce">
            <ShieldCheckIcon className="h-8 w-8 text-white/20" />
          </div>
          <div className="absolute top-32 right-32 animate-pulse">
            <LockClosedIcon className="h-6 w-6 text-white/20" />
          </div>
          <div className="absolute bottom-40 left-40 animate-bounce delay-300">
            <CloudIcon className="h-10 w-10 text-white/20" />
          </div>
          <div className="absolute top-40 right-20 animate-pulse delay-500">
            <EyeIcon className="h-7 w-7 text-white/20" />
          </div>
        </div>

        <div className="relative max-w-7xl mx-auto py-24 px-4 sm:py-32 sm:px-6 lg:px-8">
          <div className="text-center">
            <div className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-white/10 text-white border border-white/20 mb-8">
              <SparklesIcon className="h-4 w-4 mr-2" />
              Enterprise-Grade SaaS Security Platform
            </div>
            
            <h1 className="text-5xl font-extrabold tracking-tight text-white sm:text-6xl lg:text-7xl">
              <span className="block">CloudShield</span>
              <span className="block text-gradient bg-gradient-to-r from-yellow-400 to-orange-400 bg-clip-text text-transparent">
                Security Analyzer
              </span>
            </h1>
            
            <p className="mt-6 max-w-3xl mx-auto text-xl text-gray-100 leading-relaxed">
              Advanced SaaS Security Configuration Analyzer with OAuth integrations and automated scanning. 
              Protect your organization's cloud infrastructure with continuous security monitoring across 
              Google Workspace, Microsoft 365, Slack, GitHub, and Notion.
            </p>

            {/* Integration badges */}
            <div className="mt-8 flex flex-wrap justify-center gap-3">
              {integrations.map((integration) => (
                <div key={integration.name} className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${integration.color} bg-white/90`}>
                  <span className="mr-2">{integration.icon}</span>
                  {integration.name}
                </div>
              ))}
            </div>
            
            <div className="mt-12 flex flex-col sm:flex-row gap-4 justify-center">
              <Link
                to="/register"
                className="inline-flex items-center px-8 py-4 border border-transparent text-lg font-semibold rounded-xl text-primary-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-white shadow-xl transform hover:scale-105 transition-all duration-200"
              >
                Get Started Free
                <ArrowRightIcon className="ml-2 h-5 w-5" />
              </Link>
              <Link
                to="/login"
                className="inline-flex items-center px-8 py-4 border-2 border-white/30 text-lg font-semibold rounded-xl text-white bg-white/10 hover:bg-white/20 backdrop-blur-sm focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-white transition-all duration-200"
              >
                Sign In
              </Link>
            </div>

            {/* Stats */}
            <div className="mt-16 grid grid-cols-2 gap-8 md:grid-cols-4">
              {stats.map((stat) => (
                <div key={stat.name} className="text-center">
                  <div className="text-3xl font-bold text-white">{stat.value}</div>
                  <div className="text-sm text-gray-200 mt-1">{stat.name}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Features section */}
      <div className="py-20 bg-gradient-to-b from-gray-50 to-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center">
            <h2 className="text-4xl font-extrabold text-gray-900 sm:text-5xl">
              Comprehensive Security Monitoring
            </h2>
            <p className="mt-4 max-w-3xl mx-auto text-xl text-gray-600 leading-relaxed">
              Detect misconfigurations, inactive users, public shares, and overpermissive tokens across all your SaaS platforms 
              with our advanced AI-powered security engine.
            </p>
          </div>

          <div className="mt-20">
            <div className="grid grid-cols-1 gap-12 sm:grid-cols-2 lg:grid-cols-4">
              {features.map((feature, index) => (
                <div key={feature.name} className="relative group">
                  <div className="relative">
                    {/* Icon background with gradient */}
                    <div className="absolute h-16 w-16 rounded-2xl bg-gradient-to-br from-primary-500 to-purple-600 flex items-center justify-center shadow-lg group-hover:shadow-xl transition-all duration-300 group-hover:scale-110">
                      <feature.icon className="h-8 w-8 text-white" aria-hidden="true" />
                    </div>
                    
                    {/* Content */}
                    <div className="ml-20 pt-2">
                      <h3 className="text-xl font-bold text-gray-900 group-hover:text-primary-600 transition-colors duration-200">
                        {feature.name}
                      </h3>
                      <p className="mt-3 text-base text-gray-600 leading-relaxed">
                        {feature.description}
                      </p>
                    </div>

                    {/* Decorative element */}
                    <div className="absolute -top-2 -left-2 w-20 h-20 bg-gradient-to-br from-primary-100 to-purple-100 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300 -z-10" />
                  </div>

                  {/* Feature number */}
                  <div className="absolute -top-4 -right-2 w-8 h-8 bg-gradient-to-br from-yellow-400 to-orange-500 rounded-full flex items-center justify-center text-white font-bold text-sm shadow-lg">
                    {index + 1}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Additional feature highlights */}
          <div className="mt-20 bg-white rounded-3xl shadow-2xl p-8 lg:p-12 border border-gray-100">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
              <div className="text-center">
                <div className="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-br from-green-400 to-green-600 rounded-full mb-4">
                  <svg className="w-8 h-8 text-white" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                  </svg>
                </div>
                <h3 className="text-xl font-bold text-gray-900 mb-2">99.9% Accuracy</h3>
                <p className="text-gray-600">Industry-leading detection accuracy with minimal false positives</p>
              </div>
              
              <div className="text-center">
                <div className="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-br from-blue-400 to-blue-600 rounded-full mb-4">
                  <svg className="w-8 h-8 text-white" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                  </svg>
                </div>
                <h3 className="text-xl font-bold text-gray-900 mb-2">Real-Time Alerts</h3>
                <p className="text-gray-600">Instant notifications for critical security findings</p>
              </div>
              
              <div className="text-center">
                <div className="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-br from-purple-400 to-purple-600 rounded-full mb-4">
                  <svg className="w-8 h-8 text-white" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M12.395 2.553a1 1 0 00-1.45-.385c-.345.23-.614.558-.822.88-.214.33-.403.713-.57 1.116-.334.804-.614 1.768-.84 2.734a31.365 31.365 0 00-.613 3.58 2.64 2.64 0 01-.945-1.067c-.328-.68-.398-1.534-.398-2.654A1 1 0 005.05 6.05 6.981 6.981 0 003 11a7 7 0 1011.95-4.95c-.592-.591-.98-.985-1.348-1.467-.363-.476-.724-1.063-1.207-2.03zM12.12 15.12A3 3 0 017 13s.879.5 2.5.5c0-1 .5-4 1.25-4.5.5 1 .786 1.293 1.371 1.879A2.99 2.99 0 0113 13a2.99 2.99 0 01-.879 2.121z" clipRule="evenodd" />
                  </svg>
                </div>
                <h3 className="text-xl font-bold text-gray-900 mb-2">Auto Remediation</h3>
                <p className="text-gray-600">Automated fixes for common security misconfigurations</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Security benefits section */}
      <div className="py-20 bg-gradient-to-br from-gray-900 to-gray-800 relative overflow-hidden">
        {/* Background decoration */}
        <div className="absolute inset-0">
          <div className="absolute top-0 left-0 w-96 h-96 bg-gradient-to-br from-primary-500/10 to-purple-500/10 rounded-full blur-3xl" />
          <div className="absolute bottom-0 right-0 w-96 h-96 bg-gradient-to-br from-blue-500/10 to-indigo-500/10 rounded-full blur-3xl" />
        </div>

        <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="lg:grid lg:grid-cols-2 lg:gap-16 lg:items-center">
            <div>
              <h2 className="text-4xl font-extrabold text-white sm:text-5xl">
                Protect Your 
                <span className="block text-gradient bg-gradient-to-r from-blue-400 to-purple-400 bg-clip-text text-transparent">
                  Digital Assets
                </span>
              </h2>
              <p className="mt-4 text-xl text-gray-300 leading-relaxed">
                CloudShield continuously monitors your SaaS applications for security vulnerabilities, 
                helping you maintain compliance and protect sensitive data with enterprise-grade security.
              </p>

              <div className="mt-12 space-y-8">
                <div className="flex items-start">
                  <div className="flex-shrink-0">
                    <div className="flex items-center justify-center h-12 w-12 rounded-xl bg-gradient-to-br from-green-400 to-green-600 shadow-lg">
                      <svg className="h-6 w-6 text-white" fill="currentColor" viewBox="0 0 20 20">
                        <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                      </svg>
                    </div>
                  </div>
                  <div className="ml-6">
                    <h3 className="text-xl font-bold text-white">Real-time Threat Detection</h3>
                    <p className="mt-2 text-lg text-gray-300">
                      Advanced AI algorithms identify security threats as they emerge with continuous monitoring 
                      and instant alerts across all connected platforms.
                    </p>
                  </div>
                </div>

                <div className="flex items-start">
                  <div className="flex-shrink-0">
                    <div className="flex items-center justify-center h-12 w-12 rounded-xl bg-gradient-to-br from-blue-400 to-blue-600 shadow-lg">
                      <svg className="h-6 w-6 text-white" fill="currentColor" viewBox="0 0 20 20">
                        <path fillRule="evenodd" d="M3 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1z" clipRule="evenodd" />
                      </svg>
                    </div>
                  </div>
                  <div className="ml-6">
                    <h3 className="text-xl font-bold text-white">Compliance Monitoring</h3>
                    <p className="mt-2 text-lg text-gray-300">
                      Stay compliant with SOC 2, GDPR, HIPAA, and other industry standards through 
                      automated security assessments and detailed audit trails.
                    </p>
                  </div>
                </div>

                <div className="flex items-start">
                  <div className="flex-shrink-0">
                    <div className="flex items-center justify-center h-12 w-12 rounded-xl bg-gradient-to-br from-purple-400 to-purple-600 shadow-lg">
                      <svg className="h-6 w-6 text-white" fill="currentColor" viewBox="0 0 20 20">
                        <path fillRule="evenodd" d="M11.3 1.046A1 1 0 0112 2v5h4a1 1 0 01.82 1.573l-7 10A1 1 0 018 18v-5H4a1 1 0 01-.82-1.573l7-10a1 1 0 011.12-.38z" clipRule="evenodd" />
                      </svg>
                    </div>
                  </div>
                  <div className="ml-6">
                    <h3 className="text-xl font-bold text-white">Actionable Insights</h3>
                    <p className="mt-2 text-lg text-gray-300">
                      Get detailed remediation steps, prioritized recommendations, and automated 
                      fixes to resolve security issues quickly and efficiently.
                    </p>
                  </div>
                </div>
              </div>
            </div>

            <div className="mt-12 lg:mt-0">
              <div className="bg-white/95 backdrop-blur-sm rounded-2xl shadow-2xl p-8 border border-white/20">
                <div className="text-center mb-6">
                  <h3 className="text-2xl font-bold text-gray-900 mb-2">Live Security Dashboard</h3>
                  <p className="text-gray-600">Real-time monitoring across your platforms</p>
                </div>
                
                <div className="space-y-4">
                  <div className="flex justify-between items-center p-4 bg-gradient-to-r from-red-50 to-red-100 rounded-xl border border-red-200">
                    <div className="flex items-center">
                      <div className="w-3 h-3 bg-red-500 rounded-full mr-3 animate-pulse"></div>
                      <span className="text-red-800 font-semibold">Critical Issues</span>
                    </div>
                    <span className="text-red-600 text-3xl font-bold">3</span>
                  </div>
                  
                  <div className="flex justify-between items-center p-4 bg-gradient-to-r from-yellow-50 to-yellow-100 rounded-xl border border-yellow-200">
                    <div className="flex items-center">
                      <div className="w-3 h-3 bg-yellow-500 rounded-full mr-3 animate-pulse"></div>
                      <span className="text-yellow-800 font-semibold">High Risk</span>
                    </div>
                    <span className="text-yellow-600 text-3xl font-bold">7</span>
                  </div>
                  
                  <div className="flex justify-between items-center p-4 bg-gradient-to-r from-green-50 to-green-100 rounded-xl border border-green-200">
                    <div className="flex items-center">
                      <div className="w-3 h-3 bg-green-500 rounded-full mr-3"></div>
                      <span className="text-green-800 font-semibold">Resolved</span>
                    </div>
                    <span className="text-green-600 text-3xl font-bold">24</span>
                  </div>
                  
                  <div className="flex justify-between items-center p-4 bg-gradient-to-r from-blue-50 to-blue-100 rounded-xl border border-blue-200">
                    <div className="flex items-center">
                      <div className="w-3 h-3 bg-blue-500 rounded-full mr-3"></div>
                      <span className="text-blue-800 font-semibold">Monitoring</span>
                    </div>
                    <span className="text-blue-600 text-3xl font-bold">156</span>
                  </div>
                </div>

                <div className="mt-6 pt-6 border-t border-gray-200">
                  <div className="flex justify-between items-center text-sm">
                    <span className="text-gray-600">Last scan:</span>
                    <span className="text-gray-900 font-medium">2 minutes ago</span>
                  </div>
                  <div className="flex justify-between items-center text-sm mt-2">
                    <span className="text-gray-600">Next scan:</span>
                    <span className="text-gray-900 font-medium">In 28 minutes</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* CTA section */}
      <div className="bg-gradient-to-r from-primary-600 via-blue-600 to-purple-700 relative overflow-hidden">
        {/* Background decoration */}
        <div className="absolute inset-0">
          <div className="absolute top-0 right-0 w-80 h-80 bg-white/10 rounded-full blur-3xl" />
          <div className="absolute bottom-0 left-0 w-80 h-80 bg-white/5 rounded-full blur-3xl" />
        </div>

        <div className="relative max-w-7xl mx-auto py-16 px-4 sm:px-6 lg:py-24 lg:px-8">
          <div className="text-center">
            <h2 className="text-4xl font-extrabold tracking-tight text-white sm:text-5xl lg:text-6xl">
              <span className="block">Ready to secure your SaaS?</span>
              <span className="block text-yellow-300 mt-2">Start monitoring today.</span>
            </h2>
            
            <p className="mt-6 max-w-3xl mx-auto text-xl text-blue-100 leading-relaxed">
              Join thousands of security teams who trust CloudShield to protect their digital infrastructure. 
              Get started in minutes with our free trial.
            </p>

            <div className="mt-12 flex flex-col sm:flex-row gap-6 justify-center">
              <Link
                to="/register"
                className="inline-flex items-center justify-center px-10 py-4 border border-transparent text-xl font-bold rounded-2xl text-primary-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-4 focus:ring-white/50 shadow-2xl transform hover:scale-105 transition-all duration-200"
              >
                <SparklesIcon className="h-6 w-6 mr-3" />
                Start Free Trial
              </Link>
              <Link
                to="/login"
                className="inline-flex items-center justify-center px-10 py-4 border-2 border-white/40 text-xl font-bold rounded-2xl text-white bg-white/10 hover:bg-white/20 backdrop-blur-sm focus:outline-none focus:ring-4 focus:ring-white/50 transition-all duration-200"
              >
                Schedule Demo
                <ArrowRightIcon className="ml-3 h-6 w-6" />
              </Link>
            </div>

            <div className="mt-12 flex flex-col sm:flex-row items-center justify-center gap-8 text-blue-100">
              <div className="flex items-center">
                <svg className="h-5 w-5 text-green-400 mr-2" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                </svg>
                <span className="font-medium">No credit card required</span>
              </div>
              <div className="flex items-center">
                <svg className="h-5 w-5 text-green-400 mr-2" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                </svg>
                <span className="font-medium">Setup in 5 minutes</span>
              </div>
              <div className="flex items-center">
                <svg className="h-5 w-5 text-green-400 mr-2" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                </svg>
                <span className="font-medium">24/7 support</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
