import React, { useState, useMemo } from 'react';
import { AlertTriangle, Shield, Clock, Server, Users, DollarSign, CheckCircle, XCircle, ChevronDown, ChevronUp } from 'lucide-react';

const PQCMigrationDashboard = () => {
  const [selectedPhase, setSelectedPhase] = useState(null);
  const [orgSize, setOrgSize] = useState('medium');
  const [dataRetention, setDataRetention] = useState(10);
  const [migrationYears, setMigrationYears] = useState(5);
  const [isStateTarget, setIsStateTarget] = useState(false);
  const [expandedSection, setExpandedSection] = useState('risk');

  // Risk calculation
  const riskCalculation = useMemo(() => {
    const qDay = isStateTarget ? 2028 : 2030;
    const currentYear = 2025;
    const Z = Math.max(qDay - currentYear, 0.1);
    const hndlExposure = 2;
    const urgency = (dataRetention + migrationYears + hndlExposure) / Z;
    
    let riskLevel, color, recommendation;
    if (urgency > 1.5) {
      riskLevel = 'CRITICAL';
      color = '#dc2626';
      recommendation = 'EMERGENCY: Begin migration immediately. Already behind schedule.';
    } else if (urgency > 1.0) {
      riskLevel = 'HIGH';
      color = '#ea580c';
      recommendation = 'URGENT: Migration must start this quarter to meet deadline.';
    } else if (urgency > 0.7) {
      riskLevel = 'ELEVATED';
      color = '#ca8a04';
      recommendation = 'PRIORITY: Schedule migration planning within 6 months.';
    } else {
      riskLevel = 'MODERATE';
      color = '#16a34a';
      recommendation = 'PLANNED: Include in 12-24 month roadmap.';
    }
    
    return { urgency: urgency.toFixed(3), riskLevel, color, recommendation, Z, qDay };
  }, [dataRetention, migrationYears, isStateTarget]);

  // Budget multipliers
  const budgetMultipliers = {
    small: 0.25,
    medium: 1.0,
    large: 3.5,
    enterprise: 10
  };

  const baseBudget = 1100000; // Medium baseline
  const estimatedBudget = baseBudget * budgetMultipliers[orgSize];

  // Phase data
  const phases = [
    {
      id: 1,
      name: 'Discovery & Inventory',
      timeline: '2025 Q1-Q2',
      duration: '6 months',
      priority: 'CRITICAL',
      status: 'NOT_STARTED',
      deliverables: ['Complete CBOM', 'Asset inventory in CMDB', 'Network crypto annotations'],
      owner: 'CISO / Security Architecture'
    },
    {
      id: 2,
      name: 'Risk Assessment',
      timeline: '2025 Q2-Q3',
      duration: '3 months',
      priority: 'HIGH',
      status: 'NOT_STARTED',
      deliverables: ['Risk-prioritized backlog', 'Business impact analysis', 'Migration timeline'],
      owner: 'Risk Management'
    },
    {
      id: 3,
      name: 'Infrastructure Prep',
      timeline: '2025 Q3 - 2026 Q3',
      duration: '12 months',
      priority: 'HIGH',
      status: 'NOT_STARTED',
      deliverables: ['HSM firmware upgrades', 'PKI PQC chain', 'TLS 1.3 hybrid config'],
      owner: 'Platform Engineering'
    },
    {
      id: 4,
      name: 'Vendor Assessment',
      timeline: '2025 Q2-Q4',
      duration: '6 months',
      priority: 'MEDIUM',
      status: 'NOT_STARTED',
      deliverables: ['Vendor capability matrix', 'Contract amendments', 'Third-party risk updates'],
      owner: 'Vendor Management'
    },
    {
      id: 5,
      name: 'Pilot Deployment',
      timeline: '2026 Q1 - 2027 Q1',
      duration: '12 months',
      priority: 'HIGH',
      status: 'NOT_STARTED',
      deliverables: ['Sandbox environment', 'Performance benchmarks', 'Rollback procedures'],
      owner: 'Security Engineering'
    },
    {
      id: 6,
      name: 'Production Rollout',
      timeline: '2027 - 2030',
      duration: '36 months',
      priority: 'CRITICAL',
      status: 'NOT_STARTED',
      deliverables: ['Tier 1-3 migrations', 'Legacy remediation', 'Zero classical by 2030'],
      owner: 'Engineering / Operations'
    }
  ];

  // HSM comparison data
  const hsmVendors = [
    { vendor: 'Thales', model: 'Luna Network HSM 7', fips: '140-3 L3', cost: 50000, pqc: ['ML-KEM', 'ML-DSA', 'SLH-DSA'] },
    { vendor: 'Utimaco', model: 'u.trust GP Se-Series', fips: '140-2 L4', cost: 45000, pqc: ['ML-KEM', 'ML-DSA', 'XMSS', 'LMS'] },
    { vendor: 'Entrust', model: 'nShield HSM', fips: '140-2 L3', cost: 55000, pqc: ['ML-KEM', 'ML-DSA'] },
    { vendor: 'Securosys', model: 'Primus CyberVault X2', fips: '140-2 L3', cost: 60000, pqc: ['ML-KEM-768/1024', 'ML-DSA-65/87'] },
    { vendor: 'Eviden', model: 'Trustway Proteccio', fips: 'ANSSI Highest', cost: 70000, pqc: ['ML-KEM', 'ML-DSA', 'SLH-DSA'] }
  ];

  // Compliance deadlines
  const complianceItems = [
    { standard: 'NIST IR 8547', deadline: '2030-01-01', description: 'RSA, ECDSA deprecated', critical: true },
    { standard: 'NIST IR 8547', deadline: '2035-01-01', description: 'All QV algorithms disallowed', critical: true },
    { standard: 'CISA', deadline: '2025-12-31', description: 'Annual CBOM reporting', critical: false },
    { standard: 'PCI DSS 4.0', deadline: '2025-03-31', description: 'Strong cryptography', critical: false }
  ];

  const priorityColors = {
    CRITICAL: '#dc2626',
    HIGH: '#ea580c',
    MEDIUM: '#ca8a04',
    LOW: '#16a34a'
  };

  const toggleSection = (section) => {
    setExpandedSection(expandedSection === section ? null : section);
  };

  return (
    <div className="min-h-screen bg-slate-900 text-white p-6">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-cyan-400 mb-2">
          Corporate PQC Migration Dashboard
        </h1>
        <p className="text-slate-400">
          Enterprise Post-Quantum Cryptography Readiness Framework
        </p>
      </div>

      {/* Risk Calculator Section */}
      <div className="mb-6">
        <button
          onClick={() => toggleSection('risk')}
          className="w-full flex items-center justify-between bg-slate-800 p-4 rounded-lg hover:bg-slate-750"
        >
          <div className="flex items-center gap-3">
            <AlertTriangle className="text-amber-400" size={24} />
            <span className="text-xl font-semibold">Quantum Threat Risk Calculator</span>
          </div>
          {expandedSection === 'risk' ? <ChevronUp /> : <ChevronDown />}
        </button>
        
        {expandedSection === 'risk' && (
          <div className="bg-slate-800 p-6 rounded-b-lg border-t border-slate-700">
            {/* Risk Equation */}
            <div className="bg-slate-900 p-4 rounded-lg mb-6 font-mono text-center">
              <div className="text-cyan-400 mb-2">Migration Urgency Equation:</div>
              <div className="text-xl">
                (X + Y + H) / Z = ({dataRetention} + {migrationYears} + 2) / {riskCalculation.Z} = <span style={{ color: riskCalculation.color }}>{riskCalculation.urgency}</span>
              </div>
              <div className="text-sm text-slate-400 mt-2">
                Where: X=Data Retention, Y=Migration Duration, H=HNDL Exposure, Z=Years to Q-Day
              </div>
            </div>

            {/* Input Controls */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
              <div>
                <label className="block text-sm text-slate-400 mb-1">Organization Size</label>
                <select
                  value={orgSize}
                  onChange={(e) => setOrgSize(e.target.value)}
                  className="w-full bg-slate-700 rounded px-3 py-2 text-white"
                >
                  <option value="small">Small (&lt;500)</option>
                  <option value="medium">Medium (500-5K)</option>
                  <option value="large">Large (5K-25K)</option>
                  <option value="enterprise">Enterprise (&gt;25K)</option>
                </select>
              </div>
              <div>
                <label className="block text-sm text-slate-400 mb-1">Data Retention (years)</label>
                <input
                  type="range"
                  min="1"
                  max="25"
                  value={dataRetention}
                  onChange={(e) => setDataRetention(parseInt(e.target.value))}
                  className="w-full"
                />
                <div className="text-center text-cyan-400">{dataRetention} years</div>
              </div>
              <div>
                <label className="block text-sm text-slate-400 mb-1">Migration Duration (years)</label>
                <input
                  type="range"
                  min="1"
                  max="10"
                  value={migrationYears}
                  onChange={(e) => setMigrationYears(parseInt(e.target.value))}
                  className="w-full"
                />
                <div className="text-center text-cyan-400">{migrationYears} years</div>
              </div>
              <div>
                <label className="block text-sm text-slate-400 mb-1">State Actor Target?</label>
                <button
                  onClick={() => setIsStateTarget(!isStateTarget)}
                  className={`w-full py-2 rounded ${isStateTarget ? 'bg-red-600' : 'bg-slate-600'}`}
                >
                  {isStateTarget ? 'YES (Q-Day 2028)' : 'NO (Q-Day 2030)'}
                </button>
              </div>
            </div>

            {/* Risk Result */}
            <div 
              className="p-4 rounded-lg text-center"
              style={{ backgroundColor: `${riskCalculation.color}22`, border: `2px solid ${riskCalculation.color}` }}
            >
              <div className="text-2xl font-bold mb-2" style={{ color: riskCalculation.color }}>
                {riskCalculation.riskLevel}
              </div>
              <div className="text-slate-300">{riskCalculation.recommendation}</div>
            </div>
          </div>
        )}
      </div>

      {/* Budget Overview Section */}
      <div className="mb-6">
        <button
          onClick={() => toggleSection('budget')}
          className="w-full flex items-center justify-between bg-slate-800 p-4 rounded-lg hover:bg-slate-750"
        >
          <div className="flex items-center gap-3">
            <DollarSign className="text-green-400" size={24} />
            <span className="text-xl font-semibold">Budget & Resource Estimates</span>
          </div>
          {expandedSection === 'budget' ? <ChevronUp /> : <ChevronDown />}
        </button>
        
        {expandedSection === 'budget' && (
          <div className="bg-slate-800 p-6 rounded-b-lg border-t border-slate-700">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="bg-slate-900 p-4 rounded-lg text-center">
                <DollarSign className="mx-auto mb-2 text-green-400" size={32} />
                <div className="text-sm text-slate-400">Estimated 5-Year Budget</div>
                <div className="text-2xl font-bold text-green-400">
                  ${(estimatedBudget / 1000000).toFixed(1)}M
                </div>
              </div>
              <div className="bg-slate-900 p-4 rounded-lg text-center">
                <Users className="mx-auto mb-2 text-blue-400" size={32} />
                <div className="text-sm text-slate-400">Peak FTE Requirement</div>
                <div className="text-2xl font-bold text-blue-400">
                  {orgSize === 'small' ? '2' : orgSize === 'medium' ? '5' : orgSize === 'large' ? '15' : '30+'}
                </div>
              </div>
              <div className="bg-slate-900 p-4 rounded-lg text-center">
                <Clock className="mx-auto mb-2 text-amber-400" size={32} />
                <div className="text-sm text-slate-400">Migration Timeline</div>
                <div className="text-2xl font-bold text-amber-400">
                  2025-2030
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Migration Phases Section */}
      <div className="mb-6">
        <button
          onClick={() => toggleSection('phases')}
          className="w-full flex items-center justify-between bg-slate-800 p-4 rounded-lg hover:bg-slate-750"
        >
          <div className="flex items-center gap-3">
            <Clock className="text-blue-400" size={24} />
            <span className="text-xl font-semibold">Migration Phases</span>
          </div>
          {expandedSection === 'phases' ? <ChevronUp /> : <ChevronDown />}
        </button>
        
        {expandedSection === 'phases' && (
          <div className="bg-slate-800 p-6 rounded-b-lg border-t border-slate-700">
            <div className="space-y-3">
              {phases.map((phase) => (
                <div
                  key={phase.id}
                  className={`bg-slate-900 p-4 rounded-lg cursor-pointer transition-all ${
                    selectedPhase === phase.id ? 'ring-2 ring-cyan-400' : ''
                  }`}
                  onClick={() => setSelectedPhase(selectedPhase === phase.id ? null : phase.id)}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div 
                        className="w-3 h-3 rounded-full"
                        style={{ backgroundColor: priorityColors[phase.priority] }}
                      />
                      <span className="font-semibold">{phase.name}</span>
                    </div>
                    <div className="flex items-center gap-4">
                      <span className="text-slate-400 text-sm">{phase.timeline}</span>
                      <span 
                        className="px-2 py-1 rounded text-xs"
                        style={{ 
                          backgroundColor: `${priorityColors[phase.priority]}22`,
                          color: priorityColors[phase.priority]
                        }}
                      >
                        {phase.priority}
                      </span>
                    </div>
                  </div>
                  
                  {selectedPhase === phase.id && (
                    <div className="mt-4 pt-4 border-t border-slate-700">
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <div className="text-sm text-slate-400 mb-1">Duration</div>
                          <div className="text-cyan-400">{phase.duration}</div>
                        </div>
                        <div>
                          <div className="text-sm text-slate-400 mb-1">Owner</div>
                          <div className="text-cyan-400">{phase.owner}</div>
                        </div>
                      </div>
                      <div className="mt-3">
                        <div className="text-sm text-slate-400 mb-2">Deliverables:</div>
                        <ul className="space-y-1">
                          {phase.deliverables.map((d, i) => (
                            <li key={i} className="flex items-center gap-2 text-sm">
                              <CheckCircle size={14} className="text-green-400" />
                              {d}
                            </li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* HSM Comparison Section */}
      <div className="mb-6">
        <button
          onClick={() => toggleSection('hsm')}
          className="w-full flex items-center justify-between bg-slate-800 p-4 rounded-lg hover:bg-slate-750"
        >
          <div className="flex items-center gap-3">
            <Server className="text-purple-400" size={24} />
            <span className="text-xl font-semibold">HSM Vendor Comparison</span>
          </div>
          {expandedSection === 'hsm' ? <ChevronUp /> : <ChevronDown />}
        </button>
        
        {expandedSection === 'hsm' && (
          <div className="bg-slate-800 p-6 rounded-b-lg border-t border-slate-700 overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-slate-400 border-b border-slate-700">
                  <th className="pb-3">Vendor</th>
                  <th className="pb-3">Model</th>
                  <th className="pb-3">FIPS</th>
                  <th className="pb-3">PQC Algorithms</th>
                  <th className="pb-3">Est. Cost</th>
                </tr>
              </thead>
              <tbody>
                {hsmVendors.map((hsm, i) => (
                  <tr key={i} className="border-b border-slate-700/50">
                    <td className="py-3 font-semibold text-cyan-400">{hsm.vendor}</td>
                    <td className="py-3">{hsm.model}</td>
                    <td className="py-3">{hsm.fips}</td>
                    <td className="py-3">
                      <div className="flex flex-wrap gap-1">
                        {hsm.pqc.map((alg, j) => (
                          <span key={j} className="px-2 py-0.5 bg-purple-900/50 rounded text-xs text-purple-300">
                            {alg}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="py-3 text-green-400">${hsm.cost.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Compliance Section */}
      <div className="mb-6">
        <button
          onClick={() => toggleSection('compliance')}
          className="w-full flex items-center justify-between bg-slate-800 p-4 rounded-lg hover:bg-slate-750"
        >
          <div className="flex items-center gap-3">
            <Shield className="text-amber-400" size={24} />
            <span className="text-xl font-semibold">Compliance Deadlines</span>
          </div>
          {expandedSection === 'compliance' ? <ChevronUp /> : <ChevronDown />}
        </button>
        
        {expandedSection === 'compliance' && (
          <div className="bg-slate-800 p-6 rounded-b-lg border-t border-slate-700">
            <div className="space-y-3">
              {complianceItems.map((item, i) => (
                <div 
                  key={i}
                  className={`flex items-center justify-between p-3 rounded-lg ${
                    item.critical ? 'bg-red-900/30' : 'bg-slate-900'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    {item.critical ? (
                      <AlertTriangle className="text-red-400" size={20} />
                    ) : (
                      <Clock className="text-slate-400" size={20} />
                    )}
                    <div>
                      <div className="font-semibold">{item.standard}</div>
                      <div className="text-sm text-slate-400">{item.description}</div>
                    </div>
                  </div>
                  <div className={`font-mono ${item.critical ? 'text-red-400' : 'text-slate-300'}`}>
                    {item.deadline}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="mt-8 text-center text-slate-500 text-sm">
        <p>Corporate PQC Migration Framework v1.0</p>
        <p>NeuroProgressive AI Evolution Strategy | Trade Momentum LLC</p>
      </div>
    </div>
  );
};

export default PQCMigrationDashboard;
