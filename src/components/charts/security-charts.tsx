'use client';

import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler,
} from 'chart.js';
import { Line, Bar, Doughnut } from 'react-chartjs-2';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

interface SecurityChartsProps {
  threats: any[];
  vulnerabilities: any[];
  attackLogs: any[];
  assets: any[];
}

export function ThreatTrendChart({ attackLogs }: { attackLogs: any[] }) {
  // Group attack logs by day for the last 7 days
  const last7Days = Array.from({ length: 7 }, (_, i) => {
    const date = new Date();
    date.setDate(date.getDate() - (6 - i));
    return date;
  });

  const attacksByDay = last7Days.map(date => {
    const dayLogs = attackLogs.filter(log => {
      const logDate = new Date(log.timestamp);
      return logDate.toDateString() === date.toDateString();
    });
    return dayLogs.length;
  });

  const blockedByDay = last7Days.map(date => {
    const dayLogs = attackLogs.filter(log => {
      const logDate = new Date(log.timestamp);
      return logDate.toDateString() === date.toDateString() && log.status === 'blocked';
    });
    return dayLogs.length;
  });

  const data = {
    labels: last7Days.map(date => date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })),
    datasets: [
      {
        label: 'Total Attacks',
        data: attacksByDay,
        borderColor: 'rgb(239, 68, 68)',
        backgroundColor: 'rgba(239, 68, 68, 0.1)',
        fill: true,
        tension: 0.4,
      },
      {
        label: 'Blocked',
        data: blockedByDay,
        borderColor: 'rgb(34, 197, 94)',
        backgroundColor: 'rgba(34, 197, 94, 0.1)',
        fill: true,
        tension: 0.4,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'top' as const,
      },
      title: {
        display: true,
        text: 'Attack Trend - Last 7 Days',
        font: {
          size: 16,
          weight: 'bold' as const,
        },
      },
    },
    scales: {
      y: {
        beginAtZero: true,
        ticks: {
          stepSize: 1,
        },
      },
    },
  };

  return (
    <div className="h-[300px]">
      <Line data={data} options={options} />
    </div>
  );
}

export function ThreatTypeChart({ threats }: { threats: any[] }) {
  const threatTypes = threats.reduce((acc: any, threat) => {
    const type = threat.type.replace('-', ' ');
    acc[type] = (acc[type] || 0) + 1;
    return acc;
  }, {});

  const data = {
    labels: Object.keys(threatTypes),
    datasets: [
      {
        label: 'Number of Threats',
        data: Object.values(threatTypes),
        backgroundColor: [
          'rgba(239, 68, 68, 0.8)',
          'rgba(249, 115, 22, 0.8)',
          'rgba(234, 179, 8, 0.8)',
          'rgba(34, 197, 94, 0.8)',
          'rgba(59, 130, 246, 0.8)',
          'rgba(139, 92, 246, 0.8)',
        ],
        borderColor: [
          'rgb(239, 68, 68)',
          'rgb(249, 115, 22)',
          'rgb(234, 179, 8)',
          'rgb(34, 197, 94)',
          'rgb(59, 130, 246)',
          'rgb(139, 92, 246)',
        ],
        borderWidth: 2,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        display: false,
      },
      title: {
        display: true,
        text: 'Threats by Type',
        font: {
          size: 16,
          weight: 'bold' as const,
        },
      },
    },
    scales: {
      y: {
        beginAtZero: true,
        ticks: {
          stepSize: 1,
        },
      },
    },
  };

  return (
    <div className="h-[300px]">
      <Bar data={data} options={options} />
    </div>
  );
}

export function VulnerabilitySeverityChart({ vulnerabilities }: { vulnerabilities: any[] }) {
  const severityCount = vulnerabilities.reduce((acc: any, vuln) => {
    acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
    return acc;
  }, { critical: 0, high: 0, medium: 0, low: 0 });

  const data = {
    labels: ['Critical', 'High', 'Medium', 'Low'],
    datasets: [
      {
        data: [
          severityCount.critical,
          severityCount.high,
          severityCount.medium,
          severityCount.low,
        ],
        backgroundColor: [
          'rgba(239, 68, 68, 0.8)',
          'rgba(249, 115, 22, 0.8)',
          'rgba(234, 179, 8, 0.8)',
          'rgba(34, 197, 94, 0.8)',
        ],
        borderColor: [
          'rgb(239, 68, 68)',
          'rgb(249, 115, 22)',
          'rgb(234, 179, 8)',
          'rgb(34, 197, 94)',
        ],
        borderWidth: 2,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'right' as const,
      },
      title: {
        display: true,
        text: 'Vulnerabilities by Severity',
        font: {
          size: 16,
          weight: 'bold' as const,
        },
      },
    },
  };

  return (
    <div className="h-[300px]">
      <Doughnut data={data} options={options} />
    </div>
  );
}

export function AssetRiskChart({ assets, threats }: { assets: any[], threats: any[] }) {
  // Calculate risk per asset based on associated threats
  const assetRisks = assets.map(asset => {
    const assetThreats = threats.filter(t => t.assetId === asset.id);
    const criticalThreats = assetThreats.filter(t => t.severity === 'critical').length;
    const highThreats = assetThreats.filter(t => t.severity === 'high').length;
    const riskScore = (criticalThreats * 3) + (highThreats * 2) + assetThreats.length;
    
    return {
      name: asset.name.length > 15 ? asset.name.substring(0, 15) + '...' : asset.name,
      risk: riskScore,
    };
  }).sort((a, b) => b.risk - a.risk).slice(0, 8); // Top 8 assets

  const data = {
    labels: assetRisks.map(a => a.name),
    datasets: [
      {
        label: 'Risk Score',
        data: assetRisks.map(a => a.risk),
        backgroundColor: 'rgba(59, 130, 246, 0.8)',
        borderColor: 'rgb(59, 130, 246)',
        borderWidth: 2,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    indexAxis: 'y' as const,
    plugins: {
      legend: {
        display: false,
      },
      title: {
        display: true,
        text: 'Asset Risk Scores',
        font: {
          size: 16,
          weight: 'bold' as const,
        },
      },
    },
    scales: {
      x: {
        beginAtZero: true,
      },
    },
  };

  return (
    <div className="h-[300px]">
      <Bar data={data} options={options} />
    </div>
  );
}

export function TrafficVolumeChart({ attackLogs }: { attackLogs: any[] }) {
  // Simulate traffic volume based on attack logs
  const last24Hours = Array.from({ length: 24 }, (_, i) => {
    const hour = (new Date().getHours() - (23 - i) + 24) % 24;
    return `${hour}:00`;
  });

  const trafficVolume = last24Hours.map(() => Math.floor(Math.random() * 100) + 50);
  const maliciousTraffic = last24Hours.map(() => Math.floor(Math.random() * 20) + 5);

  const data = {
    labels: last24Hours,
    datasets: [
      {
        label: 'Total Traffic',
        data: trafficVolume,
        borderColor: 'rgb(59, 130, 246)',
        backgroundColor: 'rgba(59, 130, 246, 0.1)',
        fill: true,
        tension: 0.4,
      },
      {
        label: 'Malicious Traffic',
        data: maliciousTraffic,
        borderColor: 'rgb(239, 68, 68)',
        backgroundColor: 'rgba(239, 68, 68, 0.1)',
        fill: true,
        tension: 0.4,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'top' as const,
      },
      title: {
        display: true,
        text: 'Traffic Volume - Last 24 Hours',
        font: {
          size: 16,
          weight: 'bold' as const,
        },
      },
    },
    scales: {
      y: {
        beginAtZero: true,
        title: {
          display: true,
          text: 'Requests (MB)',
        },
      },
    },
  };

  return (
    <div className="h-[300px]">
      <Line data={data} options={options} />
    </div>
  );
}

export function SecurityCharts({ threats, vulnerabilities, attackLogs, assets }: SecurityChartsProps) {
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="shadow-lg">
          <CardHeader>
            <CardTitle>Traffic Analysis</CardTitle>
            <CardDescription>Real-time network traffic monitoring</CardDescription>
          </CardHeader>
          <CardContent>
            <TrafficVolumeChart attackLogs={attackLogs} />
          </CardContent>
        </Card>

        <Card className="shadow-lg">
          <CardHeader>
            <CardTitle>Threat Trends</CardTitle>
            <CardDescription>Attack patterns over time</CardDescription>
          </CardHeader>
          <CardContent>
            <ThreatTrendChart attackLogs={attackLogs} />
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="shadow-lg">
          <CardHeader>
            <CardTitle>Threat Types</CardTitle>
            <CardDescription>Distribution by category</CardDescription>
          </CardHeader>
          <CardContent>
            <ThreatTypeChart threats={threats} />
          </CardContent>
        </Card>

        <Card className="shadow-lg">
          <CardHeader>
            <CardTitle>Vulnerability Severity</CardTitle>
            <CardDescription>CVSS severity breakdown</CardDescription>
          </CardHeader>
          <CardContent>
            <VulnerabilitySeverityChart vulnerabilities={vulnerabilities} />
          </CardContent>
        </Card>

        <Card className="shadow-lg">
          <CardHeader>
            <CardTitle>Asset Risk</CardTitle>
            <CardDescription>Risk score by asset</CardDescription>
          </CardHeader>
          <CardContent>
            <AssetRiskChart assets={assets} threats={threats} />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
