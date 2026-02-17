'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  Shield,
  Activity,
  AlertTriangle,
  Database,
  Bell,
  User,
  LogOut,
  Search,
  Filter,
  Download,
  RefreshCw,
  TrendingUp,
  TrendingDown,
  AlertCircle,
  CheckCircle,
  XCircle,
  Clock,
  MapPin,
  Server,
  Monitor,
  Lock,
  Eye,
  FileText,
  BarChart3,
  Target,
  Zap,
  Globe,
  Network,
  ListTodo,
  File,
  ShieldCheck,
  PieChart,
  Plus,
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { SecurityCharts } from '@/components/charts/security-charts';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';

interface Threat {
  id: string;
  name: string;
  type: string;
  severity: string;
  status: string;
  description: string;
  sourceIp: string | null;
  targetIp: string | null;
  sourceCountry: string | null;
  createdAt: string;
}

interface Vulnerability {
  id: string;
  cveId: string;
  title: string;
  severity: string;
  cvssScore: number | null;
  publishedDate: string;
  exploitStatus: string;
  solution: string | null;
}

interface Asset {
  id: string;
  name: string;
  type: string;
  ipAddress: string | null;
  status: string;
  criticality: string;
  location: string | null;
}

interface AlertItem {
  id: string;
  type: string;
  severity: string;
  title: string;
  message: string;
  alertType: string;
  createdAt: string;
  status?: string;
}

interface AttackLog {
  id: string;
  timestamp: string;
  attackType: string;
  severity: string;
  sourceIp: string | null;
  sourcePort: number | null;
  destinationIp: string | null;
  destinationPort: number | null;
  protocol: string | null;
  status: string;
  description: string;
  mitigated: boolean;
}

interface Mitigation {
  id: string;
  title: string;
  description: string;
  type: string;
  priority: string;
  status: string;
  estimatedEffort: string | null;
  dueDate: string | null;
  completedAt: string | null;
  createdAt: string;
}

interface Report {
  id: string;
  title: string;
  type: string;
  summary: string;
  threatCount: number;
  vulnerabilityCount: number;
  riskScore: number;
  generatedAt: string;
}

export default function DashboardPage() {
  const router = useRouter();
  const [user, setUser] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [threats, setThreats] = useState<Threat[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [attackLogs, setAttackLogs] = useState<AttackLog[]>([]);
  const [mitigations, setMitigations] = useState<Mitigation[]>([]);
  const [riskScore, setRiskScore] = useState(0);
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    // Check authentication
    const userData = localStorage.getItem('medisentinel_user');
    const token = localStorage.getItem('medisentinel_token');

    if (!userData || !token) {
      router.push('/');
      return;
    }

    setUser(JSON.parse(userData));
    fetchData();
    startThreatSimulation();
  }, [router]);

  const fetchData = async () => {
    try {
      const [threatsRes, vulnsRes, assetsRes, alertsRes, riskRes, attackLogsRes, mitigationsRes] = await Promise.all([
        fetch('/api/threats'),
        fetch('/api/vulnerabilities'),
        fetch('/api/assets'),
        fetch('/api/alerts'),
        fetch('/api/risk-score'),
        fetch('/api/attack-logs'),
        fetch('/api/mitigations'),
      ]);

      const [threatsData, vulnsData, assetsData, alertsData, riskData, attackLogsData, mitigationsData] = await Promise.all([
        threatsRes.json(),
        vulnsRes.json(),
        assetsRes.json(),
        alertsRes.json(),
        riskRes.json(),
        attackLogsRes.json(),
        mitigationsRes.json(),
      ]);

      setThreats(threatsData.threats || []);
      setVulnerabilities(vulnsData.vulnerabilities || []);
      setAssets(assetsData.assets || []);
      setAlerts(alertsData.alerts || []);
      setAttackLogs(attackLogsData.attackLogs || []);
      setMitigations(mitigationsData.mitigations || []);
      setRiskScore(riskData.score || 72);
    } catch (error) {
      console.error('Error fetching data:', error);
    } finally {
      setLoading(false);
    }
  };

  const startThreatSimulation = () => {
    // Simulate real-time threat updates every 10 seconds
    const interval = setInterval(async () => {
      try {
        const res = await fetch('/api/simulate-threat', { method: 'POST' });
        if (res.ok) {
          await fetchData();
        }
      } catch (error) {
        console.error('Simulation error:', error);
      }
    }, 10000);

    return () => clearInterval(interval);
  };

  const handleLogout = () => {
    localStorage.removeItem('medisentinel_user');
    localStorage.removeItem('medisentinel_token');
    router.push('/');
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'bg-red-100 text-red-800 border-red-200';
      case 'high':
        return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'medium':
        return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'low':
        return 'bg-green-100 text-green-800 border-green-200';
      default:
        return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status.toLowerCase()) {
      case 'active':
        return <AlertCircle className="w-4 h-4 text-red-500" />;
      case 'mitigated':
      case 'completed':
        return <CheckCircle className="w-4 h-4 text-green-500" />;
      case 'investigating':
      case 'in-progress':
        return <Clock className="w-4 h-4 text-yellow-500" />;
      default:
        return <XCircle className="w-4 h-4 text-gray-500" />;
    }
  };

  const getAssetIcon = (type: string) => {
    switch (type.toLowerCase()) {
      case 'server':
        return <Server className="w-4 h-4" />;
      case 'workstation':
        return <Monitor className="w-4 h-4" />;
      case 'router':
        return <Network className="w-4 h-4" />;
      case 'firewall':
        return <Shield className="w-4 h-4" />;
      default:
        return <Database className="w-4 h-4" />;
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 to-blue-50">
        <div className="text-center">
          <RefreshCw className="w-12 h-12 text-blue-600 animate-spin mx-auto mb-4" />
          <p className="text-gray-600">Loading Medisentinel Dashboard...</p>
        </div>
      </div>
    );
  }

  const activeThreats = threats.filter(t => t.status === 'active').length;
  const criticalVulns = vulnerabilities.filter(v => v.severity === 'critical').length;
  const unreadAlerts = alerts.filter(a => a.status === 'unread').length;

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50">
      {/* Header */}
      <header className="bg-white border-b border-gray-200 shadow-sm sticky top-0 z-50">
        <div className="container mx-auto px-4 py-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-blue-600 rounded-xl flex items-center justify-center">
                <Shield className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-gray-900">Medisentinel</h1>
                <p className="text-xs text-gray-500">Threat Intelligence</p>
              </div>
            </div>

            <div className="flex items-center gap-4">
              <div className="relative">
                <Bell className="w-5 h-5 text-gray-600 cursor-pointer hover:text-blue-600" />
                {unreadAlerts > 0 && (
                  <span className="absolute -top-1 -right-1 w-4 h-4 bg-red-500 text-white text-xs rounded-full flex items-center justify-center">
                    {unreadAlerts}
                  </span>
                )}
              </div>
              <Separator orientation="vertical" className="h-6" />
              <div className="flex items-center gap-2">
                <div className="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center">
                  <User className="w-4 h-4 text-blue-600" />
                </div>
                <div className="hidden md:block">
                  <p className="text-sm font-medium text-gray-900">{user?.name}</p>
                  <p className="text-xs text-gray-500 capitalize">{user?.role}</p>
                </div>
              </div>
              <Button
                variant="ghost"
                size="sm"
                onClick={handleLogout}
                className="text-gray-600 hover:text-red-600"
              >
                <LogOut className="w-4 h-4" />
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-6">
        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          <Card className="border-l-4 border-l-red-500 shadow-lg hover:shadow-xl transition-shadow">
            <CardHeader className="pb-3">
              <CardDescription className="text-xs font-medium text-gray-600 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-red-500" />
                Active Threats
              </CardDescription>
              <CardTitle className="text-3xl font-bold text-red-600">{activeThreats}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-center gap-2 text-sm">
                <TrendingUp className="w-4 h-4 text-red-500" />
                <span className="text-gray-600">Requires immediate attention</span>
              </div>
            </CardContent>
          </Card>

          <Card className="border-l-4 border-l-orange-500 shadow-lg hover:shadow-xl transition-shadow">
            <CardHeader className="pb-3">
              <CardDescription className="text-xs font-medium text-gray-600 flex items-center gap-2">
                <AlertCircle className="w-4 h-4 text-orange-500" />
                Critical Vulnerabilities
              </CardDescription>
              <CardTitle className="text-3xl font-bold text-orange-600">{criticalVulns}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-center gap-2 text-sm">
                <Database className="w-4 h-4 text-orange-500" />
                <span className="text-gray-600">CVEs requiring patches</span>
              </div>
            </CardContent>
          </Card>

          <Card className="border-l-4 border-l-blue-500 shadow-lg hover:shadow-xl transition-shadow">
            <CardHeader className="pb-3">
              <CardDescription className="text-xs font-medium text-gray-600 flex items-center gap-2">
                <Target className="w-4 h-4 text-blue-500" />
                Risk Score
              </CardDescription>
              <CardTitle className="text-3xl font-bold text-blue-600">{riskScore}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-center gap-2 text-sm">
                {riskScore > 70 ? (
                  <>
                    <TrendingUp className="w-4 h-4 text-red-500" />
                    <span className="text-red-600">High risk level</span>
                  </>
                ) : (
                  <>
                    <TrendingDown className="w-4 h-4 text-green-500" />
                    <span className="text-green-600">Controlled risk</span>
                  </>
                )}
              </div>
            </CardContent>
          </Card>

          <Card className="border-l-4 border-l-green-500 shadow-lg hover:shadow-xl transition-shadow">
            <CardHeader className="pb-3">
              <CardDescription className="text-xs font-medium text-gray-600 flex items-center gap-2">
                <Server className="w-4 h-4 text-green-500" />
                Protected Assets
              </CardDescription>
              <CardTitle className="text-3xl font-bold text-green-600">{assets.length}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-center gap-2 text-sm">
                <Shield className="w-4 h-4 text-green-500" />
                <span className="text-gray-600">Hospital infrastructure</span>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Main Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          <TabsList className="bg-white shadow-sm border border-gray-200 p-1 h-auto">
            <TabsTrigger value="overview" className="data-[state=active]:bg-blue-600 data-[state=active]:text-white">
              <Activity className="w-4 h-4 mr-2" />
              Overview
            </TabsTrigger>
            <TabsTrigger value="threats" className="data-[state=active]:bg-blue-600 data-[state=active]:text-white">
              <AlertTriangle className="w-4 h-4 mr-2" />
              Threats
            </TabsTrigger>
            <TabsTrigger value="vulnerabilities" className="data-[state=active]:bg-blue-600 data-[state=active]:text-white">
              <Database className="w-4 h-4 mr-2" />
              Vulnerabilities
            </TabsTrigger>
            <TabsTrigger value="assets" className="data-[state=active]:bg-blue-600 data-[state=active]:text-white">
              <Server className="w-4 h-4 mr-2" />
              Assets
            </TabsTrigger>
            <TabsTrigger value="attack-logs" className="data-[state=active]:bg-blue-600 data-[state=active]:text-white">
              <FileText className="w-4 h-4 mr-2" />
              Attack Logs
            </TabsTrigger>
            <TabsTrigger value="mitigations" className="data-[state=active]:bg-blue-600 data-[state=active]:text-white">
              <ShieldCheck className="w-4 h-4 mr-2" />
              Mitigations
            </TabsTrigger>
            <TabsTrigger value="charts" className="data-[state=active]:bg-blue-600 data-[state=active]:text-white">
              <BarChart3 className="w-4 h-4 mr-2" />
              Analytics
            </TabsTrigger>
            <TabsTrigger value="reports" className="data-[state=active]:bg-blue-600 data-[state=active]:text-white">
              <File className="w-4 h-4 mr-2" />
              Reports
            </TabsTrigger>
            <TabsTrigger value="alerts" className="data-[state=active]:bg-blue-600 data-[state=active]:text-white">
              <Bell className="w-4 h-4 mr-2" />
              Alerts
            </TabsTrigger>
          </TabsList>

          {/* Overview Tab */}
          <TabsContent value="overview" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Recent Threats */}
              <Card className="shadow-lg lg:col-span-2">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Zap className="w-5 h-5 text-yellow-500" />
                    Recent Threats
                  </CardTitle>
                  <CardDescription>Latest detected security threats</CardDescription>
                </CardHeader>
                <CardContent>
                  <ScrollArea className="h-[400px]">
                    <div className="space-y-3">
                      {threats.slice(0, 5).map((threat) => (
                        <div
                          key={threat.id}
                          className="p-4 bg-gray-50 rounded-lg border border-gray-200 hover:border-blue-300 transition-colors"
                        >
                          <div className="flex items-start justify-between mb-2">
                            <div className="flex items-center gap-2">
                              {getStatusIcon(threat.status)}
                              <h4 className="font-semibold text-sm">{threat.name}</h4>
                            </div>
                            <Badge className={getSeverityColor(threat.severity)}>
                              {threat.severity}
                            </Badge>
                          </div>
                          <p className="text-sm text-gray-600 mb-2">{threat.description}</p>
                          <div className="flex items-center gap-4 text-xs text-gray-500">
                            <span className="flex items-center gap-1">
                              <Globe className="w-3 h-3" />
                              {threat.sourceCountry || 'Unknown'}
                            </span>
                            <span className="flex items-center gap-1">
                              <Clock className="w-3 h-3" />
                              {new Date(threat.createdAt).toLocaleString()}
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                </CardContent>
              </Card>

              {/* Alerts Panel */}
              <Card className="shadow-lg">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Bell className="w-5 h-5 text-blue-500" />
                    Alerts
                  </CardTitle>
                  <CardDescription>Recent notifications</CardDescription>
                </CardHeader>
                <CardContent>
                  <ScrollArea className="h-[400px]">
                    <div className="space-y-3">
                      {alerts.slice(0, 5).map((alert) => (
                        <div
                          key={alert.id}
                          className={`p-3 rounded-lg border ${
                            alert.severity === 'critical'
                              ? 'bg-red-50 border-red-200'
                              : alert.severity === 'high'
                              ? 'bg-orange-50 border-orange-200'
                              : 'bg-blue-50 border-blue-200'
                          }`}
                        >
                          <div className="flex items-start gap-2">
                            {alert.type === 'email' && <FileText className="w-4 h-4 text-gray-500 mt-0.5" />}
                            {alert.type === 'sms' && <Bell className="w-4 h-4 text-gray-500 mt-0.5" />}
                            {alert.type === 'dashboard' && <AlertCircle className="w-4 h-4 text-gray-500 mt-0.5" />}
                            <div className="flex-1 min-w-0">
                              <p className="text-sm font-medium text-gray-900 truncate">{alert.title}</p>
                              <p className="text-xs text-gray-600 mt-1 line-clamp-2">{alert.message}</p>
                              <p className="text-xs text-gray-400 mt-1">
                                {new Date(alert.createdAt).toLocaleString()}
                              </p>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                </CardContent>
              </Card>
            </div>

            {/* Risk Overview */}
            <Card className="shadow-lg">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <BarChart3 className="w-5 h-5 text-purple-500" />
                  Risk Assessment Overview
                </CardTitle>
                <CardDescription>Comprehensive security risk analysis</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  <div className="text-center p-6 bg-gradient-to-br from-red-50 to-orange-50 rounded-xl border border-red-100">
                    <div className="w-16 h-16 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-3">
                      <AlertTriangle className="w-8 h-8 text-red-600" />
                    </div>
                    <h3 className="text-2xl font-bold text-red-600 mb-1">High Risk</h3>
                    <p className="text-sm text-gray-600">Critical assets under attack</p>
                  </div>
                  <div className="text-center p-6 bg-gradient-to-br from-yellow-50 to-amber-50 rounded-xl border border-yellow-100">
                    <div className="w-16 h-16 bg-yellow-100 rounded-full flex items-center justify-center mx-auto mb-3">
                      <AlertCircle className="w-8 h-8 text-yellow-600" />
                    </div>
                    <h3 className="text-2xl font-bold text-yellow-600 mb-1">Medium Risk</h3>
                    <p className="text-sm text-gray-600">Vulnerabilities requiring patches</p>
                  </div>
                  <div className="text-center p-6 bg-gradient-to-br from-green-50 to-emerald-50 rounded-xl border border-green-100">
                    <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-3">
                      <CheckCircle className="w-8 h-8 text-green-600" />
                    </div>
                    <h3 className="text-2xl font-bold text-green-600 mb-1">Controlled</h3>
                    <p className="text-sm text-gray-600">Mitigated threats</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Threats Tab */}
          <TabsContent value="threats">
            <Card className="shadow-lg">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <AlertTriangle className="w-5 h-5 text-red-500" />
                      Detected Threats
                    </CardTitle>
                    <CardDescription>Real-time threat intelligence feed</CardDescription>
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={fetchData}
                    className="flex items-center gap-2"
                  >
                    <RefreshCw className="w-4 h-4" />
                    Refresh
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                <div className="rounded-md border">
                  <Table>
                    <TableHeader>
                      <TableRow className="bg-gray-50">
                        <TableHead>Threat Name</TableHead>
                        <TableHead>Type</TableHead>
                        <TableHead>Severity</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Source IP</TableHead>
                        <TableHead>Country</TableHead>
                        <TableHead>Detected</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {threats.map((threat) => (
                        <TableRow key={threat.id} className="hover:bg-gray-50">
                          <TableCell className="font-medium">{threat.name}</TableCell>
                          <TableCell>
                            <Badge variant="outline" className="capitalize">
                              {threat.type.replace('-', ' ')}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <Badge className={getSeverityColor(threat.severity)}>
                              {threat.severity}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center gap-2">
                              {getStatusIcon(threat.status)}
                              <span className="capitalize">{threat.status}</span>
                            </div>
                          </TableCell>
                          <TableCell className="font-mono text-sm">{threat.sourceIp || '-'}</TableCell>
                          <TableCell>{threat.sourceCountry || '-'}</TableCell>
                          <TableCell className="text-sm text-gray-500">
                            {new Date(threat.createdAt).toLocaleString()}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Vulnerabilities Tab */}
          <TabsContent value="vulnerabilities">
            <Card className="shadow-lg">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <Database className="w-5 h-5 text-orange-500" />
                      CVE / Vulnerability Database
                    </CardTitle>
                    <CardDescription>Known security vulnerabilities in hospital systems</CardDescription>
                  </div>
                  <div className="flex gap-2">
                    <div className="relative">
                      <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                      <Input placeholder="Search CVE..." className="pl-9 w-64" />
                    </div>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="rounded-md border">
                  <Table>
                    <TableHeader>
                      <TableRow className="bg-gray-50">
                        <TableHead>CVE ID</TableHead>
                        <TableHead>Title</TableHead>
                        <TableHead>Severity</TableHead>
                        <TableHead>CVSS Score</TableHead>
                        <TableHead>Exploit Status</TableHead>
                        <TableHead>Solution</TableHead>
                        <TableHead>Published</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {vulnerabilities.map((vuln) => (
                        <TableRow key={vuln.id} className="hover:bg-gray-50">
                          <TableCell className="font-mono font-medium text-blue-600">
                            {vuln.cveId}
                          </TableCell>
                          <TableCell className="max-w-md truncate">{vuln.title}</TableCell>
                          <TableCell>
                            <Badge className={getSeverityColor(vuln.severity)}>
                              {vuln.severity}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <span className="font-semibold">{vuln.cvssScore || 'N/A'}</span>
                          </TableCell>
                          <TableCell>
                            <Badge
                              variant={vuln.exploitStatus === 'active' ? 'destructive' : 'outline'}
                              className="capitalize"
                            >
                              {vuln.exploitStatus}
                            </Badge>
                          </TableCell>
                          <TableCell className="max-w-xs truncate text-sm text-gray-600">
                            {vuln.solution || 'No solution available'}
                          </TableCell>
                          <TableCell className="text-sm text-gray-500">
                            {new Date(vuln.publishedDate).toLocaleDateString()}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Assets Tab */}
          <TabsContent value="assets">
            <Card className="shadow-lg">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <Server className="w-5 h-5 text-blue-500" />
                      Hospital Asset Inventory
                    </CardTitle>
                    <CardDescription>Monitored hospital IT infrastructure</CardDescription>
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={fetchData}
                    className="flex items-center gap-2"
                  >
                    <RefreshCw className="w-4 h-4" />
                    Refresh
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                <div className="rounded-md border">
                  <Table>
                    <TableHeader>
                      <TableRow className="bg-gray-50">
                        <TableHead>Asset Name</TableHead>
                        <TableHead>Type</TableHead>
                        <TableHead>IP Address</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Criticality</TableHead>
                        <TableHead>Location</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {assets.map((asset) => (
                        <TableRow key={asset.id} className="hover:bg-gray-50">
                          <TableCell className="font-medium flex items-center gap-2">
                            {getAssetIcon(asset.type)}
                            {asset.name}
                          </TableCell>
                          <TableCell className="capitalize">{asset.type}</TableCell>
                          <TableCell className="font-mono text-sm">{asset.ipAddress || '-'}</TableCell>
                          <TableCell>
                            <Badge
                              variant={asset.status === 'active' ? 'default' : 'secondary'}
                              className="capitalize"
                            >
                              {asset.status}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <Badge className={getSeverityColor(asset.criticality)}>
                              {asset.criticality}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-sm text-gray-600">{asset.location || '-'}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Attack Logs Tab */}
          <TabsContent value="attack-logs">
            <Card className="shadow-lg">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <FileText className="w-5 h-5 text-indigo-500" />
                      Attack Logs
                    </CardTitle>
                    <CardDescription>Timeline of detected security incidents</CardDescription>
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={fetchData}
                    className="flex items-center gap-2"
                  >
                    <RefreshCw className="w-4 h-4" />
                    Refresh
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-[600px]">
                  <div className="rounded-md border">
                    <Table>
                      <TableHeader>
                        <TableRow className="bg-gray-50 sticky top-0">
                          <TableHead>Timestamp</TableHead>
                          <TableHead>Attack Type</TableHead>
                          <TableHead>Severity</TableHead>
                          <TableHead>Source IP:Port</TableHead>
                          <TableHead>Destination</TableHead>
                          <TableHead>Protocol</TableHead>
                          <TableHead>Status</TableHead>
                          <TableHead>Mitigated</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {attackLogs.map((log) => (
                          <TableRow key={log.id} className="hover:bg-gray-50">
                            <TableCell className="text-sm text-gray-600">
                              {new Date(log.timestamp).toLocaleString()}
                            </TableCell>
                            <TableCell className="font-medium capitalize">{log.attackType}</TableCell>
                            <TableCell>
                              <Badge className={getSeverityColor(log.severity)}>
                                {log.severity}
                              </Badge>
                            </TableCell>
                            <TableCell className="font-mono text-sm">
                              {log.sourceIp ? `${log.sourceIp}:${log.sourcePort || '-'}` : '-'}
                            </TableCell>
                            <TableCell className="font-mono text-sm">
                              {log.destinationIp ? `${log.destinationIp}:${log.destinationPort || '-'}` : '-'}
                            </TableCell>
                            <TableCell className="uppercase text-sm">{log.protocol || '-'}</TableCell>
                            <TableCell>
                              <Badge
                                variant={log.status === 'blocked' ? 'default' : log.status === 'detected' ? 'secondary' : 'outline'}
                                className="capitalize"
                              >
                                {log.status}
                              </Badge>
                            </TableCell>
                            <TableCell>
                              {log.mitigated ? (
                                <CheckCircle className="w-5 h-5 text-green-500" />
                              ) : (
                                <XCircle className="w-5 h-5 text-red-500" />
                              )}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                </ScrollArea>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Mitigations Tab */}
          <TabsContent value="mitigations">
            <Card className="shadow-lg">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <ShieldCheck className="w-5 h-5 text-green-500" />
                      Suggested Mitigations
                    </CardTitle>
                    <CardDescription>Recommended security actions and patches</CardDescription>
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={fetchData}
                    className="flex items-center gap-2"
                  >
                    <RefreshCw className="w-4 h-4" />
                    Refresh
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {mitigations.map((mitigation) => (
                    <Card key={mitigation.id} className="border-l-4 border-l-blue-500 hover:shadow-md transition-shadow">
                      <CardHeader className="pb-3">
                        <div className="flex items-start justify-between">
                          <div className="flex-1">
                            <CardTitle className="text-lg flex items-center gap-2">
                              {getStatusIcon(mitigation.status)}
                              {mitigation.title}
                            </CardTitle>
                            <CardDescription className="mt-1">{mitigation.description}</CardDescription>
                          </div>
                          <div className="flex flex-col items-end gap-2">
                            <Badge className={getSeverityColor(mitigation.priority)}>
                              {mitigation.priority}
                            </Badge>
                            <Badge variant="outline" className="capitalize">
                              {mitigation.type}
                            </Badge>
                          </div>
                        </div>
                      </CardHeader>
                      <CardContent>
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                          <div>
                            <p className="text-gray-500 mb-1">Status</p>
                            <div className="flex items-center gap-2">
                              {getStatusIcon(mitigation.status)}
                              <span className="font-medium capitalize">{mitigation.status}</span>
                            </div>
                          </div>
                          <div>
                            <p className="text-gray-500 mb-1">Estimated Effort</p>
                            <p className="font-medium">{mitigation.estimatedEffort || 'TBD'}</p>
                          </div>
                          <div>
                            <p className="text-gray-500 mb-1">Due Date</p>
                            <p className="font-medium">
                              {mitigation.dueDate
                                ? new Date(mitigation.dueDate).toLocaleDateString()
                                : mitigation.completedAt
                                ? `Completed: ${new Date(mitigation.completedAt).toLocaleDateString()}`
                                : 'Not set'}
                            </p>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Charts/Analytics Tab */}
          <TabsContent value="charts">
            <Card className="shadow-lg">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <BarChart3 className="w-5 h-5 text-purple-500" />
                      Security Analytics
                    </CardTitle>
                    <CardDescription>Visual threat intelligence and traffic analysis</CardDescription>
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={fetchData}
                    className="flex items-center gap-2"
                  >
                    <RefreshCw className="w-4 h-4" />
                    Refresh Charts
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                <SecurityCharts
                  threats={threats}
                  vulnerabilities={vulnerabilities}
                  attackLogs={attackLogs}
                  assets={assets}
                />
              </CardContent>
            </Card>
          </TabsContent>

          {/* Reports Tab */}
          <TabsContent value="reports">
            <div className="space-y-6">
              <Card className="shadow-lg">
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle className="flex items-center gap-2">
                        <File className="w-5 h-5 text-indigo-500" />
                        Automated Report Generation
                      </CardTitle>
                      <CardDescription>Generate security reports on-demand</CardDescription>
                    </div>
                    <Button
                      className="bg-blue-600 hover:bg-blue-700"
                      onClick={async () => {
                        const reportType = 'daily';
                        try {
                          const res = await fetch('/api/reports', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ type: reportType }),
                          });
                          if (res.ok) {
                            fetchData();
                            alert('Report generated successfully!');
                          }
                        } catch (error) {
                          alert('Error generating report');
                        }
                      }}
                    >
                      <Plus className="w-4 h-4 mr-2" />
                      Generate Daily Report
                    </Button>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                    <Button
                      variant="outline"
                      className="h-20 flex-col gap-2"
                      onClick={async () => {
                        try {
                          const res = await fetch('/api/reports', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ type: 'daily' }),
                          });
                          if (res.ok) {
                            fetchData();
                            alert('Daily report generated!');
                          }
                        } catch (error) {
                          alert('Error generating report');
                        }
                      }}
                    >
                      <FileText className="w-6 h-6" />
                      <span>Daily Report</span>
                    </Button>
                    <Button
                      variant="outline"
                      className="h-20 flex-col gap-2"
                      onClick={async () => {
                        try {
                          const res = await fetch('/api/reports', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ type: 'weekly' }),
                          });
                          if (res.ok) {
                            fetchData();
                            alert('Weekly report generated!');
                          }
                        } catch (error) {
                          alert('Error generating report');
                        }
                      }}
                    >
                      <BarChart3 className="w-6 h-6" />
                      <span>Weekly Report</span>
                    </Button>
                    <Button
                      variant="outline"
                      className="h-20 flex-col gap-2"
                      onClick={async () => {
                        try {
                          const res = await fetch('/api/reports', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ type: 'monthly' }),
                          });
                          if (res.ok) {
                            fetchData();
                            alert('Monthly report generated!');
                          }
                        } catch (error) {
                          alert('Error generating report');
                        }
                      }}
                    >
                      <PieChart className="w-6 h-6" />
                      <span>Monthly Report</span>
                    </Button>
                  </div>

                  <h3 className="text-lg font-semibold mb-4">Generated Reports</h3>
                  <div className="space-y-3">
                    {[
                      {
                        title: 'Daily Threat Intelligence Report',
                        type: 'daily',
                        summary: '5 new threats detected, 2 critical vulnerabilities identified, overall risk score: 72',
                        date: new Date().toLocaleDateString(),
                      },
                      {
                        title: 'Weekly Security Summary',
                        type: 'weekly',
                        summary: '23 total threats this week, 12 mitigated successfully, 3 active investigations',
                        date: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toLocaleDateString(),
                      },
                      {
                        title: 'Incident Report: Ransomware Attack Attempt',
                        type: 'incident',
                        summary: 'Ransomware attack detected and blocked on EMR server. No data exfiltration confirmed.',
                        date: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toLocaleDateString(),
                      },
                    ].map((report, index) => (
                      <Card key={index} className="border-l-4 border-l-blue-500">
                        <CardHeader className="pb-3">
                          <div className="flex items-start justify-between">
                            <div>
                              <CardTitle className="text-lg">{report.title}</CardTitle>
                              <CardDescription className="mt-1">{report.summary}</CardDescription>
                            </div>
                            <Badge variant="outline" className="capitalize">
                              {report.type}
                            </Badge>
                          </div>
                        </CardHeader>
                        <CardContent>
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-4 text-sm text-gray-600">
                              <span className="flex items-center gap-1">
                                <Clock className="w-4 h-4" />
                                Generated: {report.date}
                              </span>
                              <span className="flex items-center gap-1">
                                <ShieldCheck className="w-4 h-4" />
                                Risk Score: {riskScore}
                              </span>
                            </div>
                            <Button variant="outline" size="sm" className="flex items-center gap-2">
                              <Download className="w-4 h-4" />
                              Download
                            </Button>
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Alerts Tab */}
          <TabsContent value="alerts">
            <Card className="shadow-lg">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <Bell className="w-5 h-5 text-purple-500" />
                      Alert Center
                    </CardTitle>
                    <CardDescription>Automated alerts and notifications</CardDescription>
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    className="flex items-center gap-2"
                  >
                    <Download className="w-4 h-4" />
                    Export
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {alerts.map((alert) => (
                    <Alert
                      key={alert.id}
                      variant={alert.severity === 'critical' ? 'destructive' : 'default'}
                      className={`border-l-4 ${
                        alert.severity === 'critical'
                          ? 'border-l-red-500'
                          : alert.severity === 'high'
                          ? 'border-l-orange-500'
                          : 'border-l-blue-500'
                      }`}
                    >
                      <AlertTitle className="flex items-center gap-2">
                        {alert.type === 'email' && <FileText className="w-4 h-4" />}
                        {alert.type === 'sms' && <Bell className="w-4 h-4" />}
                        {alert.type === 'dashboard' && <Eye className="w-4 h-4" />}
                        {alert.title}
                      </AlertTitle>
                      <AlertDescription className="mt-2">
                        <p>{alert.message}</p>
                        <div className="flex items-center gap-4 mt-3 text-xs text-gray-500">
                          <span className="flex items-center gap-1">
                            <Clock className="w-3 h-3" />
                            {new Date(alert.createdAt).toLocaleString()}
                          </span>
                          <Badge variant="outline" className="capitalize">
                            {alert.alertType}
                          </Badge>
                          <Badge variant="outline" className="capitalize">
                            {alert.type}
                          </Badge>
                        </div>
                      </AlertDescription>
                    </Alert>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </main>

      {/* Footer */}
      <footer className="bg-white border-t border-gray-200 mt-12">
        <div className="container mx-auto px-4 py-6">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              <Shield className="w-5 h-5 text-blue-600" />
              <span className="font-semibold text-gray-900">Medisentinel Pvt Ltd</span>
            </div>
            <p className="text-sm text-gray-500">
              Automated Threat Intelligence Framework for Healthcare Cyber Resilience
            </p>
            <p className="text-xs text-gray-400">
              Kathmandu Valley Hospital Sector
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}
