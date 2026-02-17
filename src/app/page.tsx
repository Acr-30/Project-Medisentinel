'use client';

import { useState, useEffect } from 'react';
import { Shield, Lock, Mail, AlertCircle, Activity, Database, AlertTriangle } from 'lucide-react';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Button } from '@/components/ui/button';
import { Alert, AlertDescription } from '@/components/ui/alert';

export default function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [isMobile, setIsMobile] = useState(false);

  useEffect(() => {
    setIsMobile(window.innerWidth < 1024);
  }, []);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Login failed');
      }

      // Store auth data
      localStorage.setItem('medisentinel_user', JSON.stringify(data.user));
      localStorage.setItem('medisentinel_token', data.token);

      // Redirect to dashboard
      window.location.href = '/dashboard';
    } catch (err: any) {
      setError(err.message || 'An error occurred during login');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col lg:flex-row bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50">
      {/* Left Panel - Branding */}
      <div className="lg:w-1/2 p-8 lg:p-16 flex flex-col justify-center bg-gradient-to-br from-blue-600 via-blue-700 to-indigo-800 text-white">
        <div className="max-w-xl mx-auto w-full">
          <div className="flex items-center gap-3 mb-8">
            <div className="w-16 h-16 bg-white/10 backdrop-blur-sm rounded-2xl flex items-center justify-center border-2 border-white/20">
              <Shield className="w-10 h-10 text-white" />
            </div>
            <div>
              <h1 className="text-3xl font-bold tracking-tight">Medisentinel</h1>
              <p className="text-blue-200 text-sm">Threat Intelligence</p>
            </div>
          </div>

          <h2 className="text-4xl lg:text-5xl font-bold mb-6 leading-tight">
            Automated Threat Intelligence Framework
          </h2>
          <p className="text-xl text-blue-100 mb-8">
            Enhancing Cyber Resilience in Private Hospital Sector in Kathmandu Valley
          </p>

          <div className="grid grid-cols-2 gap-4 mb-8">
            <div className="bg-white/10 backdrop-blur-sm rounded-xl p-4 border border-white/20">
              <Activity className="w-8 h-8 mb-2 text-blue-200" />
              <h3 className="font-semibold mb-1">Real-time Detection</h3>
              <p className="text-sm text-blue-200">Continuous threat monitoring</p>
            </div>
            <div className="bg-white/10 backdrop-blur-sm rounded-xl p-4 border border-white/20">
              <Database className="w-8 h-8 mb-2 text-blue-200" />
              <h3 className="font-semibold mb-1">CVE Integration</h3>
              <p className="text-sm text-blue-200">Vulnerability database</p>
            </div>
            <div className="bg-white/10 backdrop-blur-sm rounded-xl p-4 border border-white/20">
              <AlertTriangle className="w-8 h-8 mb-2 text-blue-200" />
              <h3 className="font-semibold mb-1">Risk Scoring</h3>
              <p className="text-sm text-blue-200">Automated assessment</p>
            </div>
            <div className="bg-white/10 backdrop-blur-sm rounded-xl p-4 border border-white/20">
              <Shield className="w-8 h-8 mb-2 text-blue-200" />
              <h3 className="font-semibold mb-1">MITRE ATT&CK</h3>
              <p className="text-sm text-blue-200">Framework alignment</p>
            </div>
          </div>
        </div>
      </div>

      {/* Right Panel - Login Form */}
      <div className="lg:w-1/2 p-8 lg:p-16 flex items-center justify-center">
        <Card className="w-full max-w-md shadow-2xl border-0 bg-white/80 backdrop-blur-sm">
          <CardHeader className="space-y-1">
            <div className="flex items-center justify-center gap-2 mb-4">
              <div className="w-12 h-12 bg-blue-600 rounded-xl flex items-center justify-center">
                <Shield className="w-7 h-7 text-white" />
              </div>
              <div>
                <CardTitle className="text-2xl font-bold text-blue-900">Medisentinel</CardTitle>
                <CardDescription className="text-blue-600">Threat Intelligence</CardDescription>
              </div>
            </div>
            <CardTitle className="text-2xl font-bold text-center">
              {isMobile ? 'Login to Continue' : 'Welcome Back'}
            </CardTitle>
            <CardDescription className="text-center">
              Sign in to access your threat intelligence dashboard
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleLogin} className="space-y-4">
              {error && (
                <Alert variant="destructive">
                  <AlertCircle className="h-4 w-4" />
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}

              <div className="space-y-2">
                <Label htmlFor="email">Email Address</Label>
                <div className="relative">
                  <Mail className="absolute left-3 top-3 h-5 w-5 text-gray-400" />
                  <Input
                    id="email"
                    type="email"
                    placeholder="name@hospital.com"
                    className="pl-10"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <div className="relative">
                  <Lock className="absolute left-3 top-3 h-5 w-5 text-gray-400" />
                  <Input
                    id="password"
                    type="password"
                    placeholder="••••••••"
                    className="pl-10"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                  />
                </div>
              </div>

              <Button
                type="submit"
                className="w-full bg-blue-600 hover:bg-blue-700 text-white"
                disabled={loading}
              >
                {loading ? 'Signing in...' : 'Sign In'}
              </Button>
            </form>
          </CardContent>
          <CardFooter className="flex flex-col space-y-4">
            <p className="text-xs text-center text-gray-500">
              Medisentinel Pvt Ltd - Healthcare Cybersecurity Solution
            </p>
            <p className="text-xs text-center text-gray-400">
              Protected by enterprise-grade security
            </p>
          </CardFooter>
        </Card>
      </div>
    </div>
  );
}
