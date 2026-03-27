/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import * as React from 'react';
import { useState, useEffect, useCallback, useRef } from 'react';
import { 
  Shield, 
  Globe, 
  Mail, 
  User as UserIcon, 
  Activity, 
  Lock, 
  Search, 
  AlertTriangle, 
  CheckCircle2, 
  BarChart3,
  LayoutDashboard,
  Settings,
  CreditCard,
  ChevronRight,
  ExternalLink,
  Zap,
  Clock,
  LogOut,
  LogIn,
  Menu,
  X,
  Hash,
  MapPin,
  Server,
  Building2,
  Layout,
  Cpu,
  ShieldCheck,
  ShieldAlert,
  Database,
  Terminal,
  Radio,
  Repeat,
  FileText,
  Fingerprint,
  Award,
  Cookie,
  Camera,
  Phone
} from 'lucide-react';

import { Client, Account, ID, Storage } from 'appwrite';

const appwriteClient = new Client()
    .setEndpoint(import.meta.env.VITE_APPWRITE_ENDPOINT || 'https://cloud.appwrite.io/v1')
    .setProject(import.meta.env.VITE_APPWRITE_PROJECT_ID || '');

const account = new Account(appwriteClient);
const storage = new Storage(appwriteClient);

const dnsInfo: Record<string, { description: string; link: string }> = {
  'A': {
    description: 'Maps a domain name to an IPv4 address.',
    link: 'https://www.cloudflare.com/learning/dns/dns-records/dns-a-record/'
  },
  'AAAA': {
    description: 'Maps a domain name to an IPv6 address.',
    link: 'https://www.cloudflare.com/learning/dns/dns-records/dns-aaaa-record/'
  },
  'MX': {
    description: 'Specifies the mail servers responsible for receiving email messages.',
    link: 'https://www.cloudflare.com/learning/dns/dns-records/dns-mx-record/'
  },
  'TXT': {
    description: 'Allows domain administrators to insert arbitrary text into DNS records.',
    link: 'https://www.cloudflare.com/learning/dns/dns-records/dns-txt-record/'
  },
  'NS': {
    description: 'Specifies the authoritative name servers for a domain.',
    link: 'https://www.cloudflare.com/learning/dns/dns-records/dns-ns-record/'
  },
  'CNAME': {
    description: 'Maps one domain name to another (alias).',
    link: 'https://www.cloudflare.com/learning/dns/dns-records/dns-cname-record/'
  },
  'SOA': {
    description: 'Contains administrative information about the zone.',
    link: 'https://www.cloudflare.com/learning/dns/dns-records/dns-soa-record/'
  }
};
import { cn } from './lib/utils';
import { 
  LineChart, 
  Line, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  AreaChart,
  Area
} from 'recharts';
import { motion, AnimatePresence } from 'motion/react';
import { 
  BrowserRouter as Router, 
  Routes, 
  Route, 
  Navigate, 
  useNavigate, 
  Link,
  useSearchParams 
} from 'react-router-dom';
import { GoogleGenAI, Type } from "@google/genai";

// --- Types ---
type ScanType = 'domain' | 'email' | 'username' | 'ip';

interface ScanResult {
  _id?: string;
  userId: string;
  type: ScanType;
  target: string;
  score: number;
  timestamp: string;
  details: any;
}

interface UserProfile {
  id: string;
  email: string;
  role: 'user' | 'admin';
  plan: 'trial' | 'free' | 'pro' | 'team' | 'enterprise';
  createdAt: string;
}

interface Vulnerability {
  title: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  description: string;
  remediation: string;
}

interface DomainIntelData {
  summary: string;
  score: number;
  dnsRecords: { type: string; value: string; ttl: number }[];
  whois: {
    registrar: string;
    creationDate: string;
    expiryDate: string;
    owner: string;
    abuseContactEmail: string;
    nameServerManagementDate: string;
  };
  ssl: {
    issuer: string;
    validFrom: string;
    validTo: string;
    protocol: string;
  };
  headers: { name: string; value: string; status: 'secure' | 'warning' | 'critical' }[];
  subdomains: string[];
  ipIntel: {
    ip: string;
    asn: string;
    location: string;
    provider: string;
  };
  mailSecurity: {
    spf: boolean;
    dkim: boolean;
    dmarc: boolean;
    summary: string;
  };
  techStack: {
    server: string;
    frameworks: string[];
    cms: string;
  };
  ports: {
    port: number;
    service: string;
    status: 'open' | 'closed' | 'filtered';
  }[];
  threatIntel: {
    reputation: number;
    blacklisted: boolean;
    threats: string[];
  };
  cookies: { name: string; secure: boolean; httpOnly: boolean; sameSite: string }[];
  redirects: { from: string; to: string; status: number }[];
  robots: { path: string; status: string; type: string }[];
  typosquatting: { domain: string; status: string; risk: string }[];
  sri: { script: string; status: boolean; hash: string }[];
  trustScore: { age: string; score: number; level: string };
  vulnerabilities: Vulnerability[];
  lastScanned: string;
  recommendations: string[];
}

// --- Error Handling ---
// --- Error Boundary ---
interface ErrorBoundaryProps {
  children: React.ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: any;
}

class ErrorBoundary extends React.Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = {
    hasError: false,
    error: null
  };

  static getDerivedStateFromError(error: any) {
    return { hasError: true, error };
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-bg flex items-center justify-center p-8">
          <div className="glass-panel p-8 rounded-2xl max-w-md w-full text-center">
            <AlertTriangle className="text-red-500 mx-auto mb-4" size={48} />
            <h1 className="text-xl font-bold mb-2">Something went wrong</h1>
            <p className="text-muted text-sm mb-6">
              {this.state.error?.message?.startsWith('{') 
                ? "A database permission error occurred. Please check your account access." 
                : "An unexpected error occurred in the application."}
            </p>
            <button 
              onClick={() => window.location.reload()}
              className="w-full py-2 bg-accent text-bg font-bold rounded-lg"
            >
              Reload Application
            </button>
          </div>
        </div>
      );
    }
    return (this as any).props.children;
  }
}

// --- Components ---

const SidebarItem = ({ icon: Icon, label, active, onClick }: { icon: any, label: string, active?: boolean, onClick?: () => void, key?: string }) => (
  <button 
    onClick={onClick}
    className={cn(
      "flex items-center gap-3 w-full px-4 py-3 text-sm font-medium transition-all rounded-xl border border-transparent",
      active 
        ? "text-accent bg-accent/5 border-accent/10 shadow-[0_0_20px_rgba(0,255,65,0.05)]" 
        : "text-muted hover:text-ink hover:bg-white/5"
    )}
  >
    <Icon size={18} />
    {label}
  </button>
);

const DesktopNavItem = ({ icon: Icon, label, active, onClick }: { icon: any, label: string, active?: boolean, onClick?: () => void, key?: string }) => (
  <button 
    onClick={onClick}
    className={cn(
      "flex items-center gap-2 px-3 py-1.5 text-xs font-bold uppercase tracking-wider transition-colors rounded-lg border border-transparent",
      active 
        ? "text-accent bg-accent/5 border-accent/10" 
        : "text-muted hover:text-ink hover:bg-white/5"
    )}
  >
    <Icon size={14} />
    {label}
  </button>
);

const RiskBadge = ({ score }: { score: number }) => {
  let color = "bg-green-500/10 text-green-500 border-green-500/20";
  if (score >= 70) color = "bg-red-500/10 text-red-500 border-red-500/20";
  else if (score >= 40) color = "bg-yellow-500/10 text-yellow-500 border-yellow-500/20";

  return (
    <span className={cn("px-2 py-0.5 rounded-md text-[10px] font-bold uppercase tracking-wider border backdrop-blur-sm", color)}>
      Risk: {score}
    </span>
  );
};

const SystemStatus = () => {
  const [status, setStatus] = useState<{ mongodb: string; appwrite: string }>({ mongodb: 'checking', appwrite: 'checking' });

  useEffect(() => {
    const checkStatus = async () => {
      try {
        const res = await fetch('/api/health');
        const data = await res.json();
        
        setStatus({
          mongodb: data.mongodb,
          appwrite: data.appwrite === 'configured' ? 'connected' : 'error'
        });
      } catch (err) {
        setStatus({ mongodb: 'error', appwrite: 'error' });
      }
    };
    checkStatus();
  }, []);

  return (
    <div className="flex items-center gap-4 text-[10px] uppercase tracking-widest font-bold">
      <div className="flex items-center gap-1.5">
        <div className={cn("w-1.5 h-1.5 rounded-full", status.mongodb === 'connected' ? "bg-accent shadow-[0_0_8px_#00FF41]" : "bg-red-500")} />
        <span className={status.mongodb === 'connected' ? "text-accent" : "text-red-500"}>DB: {status.mongodb}</span>
      </div>
      <div className="flex items-center gap-1.5">
        <div className={cn("w-1.5 h-1.5 rounded-full", status.appwrite === 'connected' ? "bg-accent shadow-[0_0_8px_#00FF41]" : "bg-red-500")} />
        <span className={status.appwrite === 'connected' ? "text-accent" : "text-red-500"}>AUTH: {status.appwrite}</span>
      </div>
    </div>
  );
};

const AuthLayout = ({ children, title, subtitle }: { children: React.ReactNode; title: string; subtitle: string }) => (
  <div className="min-h-screen bg-bg flex items-center justify-center p-6 relative overflow-hidden">
    {/* Cyberpunk background elements */}
    <div className="absolute top-0 left-0 w-full h-full opacity-10 pointer-events-none">
      <div className="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] bg-accent rounded-full blur-[120px]" />
      <div className="absolute bottom-[-10%] right-[-10%] w-[40%] h-[40%] bg-blue-500 rounded-full blur-[120px]" />
    </div>
    
    <motion.div 
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="w-full max-w-md relative z-10"
    >
      <div className="text-center mb-8">
        <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-accent/10 border border-accent/20 mb-4 shadow-[0_0_30px_rgba(0,255,65,0.1)]">
          <Shield className="text-accent" size={32} />
        </div>
        <h1 className="text-3xl font-black tracking-tighter text-ink mb-2 uppercase">Cybercord<span className="text-accent">.</span>Intel</h1>
        <p className="text-muted text-sm font-medium">{subtitle}</p>
      </div>
      
      <div className="glass-panel p-8 rounded-3xl border border-white/10 shadow-2xl">
        <h2 className="text-xl font-bold mb-6 text-ink">{title}</h2>
        {children}
      </div>
      
      <div className="mt-8 text-center">
        <SystemStatus />
      </div>
    </motion.div>
  </div>
);

const LoginPage = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    
    // Debug: Check if endpoint/project are set
    const endpoint = import.meta.env.VITE_APPWRITE_ENDPOINT || 'https://cloud.appwrite.io/v1';
    const projectId = import.meta.env.VITE_APPWRITE_PROJECT_ID;
    
    if (!projectId) {
      setError("Appwrite Project ID is missing. Please set VITE_APPWRITE_PROJECT_ID in environment variables.");
      setLoading(false);
      return;
    }

    try {
      await account.createEmailPasswordSession(email, password);
      navigate('/dashboard');
    } catch (err: any) {
      console.error("Login Error:", err);
      if (err.message === "Failed to fetch") {
        setError("Network error: Could not reach Appwrite. Check your internet connection or if the endpoint is correct.");
      } else {
        setError(err.message || "Invalid credentials");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthLayout title="Welcome Back" subtitle="Secure access to your intelligence dashboard">
      <form onSubmit={handleSubmit} className="space-y-4">
        {error && (
          <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/20 text-red-500 text-xs font-bold flex items-center gap-2">
            <AlertTriangle size={14} />
            {error}
          </div>
        )}
        <div className="space-y-1.5">
          <label className="text-[10px] uppercase tracking-widest font-bold text-muted ml-1">Email Address</label>
          <div className="relative">
            <Mail className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" size={16} />
            <input 
              type="email" 
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full bg-white/5 border border-white/10 rounded-xl py-3 pl-10 pr-4 text-sm focus:border-accent outline-none transition-all"
              placeholder="name@company.com"
            />
          </div>
        </div>
        <div className="space-y-1.5">
          <label className="text-[10px] uppercase tracking-widest font-bold text-muted ml-1">Password</label>
          <div className="relative">
            <Lock className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" size={16} />
            <input 
              type="password" 
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full bg-white/5 border border-white/10 rounded-xl py-3 pl-10 pr-4 text-sm focus:border-accent outline-none transition-all"
              placeholder="••••••••"
            />
          </div>
        </div>
        <button 
          type="submit"
          disabled={loading}
          className="w-full py-3 bg-accent hover:bg-accent/90 text-bg font-black uppercase tracking-widest rounded-xl transition-all shadow-[0_0_20px_rgba(0,255,65,0.2)] disabled:opacity-50"
        >
          {loading ? 'Authenticating...' : 'Sign In'}
        </button>
      </form>
      <div className="mt-6 text-center space-y-2">
        <p className="text-xs text-muted">
          Don't have an account? <Link to="/signup" className="text-accent font-bold hover:underline">Create one now</Link>
        </p>
        <p className="text-xs text-muted">
          <Link to="/forgot-password" size={14} className="text-muted hover:text-accent transition-colors">Forgot Password?</Link>
        </p>
      </div>
    </AuthLayout>
  );
};

const ForgotPasswordPage = () => {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      await account.createRecovery(email, window.location.origin + '/reset-password');
      setSuccess(true);
    } catch (err: any) {
      setError(err.message || "Failed to send recovery email.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthLayout title="Password Recovery" subtitle="Enter your email to reset your access">
      {success ? (
        <div className="text-center space-y-4">
          <div className="w-16 h-16 bg-accent/10 rounded-full flex items-center justify-center mx-auto">
            <CheckCircle2 className="text-accent" size={32} />
          </div>
          <p className="text-sm text-muted">Check your inbox for instructions to reset your password.</p>
          <Link to="/login" className="block text-accent font-bold hover:underline">Back to Login</Link>
        </div>
      ) : (
        <form onSubmit={handleSubmit} className="space-y-4">
          {error && <div className="p-3 bg-red-500/10 border border-red-500/20 text-red-500 text-xs rounded-xl flex items-center gap-2"><AlertTriangle size={14} />{error}</div>}
          <div className="space-y-1.5">
            <label className="text-[10px] uppercase tracking-widest font-bold text-muted ml-1">Email Address</label>
            <div className="relative">
              <Mail className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" size={16} />
              <input 
                type="email" 
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full bg-white/5 border border-white/10 rounded-xl py-3 pl-10 pr-4 text-sm focus:border-accent outline-none transition-all"
                placeholder="name@company.com"
              />
            </div>
          </div>
          <button 
            type="submit"
            disabled={loading}
            className="w-full py-3 bg-accent text-bg font-black uppercase tracking-widest rounded-xl transition-all disabled:opacity-50"
          >
            {loading ? 'Sending...' : 'Send Recovery Link'}
          </button>
          <div className="text-center">
            <Link to="/login" className="text-xs text-muted hover:text-accent transition-colors">Back to Login</Link>
          </div>
        </form>
      )}
    </AuthLayout>
  );
};

const ResetPasswordPage = () => {
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchParams] = useSearchParams();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (password !== confirm) {
      setError("Passwords do not match.");
      return;
    }

    const userId = searchParams.get('userId');
    const secret = searchParams.get('secret');

    if (!userId || !secret) {
      setError("Invalid recovery link.");
      return;
    }

    setLoading(true);
    setError(null);
    try {
      await account.updateRecovery(userId, secret, password);
      setSuccess(true);
    } catch (err: any) {
      setError(err.message || "Failed to reset password.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthLayout title="Reset Password" subtitle="Create a new secure access key">
      {success ? (
        <div className="text-center space-y-4">
          <div className="w-16 h-16 bg-accent/10 rounded-full flex items-center justify-center mx-auto">
            <CheckCircle2 className="text-accent" size={32} />
          </div>
          <p className="text-sm text-muted">Your password has been reset successfully.</p>
          <Link to="/login" className="block text-accent font-bold hover:underline">Back to Login</Link>
        </div>
      ) : (
        <form onSubmit={handleSubmit} className="space-y-4">
          {error && <div className="p-3 bg-red-500/10 border border-red-500/20 text-red-500 text-xs rounded-xl flex items-center gap-2"><AlertTriangle size={14} />{error}</div>}
          <div className="space-y-1.5">
            <label className="text-[10px] uppercase tracking-widest font-bold text-muted ml-1">New Password</label>
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" size={16} />
              <input 
                type="password" 
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-white/5 border border-white/10 rounded-xl py-3 pl-10 pr-4 text-sm focus:border-accent outline-none transition-all"
                placeholder="••••••••"
              />
            </div>
          </div>
          <div className="space-y-1.5">
            <label className="text-[10px] uppercase tracking-widest font-bold text-muted ml-1">Confirm Password</label>
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" size={16} />
              <input 
                type="password" 
                required
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                className="w-full bg-white/5 border border-white/10 rounded-xl py-3 pl-10 pr-4 text-sm focus:border-accent outline-none transition-all"
                placeholder="••••••••"
              />
            </div>
          </div>
          <button 
            type="submit"
            disabled={loading}
            className="w-full py-3 bg-accent text-bg font-black uppercase tracking-widest rounded-xl transition-all disabled:opacity-50"
          >
            {loading ? 'Resetting...' : 'Reset Password'}
          </button>
        </form>
      )}
    </AuthLayout>
  );
};

const SignupPage = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [phone, setPhone] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const isTemporaryEmail = (email: string) => {
    const tempDomains = ['mailinator.com', 'guerrillamail.com', 'temp-mail.org', '10minutemail.com', 'yopmail.com'];
    const domain = email.split('@')[1];
    return tempDomains.includes(domain);
  };

  const isValidPhone = (phone: string) => {
    const phoneRegex = /^\+?[1-9]\d{1,14}$/;
    return phoneRegex.test(phone.replace(/\s+/g, ''));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (isTemporaryEmail(email)) {
      setError("Temporary email addresses are not allowed.");
      return;
    }

    if (!isValidPhone(phone)) {
      setError("Please enter a valid international phone number.");
      return;
    }

    setLoading(true);

    // Debug: Check if endpoint/project are set
    const endpoint = import.meta.env.VITE_APPWRITE_ENDPOINT || 'https://cloud.appwrite.io/v1';
    const projectId = import.meta.env.VITE_APPWRITE_PROJECT_ID;
    
    if (!projectId) {
      setError("Appwrite Project ID is missing. Please set VITE_APPWRITE_PROJECT_ID in environment variables.");
      setLoading(false);
      return;
    }

    try {
      await account.create(ID.unique(), email, password, name);
      await account.createEmailPasswordSession(email, password);
      
      // Sync with backend
      const jwt = await account.createJWT();
      await fetch('/api/user/sync', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${jwt.jwt}`
        },
        body: JSON.stringify({ name, phone })
      });

      navigate('/dashboard');
    } catch (err: any) {
      console.error("Signup Error:", err);
      if (err.message === "Failed to fetch") {
        setError("Network error: Could not reach Appwrite. Ensure you have added this domain to your Appwrite Project's Web Platform settings.");
      } else {
        setError(err.message || "Signup failed");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthLayout title="Create Account" subtitle="Join the elite intelligence network">
      <form onSubmit={handleSubmit} className="space-y-4">
        {error && (
          <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/20 text-red-500 text-xs font-bold flex items-center gap-2">
            <AlertTriangle size={14} />
            {error}
          </div>
        )}
        <div className="space-y-1.5">
          <label className="text-[10px] uppercase tracking-widest font-bold text-muted ml-1">Full Name</label>
          <div className="relative">
            <UserIcon className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" size={16} />
            <input 
              type="text" 
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full bg-white/5 border border-white/10 rounded-xl py-3 pl-10 pr-4 text-sm focus:border-accent outline-none transition-all"
              placeholder="John Doe"
            />
          </div>
        </div>
        <div className="space-y-1.5">
          <label className="text-[10px] uppercase tracking-widest font-bold text-muted ml-1">Email Address</label>
          <div className="relative">
            <Mail className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" size={16} />
            <input 
              type="email" 
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full bg-white/5 border border-white/10 rounded-xl py-3 pl-10 pr-4 text-sm focus:border-accent outline-none transition-all"
              placeholder="name@company.com"
            />
          </div>
        </div>
        <div className="space-y-1.5">
          <label className="text-[10px] uppercase tracking-widest font-bold text-muted ml-1">Mobile Number</label>
          <div className="relative">
            <Activity className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" size={16} />
            <input 
              type="tel" 
              required
              value={phone}
              onChange={(e) => setPhone(e.target.value)}
              className="w-full bg-white/5 border border-white/10 rounded-xl py-3 pl-10 pr-4 text-sm focus:border-accent outline-none transition-all"
              placeholder="+1 234 567 8900"
            />
          </div>
        </div>
        <div className="space-y-1.5">
          <label className="text-[10px] uppercase tracking-widest font-bold text-muted ml-1">Password</label>
          <div className="relative">
            <Lock className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" size={16} />
            <input 
              type="password" 
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full bg-white/5 border border-white/10 rounded-xl py-3 pl-10 pr-4 text-sm focus:border-accent outline-none transition-all"
              placeholder="Min. 8 characters"
            />
          </div>
        </div>
        <button 
          type="submit"
          disabled={loading}
          className="w-full py-3 bg-accent hover:bg-accent/90 text-bg font-black uppercase tracking-widest rounded-xl transition-all shadow-[0_0_20px_rgba(0,255,65,0.2)] disabled:opacity-50"
        >
          {loading ? 'Creating Account...' : 'Sign Up'}
        </button>
      </form>
      <div className="mt-6 text-center">
        <p className="text-xs text-muted">
          Already have an account? <Link to="/login" className="text-accent font-bold hover:underline">Sign in instead</Link>
        </p>
      </div>
    </AuthLayout>
  );
};

function CybercordApp() {
  const [user, setUser] = useState<{ id: string; email: string; role: string; plan: string } | null>(null);
  const [profileData, setProfileData] = useState<{ name: string; email: string; phone: string; avatarUrl: string } | null>(null);
  const [isAuthReady, setIsAuthReady] = useState(false);
  const [activeTab, setActiveTab] = useState<string>('dashboard');
  const [isEditingProfile, setIsEditingProfile] = useState(false);
  const [profileForm, setProfileForm] = useState({ name: '', phone: '' });
  const [isUploading, setIsUploading] = useState(false);
  const [results, setResults] = useState<any[]>([]);
  const [scanInput, setScanInput] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [passwordForm, setPasswordForm] = useState({ current: '', new: '', confirm: '' });
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [passwordSuccess, setPasswordSuccess] = useState<string | null>(null);

  // Domain Intel State
  const [domainIntelInput, setDomainIntelInput] = useState('');
  const [isFetchingIntel, setIsFetchingIntel] = useState(false);
  const [intelData, setIntelData] = useState<DomainIntelData | null>(null);
  const [domainError, setDomainError] = useState<string | null>(null);
  const [scanProgress, setScanProgress] = useState(0);
  const progressIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [isProfileMenuOpen, setIsProfileMenuOpen] = useState(false);
  const [selectedFeature, setSelectedFeature] = useState<{ name: string; value: string; status?: string; type?: string } | null>(null);
  const [selectedVulnerability, setSelectedVulnerability] = useState<Vulnerability | null>(null);

  const mainNavItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'domain-intel', label: 'Domain Intel', icon: Globe },
    { id: 'email', label: 'Email Exposure', icon: Mail },
    { id: 'profile', label: 'My Profile', icon: UserIcon },
    { id: 'risk', label: 'Risk Engine', icon: Activity },
  ];

  const businessNavItems = [
    { id: 'billing', label: 'Subscriptions', icon: CreditCard },
    { id: 'settings', label: 'Settings', icon: Settings },
  ];

  // Close profile menu on click outside
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (isProfileMenuOpen && !(e.target as HTMLElement).closest('.profile-menu-container')) {
        setIsProfileMenuOpen(false);
      }
    };
    window.addEventListener('mousedown', handleClickOutside);
    return () => window.removeEventListener('mousedown', handleClickOutside);
  }, [isProfileMenuOpen]);

  const navigate = useNavigate();

  // Auth Listener
  useEffect(() => {
    const checkAuth = async () => {
      try {
        const session = await account.get();
        if (session) {
          const jwt = await account.createJWT();
          const userData = {
            id: session.$id,
            email: session.email,
            role: 'user',
            plan: 'trial'
          };
          setUser(userData);
          fetchScans(jwt.jwt);
          fetchProfile(jwt.jwt);
          if (window.location.pathname === '/login' || window.location.pathname === '/signup' || window.location.pathname === '/') {
            navigate('/dashboard');
          }
        } else {
          if (window.location.pathname !== '/login' && window.location.pathname !== '/signup') {
            navigate('/login');
          }
        }
      } catch (err) {
        if (window.location.pathname !== '/login' && window.location.pathname !== '/signup') {
          navigate('/login');
        }
      }
      setIsAuthReady(true);
    };
    checkAuth();
  }, [navigate]);

  const fetchProfile = async (token: string) => {
    try {
      const res = await fetch('/api/user/profile', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setProfileData(data);
        setProfileForm({ name: data.name || '', phone: data.phone || '' });
      }
    } catch (err) {
      console.error("Fetch profile failed:", err);
    }
  };

  const handleUpdateProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const jwt = await account.createJWT();
      const res = await fetch('/api/user/profile', {
        method: 'PUT',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${jwt.jwt}`
        },
        body: JSON.stringify({ ...profileForm, avatarUrl: profileData?.avatarUrl })
      });
      if (res.ok) {
        const data = await res.json();
        setProfileData(data);
        setIsEditingProfile(false);
      }
    } catch (err) {
      console.error("Update profile failed:", err);
    }
  };

  const handleAvatarUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    // Check file size (limit to 2MB for Mongo storage)
    if (file.size > 2 * 1024 * 1024) {
      alert("File too large. Please select an image under 2MB.");
      return;
    }

    setIsUploading(true);
    try {
      const reader = new FileReader();
      reader.readAsDataURL(file);
      reader.onload = async () => {
        const base64Data = reader.result as string;
        
        const jwt = await account.createJWT();
        const res = await fetch('/api/user/profile', {
          method: 'PUT',
          headers: { 
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${jwt.jwt}`
          },
          body: JSON.stringify({ 
            ...profileForm, 
            avatarData: base64Data,
            avatarUrl: base64Data // Use base64 directly as URL
          })
        });
        
        if (res.ok) {
          const data = await res.json();
          setProfileData(data);
        }
      };
    } catch (err: any) {
      console.error("Avatar upload failed:", err);
      alert(`Avatar upload failed: ${err.message || String(err)}`);
    } finally {
      setIsUploading(false);
    }
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setPasswordError(null);
    setPasswordSuccess(null);

    if (passwordForm.new !== passwordForm.confirm) {
      setPasswordError("New passwords do not match.");
      return;
    }

    try {
      await account.updatePassword(passwordForm.new, passwordForm.current);
      setPasswordSuccess("Password updated successfully.");
      setPasswordForm({ current: '', new: '', confirm: '' });
    } catch (err: any) {
      setPasswordError(err.message || "Failed to update password.");
    }
  };

  const fetchScans = async (token: string) => {
    try {
      const res = await fetch('/api/scans', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setResults(data);
      }
    } catch (err) {
      console.error("Fetch scans failed:", err);
    }
  };

  const handleLogout = async () => {
    try {
      await account.deleteSession('current');
      setUser(null);
      setResults([]);
      navigate('/login');
    } catch (err) {
      console.error("Logout failed:", err);
    }
  };

  const isValidDomain = (domain: string) => {
    const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/i;
    return domainRegex.test(domain);
  };

  const fetchDomainIntel = async (domain: string) => {
    if (!domain) return;
    
    if (!isValidDomain(domain)) {
      setDomainError('Please enter a valid domain or subdomain (e.g., example.com)');
      return;
    }

    setDomainError(null);
    setIsFetchingIntel(true);
    setIntelData(null);
    setScanProgress(0);
    if (progressIntervalRef.current) clearInterval(progressIntervalRef.current);

    // Simulate progress
    progressIntervalRef.current = setInterval(() => {
      setScanProgress(prev => {
        if (prev >= 95) {
          if (progressIntervalRef.current) clearInterval(progressIntervalRef.current);
          return 95;
        }
        return prev + Math.floor(Math.random() * 5) + 1;
      });
    }, 200);

    try {
      const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY! });
      const response = await ai.models.generateContent({
        model: "gemini-3-flash-preview",
        contents: `Analyze the domain "${domain}" and provide realistic cybersecurity intelligence. 
        Include:
        1. DNS records (A, MX, TXT, NS).
        2. WHOIS summary (Registrar, Dates, Owner, Registrar Abuse Contact Email, Name Server Management Date).
        3. SSL certificate details (Issuer, Dates, Protocol).
        4. Comprehensive security headers analysis.
        5. Subdomains (list 5-8 realistic subdomains).
        6. IP Intelligence (IP address, ASN, Location, Hosting Provider).
        7. Mail Security (SPF, DKIM, DMARC status and summary).
        8. Technology Stack (Web server, Frameworks, CMS).
        9. Port Scan (Simulate status of ports 21, 22, 25, 53, 80, 443, 3306, 8080).
        10. Threat Intelligence (Reputation score 0-100, Blacklist status, known threats).
        11. Vulnerability Scan: Provide 3-5 simulated findings for common web vulnerabilities (e.g., XSS, SQL Injection, Outdated Components, CSRF, Open Redirects). For each finding, include a title, severity (Low, Medium, High, Critical), a detailed description of the risk, and a remediation step.
        12. Cookie Security Audit: List 3-5 common cookies and their security flags (Secure, HttpOnly, SameSite).
        13. Redirect Path Analysis: Show the redirect chain from HTTP to HTTPS or other endpoints.
        14. Robots.txt & Sitemap Scan: Check for existence and list key paths.
        15. Brand Protection (Typosquatting): List 3-5 similar domains and their risk level.
        16. Subresource Integrity (SRI): Check if external scripts use integrity hashes.
        17. Domain Age & Trust Score: Provide domain age, a trust score (0-100), and a trust level (Low, Medium, High).
        18. Security Score (0-100) and a brief summary.
        19. Actionable security recommendations.`,
        config: {
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              summary: { type: Type.STRING },
              score: { type: Type.INTEGER },
              lastScanned: { type: Type.STRING },
              dnsRecords: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    type: { type: Type.STRING },
                    value: { type: Type.STRING },
                    ttl: { type: Type.INTEGER }
                  },
                  required: ["type", "value", "ttl"]
                }
              },
              whois: {
                type: Type.OBJECT,
                properties: {
                  registrar: { type: Type.STRING },
                  creationDate: { type: Type.STRING },
                  expiryDate: { type: Type.STRING },
                  owner: { type: Type.STRING },
                  abuseContactEmail: { type: Type.STRING },
                  nameServerManagementDate: { type: Type.STRING }
                },
                required: ["registrar", "creationDate", "expiryDate", "owner", "abuseContactEmail", "nameServerManagementDate"]
              },
              ssl: {
                type: Type.OBJECT,
                properties: {
                  issuer: { type: Type.STRING },
                  validFrom: { type: Type.STRING },
                  validTo: { type: Type.STRING },
                  protocol: { type: Type.STRING }
                },
                required: ["issuer", "validFrom", "validTo", "protocol"]
              },
              headers: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    name: { type: Type.STRING },
                    value: { type: Type.STRING },
                    status: { type: Type.STRING, enum: ["secure", "warning", "critical"] }
                  },
                  required: ["name", "value", "status"]
                }
              },
              subdomains: {
                type: Type.ARRAY,
                items: { type: Type.STRING }
              },
              ipIntel: {
                type: Type.OBJECT,
                properties: {
                  ip: { type: Type.STRING },
                  asn: { type: Type.STRING },
                  location: { type: Type.STRING },
                  provider: { type: Type.STRING }
                },
                required: ["ip", "asn", "location", "provider"]
              },
              mailSecurity: {
                type: Type.OBJECT,
                properties: {
                  spf: { type: Type.BOOLEAN },
                  dkim: { type: Type.BOOLEAN },
                  dmarc: { type: Type.BOOLEAN },
                  summary: { type: Type.STRING }
                },
                required: ["spf", "dkim", "dmarc", "summary"]
              },
              techStack: {
                type: Type.OBJECT,
                properties: {
                  server: { type: Type.STRING },
                  frameworks: { type: Type.ARRAY, items: { type: Type.STRING } },
                  cms: { type: Type.STRING }
                },
                required: ["server", "frameworks", "cms"]
              },
              ports: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    port: { type: Type.INTEGER },
                    service: { type: Type.STRING },
                    status: { type: Type.STRING, enum: ["open", "closed", "filtered"] }
                  },
                  required: ["port", "service", "status"]
                }
              },
              threatIntel: {
                type: Type.OBJECT,
                properties: {
                  reputation: { type: Type.INTEGER },
                  blacklisted: { type: Type.BOOLEAN },
                  threats: { type: Type.ARRAY, items: { type: Type.STRING } }
                },
                required: ["reputation", "blacklisted", "threats"]
              },
              cookies: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    name: { type: Type.STRING },
                    secure: { type: Type.BOOLEAN },
                    httpOnly: { type: Type.BOOLEAN },
                    sameSite: { type: Type.STRING }
                  },
                  required: ["name", "secure", "httpOnly", "sameSite"]
                }
              },
              redirects: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    from: { type: Type.STRING },
                    to: { type: Type.STRING },
                    status: { type: Type.INTEGER }
                  },
                  required: ["from", "to", "status"]
                }
              },
              robots: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    path: { type: Type.STRING },
                    status: { type: Type.STRING },
                    type: { type: Type.STRING }
                  },
                  required: ["path", "status", "type"]
                }
              },
              typosquatting: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    domain: { type: Type.STRING },
                    status: { type: Type.STRING },
                    risk: { type: Type.STRING }
                  },
                  required: ["domain", "status", "risk"]
                }
              },
              sri: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    script: { type: Type.STRING },
                    status: { type: Type.BOOLEAN },
                    hash: { type: Type.STRING }
                  },
                  required: ["script", "status", "hash"]
                }
              },
              trustScore: {
                type: Type.OBJECT,
                properties: {
                  age: { type: Type.STRING },
                  score: { type: Type.INTEGER },
                  level: { type: Type.STRING }
                },
                required: ["age", "score", "level"]
              },
              vulnerabilities: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    title: { type: Type.STRING },
                    severity: { type: Type.STRING, enum: ["Low", "Medium", "High", "Critical"] },
                    description: { type: Type.STRING },
                    remediation: { type: Type.STRING }
                  },
                  required: ["title", "severity", "description", "remediation"]
                }
              },
              recommendations: {
                type: Type.ARRAY,
                items: { type: Type.STRING }
              }
            },
            required: ["summary", "score", "lastScanned", "dnsRecords", "whois", "ssl", "headers", "subdomains", "ipIntel", "mailSecurity", "techStack", "ports", "threatIntel", "cookies", "redirects", "robots", "typosquatting", "sri", "trustScore", "vulnerabilities", "recommendations"]
          }
        }
      });

      if (response.text) {
        setIntelData(JSON.parse(response.text));
      }
    } catch (error) {
      console.error("Failed to fetch domain intel:", error);
    } finally {
      setIsFetchingIntel(false);
      setScanProgress(100);
      if (progressIntervalRef.current) clearInterval(progressIntervalRef.current);
    }
  };

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!scanInput || !user) return;
    
    setIsScanning(true);
    try {
      // Simulate scan delay
      await new Promise(r => setTimeout(r, 2000));
      
      const session = await account.get();
      const jwt = await account.createJWT();
      if (jwt.jwt) {
        await fetch('/api/scans', {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${jwt.jwt}`
          },
          body: JSON.stringify({
            type: scanInput.includes('@') ? 'email' : 'domain',
            target: scanInput,
            score: Math.floor(Math.random() * 100),
            details: { status: 'Analyzed', findings: Math.floor(Math.random() * 20) }
          })
        });
        fetchScans(jwt.jwt);
        setScanInput('');
      }
    } catch (error) {
      console.error("Scan failed:", error);
    } finally {
      setIsScanning(false);
    }
  };

  if (!isAuthReady) {
    return (
      <div className="h-screen bg-bg flex items-center justify-center">
        <Zap className="text-accent animate-pulse" size={48} />
      </div>
    );
  }

  if (!user) {
    return (
      <div className="h-screen bg-bg flex items-center justify-center p-4 sm:p-8 cyber-grid">
        <div className="glass-panel p-8 sm:p-12 rounded-3xl max-w-md w-full text-center relative overflow-hidden">
          <div className="scan-line" />
          <div className="w-16 h-16 bg-accent rounded-2xl flex items-center justify-center mx-auto mb-8 shadow-[0_0_30px_rgba(0,255,65,0.3)]">
            <Shield className="text-bg" size={32} />
          </div>
          <h1 className="text-3xl font-bold mb-4 tracking-tight">cybercord</h1>
          <p className="text-muted text-sm mb-8">
            Enterprise-grade cybersecurity exposure intelligence. 
            Connect your account to start your 7-day free trial.
          </p>
          <Link 
            to="/login"
            className="w-full py-3 bg-accent text-bg font-bold rounded-xl flex items-center justify-center gap-3 hover:opacity-90 transition-opacity"
          >
            <LogIn size={20} /> Sign In to Dashboard
          </Link>
          <p className="mt-6 text-[10px] text-muted uppercase tracking-widest">
            Legal • Public Data Only • Non-Invasive
          </p>
        </div>
      </div>
    );
  }

  const featureExplanations: Record<string, { title: string, description: string, why: string }> = {
    // Security Headers
    'Strict-Transport-Security': {
      title: 'HTTP Strict Transport Security (HSTS)',
      description: 'HSTS tells the browser that it should only communicate with this website using a secure HTTPS connection, never an unencrypted HTTP connection.',
      why: 'It prevents attackers from intercepting your connection and stealing sensitive data like passwords or cookies.'
    },
    'Content-Security-Policy': {
      title: 'Content Security Policy (CSP)',
      description: 'CSP is a security layer that helps detect and mitigate certain types of attacks, including Cross-Site Scripting (XSS) and data injection attacks.',
      why: 'It tells the browser which sources of content (scripts, images, etc.) are trusted, preventing malicious code from running on the site.'
    },
    'X-Frame-Options': {
      title: 'X-Frame-Options',
      description: 'This header indicates whether or not a browser should be allowed to render a page in a <frame>, <iframe>, <embed> or <object>.',
      why: 'It prevents "Clickjacking" attacks, where an attacker tricks you into clicking something on a different site by overlaying it with an invisible frame.'
    },
    'X-Content-Type-Options': {
      title: 'X-Content-Type-Options',
      description: 'This header prevents the browser from trying to "sniff" the content type and forces it to stick to the declared content-type.',
      why: 'It prevents attackers from disguising malicious files (like a script) as a harmless one (like an image).'
    },
    'Referrer-Policy': {
      title: 'Referrer Policy',
      description: 'This header controls how much information the browser includes when you click a link that goes to another website.',
      why: 'It protects your privacy by preventing the destination website from seeing exactly which page you came from, which might contain sensitive data in the URL.'
    },
    'Permissions-Policy': {
      title: 'Permissions Policy',
      description: 'This header allows a site to control which browser features (like the camera, microphone, or geolocation) can be used by the site or its embedded frames.',
      why: 'It enhances security and privacy by ensuring that sensitive hardware or APIs are only used when explicitly allowed.'
    },
    'Expect-CT': {
      title: 'Expect-CT',
      description: 'This header allows sites to opt-in to reporting and/or enforcement of Certificate Transparency requirements.',
      why: 'It helps detect and prevent the use of misissued or fraudulent SSL certificates for the website.'
    },
    // WHOIS
    'Registrar': {
      title: 'Domain Registrar',
      description: 'The company where the domain name was purchased and registered (e.g., GoDaddy, Namecheap).',
      why: 'The registrar manages the domain\'s settings and ownership information.'
    },
    'Owner': {
      title: 'Domain Owner',
      description: 'The person or organization that legally owns the domain name.',
      why: 'Identifying the owner is important for transparency and for contacting the responsible party in case of issues.'
    },
    'Created': {
      title: 'Creation Date',
      description: 'The date when the domain name was first registered.',
      why: 'Older domains often have a better reputation and are less likely to be used for temporary malicious activities.'
    },
    'Expires': {
      title: 'Expiry Date',
      description: 'The date when the current domain registration will expire.',
      why: 'If a domain is close to expiry, it might indicate a lack of maintenance or a temporary project.'
    },
    // SSL
    'Valid From': {
      title: 'Certificate Valid From',
      description: 'The date when the current SSL certificate became active.',
      why: 'It shows how recently the website updated its security credentials.'
    },
    'Valid To': {
      title: 'Certificate Expiry',
      description: 'The date when the current SSL certificate will expire.',
      why: 'Expired certificates cause browser warnings and indicate that the site is no longer secure.'
    },
    'Issuer': {
      title: 'SSL Certificate Issuer',
      description: 'The Certificate Authority (CA) that verified the website owner\'s identity and issued the SSL certificate.',
      why: 'Trusted issuers (like Let\'s Encrypt, DigiCert) ensure that the certificate is legitimate and the connection is secure.'
    },
    'Protocol': {
      title: 'SSL/TLS Protocol',
      description: 'The version of the security protocol used to encrypt the connection (e.g., TLS 1.2, TLS 1.3).',
      why: 'Modern protocols like TLS 1.3 are faster and more secure than older versions, which may have known vulnerabilities.'
    },
    // Tech Stack
    'Server': {
      title: 'Web Server',
      description: 'The software that handles requests from your browser and sends back the website pages (e.g., Nginx, Apache).',
      why: 'Different servers have different security features and performance characteristics.'
    },
    'CMS': {
      title: 'Content Management System',
      description: 'The platform used to build and manage the website content (e.g., WordPress, Webflow).',
      why: 'Knowing the CMS helps identify potential platform-specific security risks or features.'
    },
    'Framework': {
      title: 'Web Framework',
      description: 'The underlying code library used to build the website (e.g., React, Next.js).',
      why: 'Frameworks provide the building blocks for the site and often include built-in security protections.'
    },
    // DNS Records
    'A': {
      title: 'A Record (Address Record)',
      description: 'An A record maps a domain name (like google.com) to the IP address (like 142.250.190.46) of the computer hosting the site.',
      why: 'It is the most basic DNS record and is essential for pointing your domain to your web server.'
    },
    'MX': {
      title: 'MX Record (Mail Exchanger)',
      description: 'MX records tell the internet which mail servers are responsible for accepting email on behalf of your domain.',
      why: 'Without correct MX records, you cannot receive emails at your domain (e.g., info@yourdomain.com).'
    },
    'TXT': {
      title: 'TXT Record (Text Record)',
      description: 'TXT records allow a domain owner to enter text into the DNS. They are often used for verifying domain ownership and security settings.',
      why: 'They are critical for email security (SPF/DKIM) and for proving to services like Google or Microsoft that you own the domain.'
    },
    'NS': {
      title: 'NS Record (Name Server)',
      description: 'NS records indicate which DNS servers are authoritative for your domain (i.e., which servers hold all your other DNS records).',
      why: 'They tell the rest of the internet where to go to find out the IP address and other details about your domain.'
    },
    'CNAME': {
      title: 'CNAME Record (Canonical Name)',
      description: 'A CNAME record maps an alias name to a true or canonical domain name. For example, mapping "www.example.com" to "example.com".',
      why: 'It allows you to have multiple names point to the same IP address without having to update multiple A records if the IP changes.'
    },
    // Mail Security
    'SPF': {
      title: 'SPF (Sender Policy Framework)',
      description: 'SPF is an email authentication method that specifies which mail servers are authorized to send email on behalf of your domain.',
      why: 'It helps prevent spammers from sending emails that look like they came from your domain, improving your email delivery and protecting your reputation.'
    },
    'DKIM': {
      title: 'DKIM (DomainKeys Identified Mail)',
      description: 'DKIM adds a digital signature to your emails, which the receiving mail server can use to verify that the email was actually sent by you and wasn\'t tampered with.',
      why: 'It provides a way to validate a domain name identity that is associated with a message through cryptographic authentication.'
    },
    'DMARC': {
      title: 'DMARC (Domain-based Message Authentication, Reporting, and Conformance)',
      description: 'DMARC uses SPF and DKIM to give the receiving mail server instructions on what to do if an email fails authentication (e.g., reject it or put it in spam).',
      why: 'It is the most powerful tool for preventing email spoofing and protecting your brand from being used in phishing attacks.'
    },
    // Ports
    '21': {
      title: 'Port 21 (FTP)',
      description: 'Port 21 is used for File Transfer Protocol (FTP), which is an old method for moving files between computers.',
      why: 'It is often considered insecure because it sends passwords in plain text. Modern sites use SFTP (Port 22) instead.'
    },
    '22': {
      title: 'Port 22 (SSH)',
      description: 'Port 22 is used for Secure Shell (SSH), which allows for secure remote access to a server\'s command line.',
      why: 'It is a critical port for server management. If left open and poorly secured, it can be a major entry point for hackers.'
    },
    '80': {
      title: 'Port 80 (HTTP)',
      description: 'Port 80 is the default port for unencrypted web traffic (HTTP).',
      why: 'While still used, most modern sites redirect Port 80 traffic to Port 443 (HTTPS) for better security.'
    },
    '443': {
      title: 'Port 443 (HTTPS)',
      description: 'Port 443 is the default port for secure, encrypted web traffic (HTTPS).',
      why: 'It is the standard for modern web browsing, ensuring that the data sent between your browser and the server is private.'
    },
    '3306': {
      title: 'Port 3306 (MySQL)',
      description: 'Port 3306 is the default port for MySQL databases.',
      why: 'This port should almost never be open to the public internet, as it could allow attackers to try and break into your database.'
    },
    // IP Intelligence
    'IP Address': {
      title: 'IP Address',
      description: 'An IP address is a unique string of numbers separated by periods that identifies each computer using the Internet Protocol to communicate over a network.',
      why: 'It is the digital address of the server hosting the website, allowing your computer to find and connect to it.'
    },
    'Location': {
      title: 'Server Location',
      description: 'This is the physical location (Country/City) of the data center where the website\'s server is located.',
      why: 'Location can impact website speed (latency) and may be relevant for legal or compliance reasons.'
    },
    'ASN': {
      title: 'Autonomous System Number (ASN)',
      description: 'An ASN is a unique identifier for a collection of IP networks and routers under the control of a single entity (like an ISP or a large company).',
      why: 'It helps identify the network infrastructure provider and how traffic is routed to the website.'
    },
    'Provider': {
      title: 'Hosting Provider',
      description: 'The company that provides the server and infrastructure to host the website (e.g., Google Cloud, AWS, DigitalOcean).',
      why: 'Knowing the provider can give insights into the reliability and security standards of the hosting environment.'
    },
    'Reputation': {
      title: 'Domain Reputation',
      description: 'A score that indicates how trustworthy a domain is based on its history, content, and association with malicious activities.',
      why: 'A low reputation score suggests the domain might be used for phishing, malware distribution, or spam.'
    },
    'Status': {
      title: 'Blacklist Status',
      description: 'Whether the domain has been flagged and added to security blacklists by organizations that track malicious activity.',
      why: 'Being blacklisted means the domain is recognized as a threat, and many browsers or security tools will block access to it.'
    },
    // New Features
    'Cookie Security': {
      title: 'Cookie Security Audit',
      description: 'An analysis of the cookies used by the website and their security attributes like Secure, HttpOnly, and SameSite.',
      why: 'Properly configured cookies prevent session hijacking and Cross-Site Request Forgery (CSRF) attacks.'
    },
    'Redirect Path': {
      title: 'Redirect Path Analysis',
      description: 'The sequence of URLs a browser follows when attempting to access the domain, including status codes like 301 or 302.',
      why: 'Analyzing redirects helps identify malicious redirects, open redirect vulnerabilities, and ensures secure (HTTPS) connections.'
    },
    'Robots & Sitemap': {
      title: 'Robots.txt & Sitemap Scan',
      description: 'A check for the existence of robots.txt and sitemap.xml files, which guide search engines and can reveal hidden paths.',
      why: 'Misconfigured robots.txt files can accidentally expose sensitive administrative or private directories to search engines.'
    },
    'Brand Protection': {
      title: 'Typosquatting Detection',
      description: 'Identification of domains that are visually similar to the target domain, often used for phishing or brand impersonation.',
      why: 'Detecting similar domains early helps in proactively defending against phishing campaigns targeting your users.'
    },
    'SRI Check': {
      title: 'Subresource Integrity (SRI)',
      description: 'A security feature that enables browsers to verify that resources they fetch (from a CDN, for example) are delivered without unexpected manipulation.',
      why: 'SRI ensures that if a third-party script is compromised, it won\'t be executed on your website, protecting your users from malicious code.'
    },
    'Trust Score': {
      title: 'Domain Age & Trust Score',
      description: 'A combined metric based on the domain\'s age, registration history, and overall security posture.',
      why: 'Older domains with consistent ownership and strong security settings are generally more trustworthy than newly registered ones.'
    }
  };

  const headerTooltips: Record<string, string> = {
    'HSTS': 'HTTP Strict Transport Security: Forces browsers to use HTTPS.',
    'Strict-Transport-Security': 'Forces browsers to use HTTPS.',
    'CSP': 'Content Security Policy: Prevents XSS by restricting content sources.',
    'Content-Security-Policy': 'Prevents XSS by restricting content sources.',
    'X-Frame-Options': 'Prevents Clickjacking by controlling if a page can be framed.',
    'X-Content-Type-Options': 'Prevents MIME-type sniffing.',
    'Referrer-Policy': 'Controls how much referrer information is included with requests.',
    'Permissions-Policy': 'Controls which browser features (camera, geolocation, etc.) can be used.',
    'Feature-Policy': 'Legacy version of Permissions-Policy. Controls browser feature usage.',
    'Expect-CT': 'Enforces Certificate Transparency to prevent use of misissued certificates.'
  };

  return (
    <div className="flex h-screen bg-bg text-ink cyber-grid overflow-hidden relative">
      {/* Mobile Overlay */}
      {isSidebarOpen && (
        <div 
          className="fixed inset-0 bg-bg/80 backdrop-blur-sm z-40 lg:hidden"
          onClick={() => setIsSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside className={cn(
        "fixed inset-y-0 left-0 z-50 w-64 border-r border-border bg-card/50 backdrop-blur-xl flex flex-col p-4 transition-transform duration-300 lg:relative lg:translate-x-0 lg:flex",
        isSidebarOpen ? "translate-x-0" : "-translate-x-full"
      )}>
        <div className="flex items-center justify-between lg:justify-start gap-2 px-2 mb-8">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 bg-accent rounded flex items-center justify-center">
              <Shield className="text-bg" size={20} />
            </div>
            <span className="font-bold text-xl tracking-tight">cybercord</span>
          </div>
          <button 
            onClick={() => setIsSidebarOpen(false)}
            className="lg:hidden p-2 text-muted hover:text-ink"
          >
            <X size={20} />
          </button>
        </div>

        <nav className="flex-1 space-y-1">
          {mainNavItems.map(item => (
            <SidebarItem 
              key={item.id}
              icon={item.icon} 
              label={item.label} 
              active={activeTab === item.id} 
              onClick={() => { setActiveTab(item.id); setIsSidebarOpen(false); }} 
            />
          ))}
          <div className="pt-4 pb-2 px-4 text-[10px] font-bold text-muted uppercase tracking-widest">
            Business
          </div>
          {businessNavItems.map(item => (
            <SidebarItem 
              key={item.id}
              icon={item.icon} 
              label={item.label} 
              active={activeTab === item.id} 
              onClick={() => { setActiveTab(item.id); setIsSidebarOpen(false); }} 
            />
          ))}
        </nav>

        <div className="mt-auto">
          <div className="p-4 bg-accent/5 rounded-xl border border-accent/10">
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] font-bold text-accent uppercase">Trial Active</span>
              <span className="text-[10px] text-muted">6 days left</span>
            </div>
            <div className="h-1 w-full bg-border rounded-full overflow-hidden">
              <div className="h-full bg-accent w-5/6" />
            </div>
            <button className="w-full mt-3 py-2 text-xs font-bold bg-accent text-bg rounded-lg hover:opacity-90 transition-opacity">
              Upgrade to Pro
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col overflow-hidden relative">
        {/* Header */}
        <header className="h-16 border-b border-border bg-card/80 backdrop-blur-xl flex items-center justify-between px-4 sm:px-8 z-30 sticky top-0 shadow-[0_1px_10px_rgba(0,0,0,0.5)]">
          <div className="flex items-center gap-2 sm:gap-4 flex-1 max-w-4xl">
            <button 
              onClick={() => setIsSidebarOpen(true)}
              className="lg:hidden p-2 text-muted hover:text-ink mr-1"
            >
              <Menu size={20} />
            </button>
            
            <form onSubmit={handleScan} className="relative w-full max-w-xs">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" size={16} />
              <input 
                type="text" 
                placeholder="Scan domain, email, or IP..."
                value={scanInput}
                onChange={(e) => setScanInput(e.target.value)}
                className="w-full bg-white/5 border border-border rounded-lg py-2 pl-10 pr-4 text-sm focus:outline-none focus:border-accent/50 transition-colors"
              />
              {isScanning && (
                <>
                  <div className="absolute inset-x-0 bottom-0 h-[1px] bg-accent shadow-[0_0_10px_var(--color-accent)] animate-pulse" />
                  <div className="absolute right-3 top-1/2 -translate-y-1/2"><Zap className="text-accent animate-pulse" size={14} /></div>
                </>
              )}
            </form>
            <div className="hidden md:block ml-4">
              <SystemStatus />
            </div>
          </div>
          
          <div className="flex items-center gap-4 relative profile-menu-container">
            <button 
              onClick={() => setIsProfileMenuOpen(!isProfileMenuOpen)}
              className="relative group flex items-center gap-2"
            >
              <div className="w-8 h-8 rounded-full bg-gradient-to-br from-accent to-blue-500 group-hover:shadow-[0_0_15px_rgba(0,255,65,0.3)] transition-all flex items-center justify-center">
                <UserIcon size={14} className="text-bg" />
              </div>
            </button>
            
            <AnimatePresence>
              {isProfileMenuOpen && (
                <motion.div 
                  initial={{ opacity: 0, y: 10, scale: 0.95 }}
                  animate={{ opacity: 1, y: 0, scale: 1 }}
                  exit={{ opacity: 0, y: 10, scale: 0.95 }}
                  className="absolute right-0 top-full mt-2 w-64 dropdown-panel p-4 rounded-2xl z-50"
                >
                  <div className="flex items-center gap-3 mb-4 pb-4 border-b border-border">
                    <div className="w-10 h-10 rounded-full bg-gradient-to-br from-accent to-blue-500 flex items-center justify-center">
                      <UserIcon size={20} className="text-bg" />
                    </div>
                    <div className="flex flex-col text-left">
                      <span className="text-sm font-bold truncate max-w-[150px]">{user.email || 'User'}</span>
                      <span className="text-[10px] text-muted uppercase tracking-widest">{user?.plan || 'Trial'} Plan</span>
                    </div>
                  </div>
                  <div className="space-y-1">
                    <button 
                      onClick={() => { setActiveTab('profile'); setIsProfileMenuOpen(false); }}
                      className="flex items-center gap-3 w-full px-3 py-2 text-xs font-bold uppercase tracking-widest text-muted hover:text-accent hover:bg-accent/5 rounded-lg transition-colors"
                    >
                      <UserIcon size={14} /> View Profile
                    </button>
                    <button 
                      onClick={() => { setActiveTab('settings'); setIsProfileMenuOpen(false); }}
                      className="flex items-center gap-3 w-full px-3 py-2 text-xs font-bold uppercase tracking-widest text-muted hover:text-accent hover:bg-accent/5 rounded-lg transition-colors"
                    >
                      <Settings size={14} /> Settings
                    </button>
                    <button 
                      onClick={() => { setActiveTab('billing'); setIsProfileMenuOpen(false); }}
                      className="flex items-center gap-3 w-full px-3 py-2 text-xs font-bold uppercase tracking-widest text-muted hover:text-accent hover:bg-accent/5 rounded-lg transition-colors"
                    >
                      <CreditCard size={14} /> Billing
                    </button>
                    <div className="pt-2 mt-2 border-t border-border">
                      <button 
                        onClick={handleLogout}
                        className="flex items-center gap-3 w-full px-3 py-2 text-xs font-bold uppercase tracking-widest text-muted hover:text-red-500 hover:bg-red-500/5 rounded-lg transition-colors"
                      >
                        <LogOut size={14} /> Sign Out
                      </button>
                    </div>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </header>

        {/* Scrollable Area */}
        <div className="flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8 space-y-8 no-scrollbar">
          <AnimatePresence mode="wait">
            {activeTab === 'dashboard' && (
              <motion.div 
                key="dashboard"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="space-y-8"
              >
                {/* Hero Section */}
                <section className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                  <div className="lg:col-span-2 glass-panel p-6 rounded-2xl relative overflow-hidden group">
                    <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity">
                      <Shield size={120} />
                    </div>
                    <div className="relative z-10">
                      <div className="flex items-center gap-2 mb-4">
                        <span className="w-2 h-2 rounded-full bg-accent animate-ping" />
                        <span className="text-[10px] font-bold text-accent uppercase tracking-widest">Live System Monitoring</span>
                      </div>
                      <h2 className="text-2xl font-bold mb-2">Exposure Overview</h2>
                      <p className="text-muted text-sm mb-6">Real-time monitoring of your public attack surface.</p>
                    
                    <div className="h-64 w-full">
                      <ResponsiveContainer width="100%" height="100%">
                        <AreaChart data={results.length > 0 ? results.slice().reverse().map(s => ({ date: new Date(s.timestamp).toLocaleDateString(), score: s.score })) : []}>
                          <defs>
                            <linearGradient id="colorScore" x1="0" y1="0" x2="0" y2="1">
                              <stop offset="5%" stopColor="var(--color-accent)" stopOpacity={0.3}/>
                              <stop offset="95%" stopColor="var(--color-accent)" stopOpacity={0}/>
                            </linearGradient>
                          </defs>
                          <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" vertical={false} />
                          <XAxis dataKey="date" stroke="var(--color-muted)" fontSize={10} tickLine={false} axisLine={false} />
                          <YAxis stroke="var(--color-muted)" fontSize={10} tickLine={false} axisLine={false} />
                          <Tooltip 
                            contentStyle={{ backgroundColor: 'var(--color-card)', border: '1px solid var(--color-border)', borderRadius: '12px', boxShadow: '0 10px 30px rgba(0,0,0,0.5)' }}
                            itemStyle={{ color: 'var(--color-accent)' }}
                          />
                          <Area type="monotone" dataKey="score" stroke="var(--color-accent)" fillOpacity={1} fill="url(#colorScore)" strokeWidth={2} />
                        </AreaChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                  <div className="absolute top-0 right-0 w-64 h-64 bg-accent/5 blur-3xl rounded-full -mr-32 -mt-32" />
                </div>

                <div className="space-y-6">
                  <div className="glass-panel p-6 rounded-2xl">
                    <div className="flex items-center justify-between mb-4">
                      <h3 className="text-sm font-bold uppercase tracking-wider text-muted">Risk Score</h3>
                      <BarChart3 size={16} className="text-accent" />
                    </div>
                    <div className="flex items-baseline gap-2">
                      <span className="text-5xl font-bold">
                        {results.length > 0 ? Math.round(results.reduce((acc, s) => acc + s.score, 0) / results.length) : '0'}
                      </span>
                      <span className="text-accent text-sm font-medium">/ 100</span>
                    </div>
                    <p className="text-xs text-muted mt-2">Average risk across all scans</p>
                    <div className="mt-6 space-y-3">
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-muted">Active Scans</span>
                        <span className="text-ink">{results.length}</span>
                      </div>
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-muted">Account Status</span>
                        <span className="text-accent">Secure</span>
                      </div>
                    </div>
                  </div>

                  <div className="glass-panel p-6 rounded-2xl border-l-4 border-l-accent">
                    <h3 className="text-sm font-bold mb-2">Quick Action</h3>
                    <p className="text-xs text-muted mb-4">Run a new scan to update your risk profile.</p>
                    <button 
                      onClick={() => document.querySelector('input')?.focus()}
                      className="w-full py-2 text-xs font-bold bg-white/5 hover:bg-white/10 border border-border rounded-lg flex items-center justify-center gap-2 transition-colors"
                    >
                      Start New Scan <ChevronRight size={14} />
                    </button>
                  </div>
                </div>
              </section>

              {/* Recent Scans */}
              <section>
                <div className="flex items-center justify-between mb-6">
                  <h2 className="text-xl font-bold">Recent Intelligence</h2>
                  <button className="text-xs text-accent hover:underline flex items-center gap-1">
                    View All <ExternalLink size={12} />
                  </button>
                </div>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {results.length > 0 ? results.map((scan, i) => (
                    <div key={scan.id || i} className="glass-panel p-4 rounded-xl flex items-center gap-4 hover:border-accent/30 transition-colors group">
                      <div className="w-12 h-12 rounded-lg bg-white/5 flex items-center justify-center text-muted group-hover:text-accent transition-colors">
                        {scan.type === 'domain' ? <Globe size={20} /> : <Mail size={20} />}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <h4 className="font-bold text-sm truncate">{scan.target}</h4>
                          <RiskBadge score={scan.score} />
                        </div>
                        <div className="flex items-center gap-3 text-[10px] text-muted">
                          <span className="flex items-center gap-1"><Clock size={10} /> {new Date(scan.timestamp).toLocaleTimeString()}</span>
                          <span className="flex items-center gap-1 uppercase tracking-tighter font-mono">{scan.type}</span>
                        </div>
                      </div>
                      <button className="p-2 text-muted hover:text-ink">
                        <ChevronRight size={18} />
                      </button>
                    </div>
                  )) : (
                    <div className="col-span-full py-12 text-center text-muted text-sm glass-panel rounded-xl">
                      No scan history found. Start your first intelligence scan above.
                    </div>
                  )}
                </div>
              </section>

              {/* Compliance Signals */}
              <section className="glass-panel p-6 rounded-2xl">
                <h2 className="text-xl font-bold mb-6">Compliance Readiness</h2>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                  {[
                    { label: 'GDPR', status: 'Warning', icon: AlertTriangle, color: 'text-yellow-500' },
                    { label: 'SOC 2', status: 'Ready', icon: CheckCircle2, color: 'text-green-500' },
                    { label: 'ISO 27001', status: 'Incomplete', icon: Lock, color: 'text-red-500' },
                    { label: 'PCI DSS', status: 'Ready', icon: CheckCircle2, color: 'text-green-500' },
                  ].map((item, i) => (
                    <motion.div 
                      key={i} 
                      whileHover={{ scale: 1.05, backgroundColor: 'rgba(255, 255, 255, 0.08)' }}
                      className="p-4 rounded-xl bg-white/5 border border-border flex flex-col items-center text-center transition-colors"
                    >
                      <item.icon size={24} className={cn("mb-3", item.color)} />
                      <span className="text-xs font-bold mb-1">{item.label}</span>
                      <span className="text-[10px] text-muted uppercase tracking-widest">{item.status}</span>
                    </motion.div>
                  ))}
                </div>
              </section>

              {/* System Health & Global Threat */}
              <section className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="md:col-span-2 glass-panel p-6 rounded-2xl relative overflow-hidden">
                  <div className="scan-line opacity-10" />
                  <h3 className="text-sm font-bold text-muted uppercase tracking-widest mb-6">Active Intelligence Nodes</h3>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                    {[
                      { city: 'San Francisco', status: 'Online', latency: '24ms' },
                      { city: 'Tokyo', status: 'Online', latency: '112ms' },
                      { city: 'London', status: 'Online', latency: '45ms' },
                      { city: 'Singapore', status: 'Online', latency: '89ms' },
                    ].map((node, i) => (
                      <div key={i} className="p-3 rounded-xl bg-white/5 border border-border">
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-[10px] font-bold uppercase">{node.city}</span>
                          <div className="w-1.5 h-1.5 rounded-full bg-green-500 shadow-[0_0_5px_rgba(34,197,94,0.5)]" />
                        </div>
                        <div className="text-[10px] text-muted font-mono">{node.latency}</div>
                      </div>
                    ))}
                  </div>
                </div>
                <div className="glass-panel p-6 rounded-2xl flex flex-col justify-between">
                  <div>
                    <h3 className="text-sm font-bold text-muted uppercase tracking-widest mb-4">Risk Engine Status</h3>
                    <div className="space-y-4">
                      {[
                        { label: 'Neural Core', status: 'Optimal', color: 'bg-green-500' },
                        { label: 'Dark Web Crawler', status: 'Active', color: 'bg-green-500' },
                        { label: 'Domain Scanner', status: 'Idle', color: 'bg-blue-500' },
                      ].map((sys, i) => (
                        <div key={i} className="flex items-center justify-between">
                          <span className="text-xs">{sys.label}</span>
                          <div className="flex items-center gap-2">
                            <span className="text-[10px] text-muted">{sys.status}</span>
                            <div className={cn("w-1.5 h-1.5 rounded-full", sys.color)} />
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                  <div className="mt-6 pt-6 border-t border-border">
                    <div className="flex items-center justify-between text-xs mb-2">
                      <span className="text-muted">Global Threat Level</span>
                      <span className="text-yellow-500 font-bold">Elevated</span>
                    </div>
                    <div className="h-1.5 w-full bg-white/5 rounded-full overflow-hidden">
                      <div className="h-full w-3/4 bg-yellow-500 shadow-[0_0_10px_rgba(234,179,8,0.3)]" />
                    </div>
                  </div>
                </div>
              </section>
            </motion.div>
            )}

            {activeTab === 'domain-intel' && (
              <motion.div 
                key="domain-intel"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                className="space-y-8"
              >
              <section className="glass-panel p-8 rounded-2xl">
                <h2 className="text-2xl font-bold mb-2">Domain Intelligence</h2>
                <p className="text-muted text-sm mb-8">Deep analysis of DNS, WHOIS, and security infrastructure.</p>
                
                <div className="flex flex-col sm:flex-row gap-4 max-w-2xl">
                  <div className="relative flex-1">
                    <Globe className={cn(
                      "absolute left-3 top-1/2 -translate-y-1/2 transition-colors",
                      domainError ? "text-red-500" : "text-muted"
                    )} size={18} />
                    <input 
                      type="text" 
                      placeholder="Enter domain name (e.g., google.com)"
                      value={domainIntelInput}
                      onChange={(e) => {
                        setDomainIntelInput(e.target.value);
                        if (domainError) setDomainError(null);
                      }}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' && domainIntelInput && !isFetchingIntel) {
                          fetchDomainIntel(domainIntelInput);
                        }
                      }}
                      className={cn(
                        "w-full bg-white/5 border rounded-xl py-3 pl-10 pr-4 text-sm focus:outline-none transition-all",
                        domainError ? "border-red-500/50 focus:border-red-500" : "border-border focus:border-accent/50"
                      )}
                    />
                    {domainError && (
                      <motion.p 
                        initial={{ opacity: 0, y: -10 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="absolute -bottom-6 left-0 text-[10px] font-bold text-red-500 uppercase tracking-wider"
                      >
                        {domainError}
                      </motion.p>
                    )}
                  </div>
                  <button 
                    onClick={() => fetchDomainIntel(domainIntelInput)}
                    disabled={isFetchingIntel || !domainIntelInput}
                    className="w-full sm:w-auto px-8 py-3 bg-accent text-bg font-bold rounded-xl hover:opacity-90 transition-opacity disabled:opacity-50 flex items-center justify-center gap-2"
                  >
                    {isFetchingIntel ? <Zap className="animate-pulse" size={18} /> : <Search size={18} />}
                    {isFetchingIntel ? 'Analyzing...' : 'Analyze'}
                  </button>
                </div>
              </section>

              {isFetchingIntel && (
                <div className="py-12 flex flex-col items-center justify-center">
                  <div className="relative w-80 h-80 mb-12">
                    {/* Advanced Hacker Scanning Animation */}
                    
                    {/* Outer Rotating Rings */}
                    {[
                      { duration: 20, rotate: 360, inset: 0, opacity: 0.1, dash: "10 5" },
                      { duration: 15, rotate: -360, inset: 4, opacity: 0.15, dash: "5 10" },
                      { duration: 25, rotate: 360, inset: 12, opacity: 0.05, dash: "2 2" },
                    ].map((ring, i) => (
                      <motion.div 
                        key={i}
                        animate={{ rotate: ring.rotate }}
                        transition={{ duration: ring.duration, repeat: Infinity, ease: "linear" }}
                        className="absolute rounded-full border border-accent"
                        style={{ 
                          inset: `${ring.inset}px`, 
                          opacity: ring.opacity,
                          borderStyle: 'dashed',
                          borderDasharray: ring.dash
                        }}
                      />
                    ))}

                    {/* Orbiting Data Nodes */}
                    {[0, 72, 144, 216, 288].map((angle, i) => (
                      <motion.div
                        key={i}
                        animate={{ rotate: 360 }}
                        transition={{ duration: 8, repeat: Infinity, ease: "linear" }}
                        className="absolute inset-0"
                        style={{ transform: `rotate(${angle}deg)` }}
                      >
                        <motion.div 
                          animate={{ 
                            scale: [1, 1.5, 1],
                            opacity: [0.3, 1, 0.3]
                          }}
                          transition={{ duration: 2, repeat: Infinity, delay: i * 0.4 }}
                          className="absolute top-0 left-1/2 -translate-x-1/2 w-2 h-2 bg-accent rounded-full shadow-[0_0_10px_rgba(0,255,65,0.8)]"
                        />
                      </motion.div>
                    ))}

                    {/* Central Core */}
                    <div className="absolute inset-0 flex items-center justify-center">
                      <div className="relative">
                        {/* Core Glow */}
                        <motion.div 
                          animate={{ 
                            scale: [1, 1.2, 1],
                            opacity: [0.2, 0.4, 0.2]
                          }}
                          transition={{ duration: 3, repeat: Infinity }}
                          className="absolute inset-0 bg-accent rounded-full blur-3xl"
                        />
                        
                        {/* Progress Ring */}
                        <svg className="w-48 h-48 -rotate-90">
                          <circle
                            cx="96"
                            cy="96"
                            r="88"
                            fill="none"
                            stroke="currentColor"
                            strokeWidth="2"
                            className="text-white/5"
                          />
                          <motion.circle
                            cx="96"
                            cy="96"
                            r="88"
                            fill="none"
                            stroke="currentColor"
                            strokeWidth="2"
                            strokeDasharray="553"
                            animate={{ strokeDashoffset: 553 - (553 * scanProgress) / 100 }}
                            className="text-accent shadow-[0_0_15px_rgba(0,255,65,0.5)]"
                          />
                        </svg>

                        {/* Center Content */}
                        <div className="absolute inset-0 flex flex-col items-center justify-center">
                          <motion.div
                            animate={{ 
                              scale: [1, 1.1, 1],
                              opacity: [0.8, 1, 0.8]
                            }}
                            transition={{ duration: 1.5, repeat: Infinity }}
                          >
                            <Globe size={48} className="text-accent mb-2" />
                          </motion.div>
                          <div className="text-2xl font-mono font-bold text-accent">
                            {scanProgress}%
                          </div>
                          <div className="text-[8px] font-mono text-muted uppercase tracking-widest">
                            Analyzing
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Targeting Reticle */}
                    <div className="absolute inset-0 pointer-events-none">
                      <div className="absolute top-0 left-0 w-8 h-8 border-t-2 border-l-2 border-accent/30 rounded-tl-lg" />
                      <div className="absolute top-0 right-0 w-8 h-8 border-t-2 border-r-2 border-accent/30 rounded-tr-lg" />
                      <div className="absolute bottom-0 left-0 w-8 h-8 border-b-2 border-l-2 border-accent/30 rounded-bl-lg" />
                      <div className="absolute bottom-0 right-0 w-8 h-8 border-b-2 border-r-2 border-accent/30 rounded-br-lg" />
                    </div>

                    {/* Scanning Line */}
                    <motion.div 
                      animate={{ top: ['10%', '90%', '10%'] }}
                      transition={{ duration: 4, repeat: Infinity, ease: "easeInOut" }}
                      className="absolute left-10 right-10 h-0.5 bg-accent/40 shadow-[0_0_20px_rgba(0,255,65,0.6)] z-10"
                    />
                  </div>
                  
                  <div className="text-center space-y-6 max-w-xl w-full">
                    <div className="space-y-2">
                      <h3 className="text-2xl font-mono font-bold text-accent tracking-tighter uppercase flex items-center justify-center gap-3">
                        <Terminal size={20} className="animate-pulse" />
                        Intelligence Extraction in Progress
                      </h3>
                      <p className="text-xs font-mono text-muted uppercase tracking-[0.4em]">
                        Target: <span className="text-ink">{domainIntelInput}</span>
                      </p>
                    </div>

                    {/* Status Log */}
                    <div className="glass-panel p-6 rounded-2xl border border-accent/10 bg-black/40 text-left font-mono overflow-hidden h-48 relative">
                      <div className="absolute inset-0 bg-gradient-to-b from-transparent via-transparent to-black/60 pointer-events-none" />
                      <motion.div 
                        animate={{ y: [0, -400] }}
                        transition={{ duration: 15, repeat: Infinity, ease: "linear" }}
                        className="space-y-2"
                      >
                        {[
                          { time: "0.00s", msg: "INITIATING CORE HANDSHAKE..." },
                          { time: "0.12s", msg: "RESOLVING DOMAIN NAMESPACE..." },
                          { time: "0.45s", msg: "INTERCEPTING DNS PACKETS [A, MX, TXT]..." },
                          { time: "0.89s", msg: "QUERYING GLOBAL WHOIS DATABASES..." },
                          { time: "1.23s", msg: "SSL HANDSHAKE INITIATED (TLS 1.3)..." },
                          { time: "1.56s", msg: "CERTIFICATE CHAIN VALIDATION: OK" },
                          { time: "2.10s", msg: "ENUMERATING PUBLIC SUBDOMAINS..." },
                          { time: "2.45s", msg: "FOUND: mail." + domainIntelInput },
                          { time: "2.67s", msg: "FOUND: dev." + domainIntelInput },
                          { time: "2.89s", msg: "FOUND: api." + domainIntelInput },
                          { time: "3.22s", msg: "SCANNING NETWORK PORTS [TCP/UDP]..." },
                          { time: "3.56s", msg: "PORT 80 (HTTP): OPEN" },
                          { time: "3.78s", msg: "PORT 443 (HTTPS): OPEN" },
                          { time: "4.12s", msg: "ANALYZING SECURITY HEADERS..." },
                          { time: "4.45s", msg: "CSP POLICY: DETECTED" },
                          { time: "4.78s", msg: "HSTS POLICY: ACTIVE" },
                          { time: "5.12s", msg: "CHECKING THREAT REPUTATION..." },
                          { time: "5.45s", msg: "QUERYING VIRUSTOTAL API..." },
                          { time: "5.78s", msg: "QUERYING GOOGLE SAFE BROWSING..." },
                          { time: "6.12s", msg: "REPUTATION SCORE: CALCULATING..." },
                          { time: "6.45s", msg: "VULNERABILITY PROBING INITIATED..." },
                          { time: "6.78s", msg: "XSS VULNERABILITY: NOT FOUND" },
                          { time: "7.12s", msg: "SQL INJECTION: NOT FOUND" },
                          { time: "7.45s", msg: "GENERATING INTELLIGENCE REPORT..." },
                        ].map((log, i) => (
                          <div key={i} className="flex gap-4 text-[10px]">
                            <span className="text-accent/40">[{log.time}]</span>
                            <span className="text-accent/80 uppercase">{log.msg}</span>
                          </div>
                        ))}
                      </motion.div>
                    </div>

                    <div className="flex items-center justify-center gap-8">
                      <div className="flex flex-col items-center">
                        <div className="text-[10px] font-bold text-muted uppercase mb-1">Packets</div>
                        <div className="text-sm font-mono text-accent">1,248</div>
                      </div>
                      <div className="w-px h-8 bg-accent/10" />
                      <div className="flex flex-col items-center">
                        <div className="text-[10px] font-bold text-muted uppercase mb-1">Threats</div>
                        <div className="text-sm font-mono text-accent">0</div>
                      </div>
                      <div className="w-px h-8 bg-accent/10" />
                      <div className="flex flex-col items-center">
                        <div className="text-[10px] font-bold text-muted uppercase mb-1">Latency</div>
                        <div className="text-sm font-mono text-accent">24ms</div>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {intelData && !isFetchingIntel && (
                <div className="space-y-8">
                  {/* Summary & Score */}
                  <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                    <div className="lg:col-span-2 glass-panel p-8 rounded-3xl relative overflow-hidden flex flex-col justify-center">
                      <div className="scan-line opacity-10" />
                      <div className="relative z-10">
                        <div className="flex items-center justify-between mb-4">
                          <div className="flex items-center gap-2">
                            <Shield className="text-accent" size={24} />
                            <h3 className="text-xl font-bold">Intelligence Summary</h3>
                          </div>
                          <div className="flex items-center gap-1.5 text-[10px] text-muted font-mono uppercase tracking-widest">
                            <Clock size={12} />
                            <span>Last Scanned: {intelData.lastScanned}</span>
                          </div>
                        </div>
                        <p className="text-ink/80 leading-relaxed">{intelData.summary}</p>
                      </div>
                    </div>
                    <div className="glass-panel p-8 rounded-3xl text-center flex flex-col items-center justify-center relative overflow-hidden">
                      <div className="absolute inset-0 bg-accent/5" />
                      <div className="relative z-10">
                        <div className="text-[10px] font-bold text-muted uppercase tracking-[0.2em] mb-2">Security Score</div>
                        <div className="text-7xl font-bold text-accent mb-2">{intelData.score}</div>
                        <div className="text-xs font-medium text-muted">Overall Risk Assessment</div>
                      </div>
                    </div>
                  </div>

                  {/* Threat Intelligence */}
                  <div className="glass-panel p-8 rounded-3xl relative overflow-hidden border border-red-500/20 shadow-[0_0_30px_rgba(239,68,68,0.05)]">
                    <div className="scan-line opacity-5 bg-red-500" />
                    <div className="flex items-center justify-between mb-6">
                      <h3 className="text-xl font-bold flex items-center gap-2">
                        <Radio size={24} className="text-red-500 animate-pulse" /> Threat Intelligence
                      </h3>
                      <div className={cn(
                        "text-xs font-bold px-3 py-1 rounded-full uppercase tracking-widest border",
                        intelData.threatIntel.blacklisted ? "bg-red-500/10 text-red-500 border-red-500/20" : "bg-green-500/10 text-green-500 border-green-500/20"
                      )}>
                        {intelData.threatIntel.blacklisted ? 'Critical: Blacklisted' : 'Security Status: Clean'}
                      </div>
                    </div>
                    
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
                      <div 
                        className="p-6 bg-white/5 rounded-2xl border border-border cursor-pointer hover:bg-white/10 transition-all group"
                        onClick={() => setSelectedFeature({ name: 'Reputation', value: `${intelData.threatIntel.reputation}/100`, type: 'Threat Intelligence' })}
                      >
                        <div className="text-xs font-bold text-muted uppercase tracking-widest mb-2 group-hover:text-accent transition-colors">Reputation Score</div>
                        <div className="flex items-end gap-2">
                          <div className={cn(
                            "text-4xl font-bold",
                            intelData.threatIntel.reputation > 80 ? "text-green-500" :
                            intelData.threatIntel.reputation > 50 ? "text-yellow-500" : "text-red-500"
                          )}>
                            {intelData.threatIntel.reputation}
                          </div>
                          <div className="text-muted text-sm mb-1">/ 100</div>
                        </div>
                        <div className="mt-4 h-1.5 w-full bg-white/10 rounded-full overflow-hidden">
                          <div 
                            className={cn(
                              "h-full transition-all duration-1000",
                              intelData.threatIntel.reputation > 80 ? "bg-green-500" :
                              intelData.threatIntel.reputation > 50 ? "bg-yellow-500" : "bg-red-500"
                            )}
                            style={{ width: `${intelData.threatIntel.reputation}%` }}
                          />
                        </div>
                      </div>

                      <div className="md:col-span-2 space-y-4">
                        <div className="text-xs font-bold text-muted uppercase tracking-widest">Active Threat Indicators</div>
                        <div className="flex flex-wrap gap-3">
                          {intelData.threatIntel.threats.length > 0 ? (
                            intelData.threatIntel.threats.map((t, i) => (
                              <div 
                                key={i} 
                                className="px-4 py-2 bg-red-500/10 text-red-500 text-xs font-bold rounded-xl border border-red-500/20 flex items-center gap-2"
                              >
                                <AlertTriangle size={14} />
                                {t}
                              </div>
                            ))
                          ) : (
                            <div className="flex items-center gap-2 text-sm text-green-500 font-medium bg-green-500/10 px-4 py-2 rounded-xl border border-green-500/20">
                              <CheckCircle2 size={16} />
                              No active threats or malicious signatures detected in global databases.
                            </div>
                          )}
                        </div>
                        
                        <div className="mt-6 p-4 bg-accent/5 rounded-xl border border-accent/10">
                          <p className="text-xs text-ink/70 leading-relaxed italic">
                            Threat intelligence is sourced from real-time feeds including Google Safe Browsing, VirusTotal, and specialized cybersecurity databases.
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                    {/* IP Intelligence */}
                    <div className="glass-panel p-6 rounded-2xl">
                      <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
                        <Globe size={20} className="text-accent" /> IP Intelligence
                      </h3>
                      <div className="grid grid-cols-2 gap-4">
                        {[
                          { label: 'IP Address', value: intelData.ipIntel.ip, icon: Hash },
                          { label: 'Location', value: intelData.ipIntel.location, icon: MapPin },
                          { label: 'ASN', value: intelData.ipIntel.asn, icon: Server },
                          { label: 'Provider', value: intelData.ipIntel.provider, icon: Building2 },
                        ].map((item, i) => (
                          <div 
                            key={i} 
                            className="p-3 bg-white/5 rounded-lg border border-border cursor-pointer hover:bg-white/10 transition-colors"
                            onClick={() => setSelectedFeature({ name: item.label, value: item.value, type: 'IP Intelligence' })}
                          >
                            <div className="flex items-center gap-2 mb-1">
                              <item.icon size={10} className="text-muted" />
                              <div className="text-[10px] font-bold text-muted uppercase">{item.label}</div>
                            </div>
                            <div className="text-sm truncate font-mono">{item.value}</div>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* SSL Certificate */}
                    <div className="glass-panel p-6 rounded-2xl">
                      <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
                        <Lock size={20} className="text-accent" /> SSL Certificate
                      </h3>
                      <div className="space-y-4">
                        <div 
                          className="flex items-center justify-between cursor-pointer hover:bg-white/5 p-1 rounded transition-colors"
                          onClick={() => setSelectedFeature({ name: 'Issuer', value: intelData.ssl.issuer, type: 'SSL Certificate' })}
                        >
                          <span className="text-sm text-muted">Issuer</span>
                          <span className="text-sm font-medium">{intelData.ssl.issuer}</span>
                        </div>
                        <div 
                          className="flex items-center justify-between cursor-pointer hover:bg-white/5 p-1 rounded transition-colors"
                          onClick={() => setSelectedFeature({ name: 'Protocol', value: intelData.ssl.protocol, type: 'SSL Certificate' })}
                        >
                          <span className="text-sm text-muted">Protocol</span>
                          <span className="text-sm font-medium text-accent">{intelData.ssl.protocol}</span>
                        </div>
                        <div className="grid grid-cols-2 gap-4 pt-2">
                          <div 
                            className="p-3 bg-white/5 rounded-lg border border-border cursor-pointer hover:bg-white/10 transition-colors"
                            onClick={() => setSelectedFeature({ name: 'Valid From', value: intelData.ssl.validFrom, type: 'SSL Certificate' })}
                          >
                            <div className="text-[10px] font-bold text-muted uppercase mb-1">Valid From</div>
                            <div className="text-xs font-mono">{intelData.ssl.validFrom}</div>
                          </div>
                          <div 
                            className="p-3 bg-white/5 rounded-lg border border-border cursor-pointer hover:bg-white/10 transition-colors"
                            onClick={() => setSelectedFeature({ name: 'Valid To', value: intelData.ssl.validTo, type: 'SSL Certificate' })}
                          >
                            <div className="text-[10px] font-bold text-muted uppercase mb-1">Valid To</div>
                            <div className="text-xs font-mono">{intelData.ssl.validTo}</div>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* DNS Records */}
                    <div className="glass-panel p-6 rounded-2xl">
                      <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
                        <Activity size={20} className="text-accent" /> DNS Records
                      </h3>
                      <div className="space-y-3 max-h-[300px] overflow-y-auto no-scrollbar">
                        {intelData.dnsRecords.map((record, i) => (
                          <div 
                            key={i} 
                            className="group relative"
                          >
                            <div 
                              className="flex items-center justify-between p-3 bg-white/5 rounded-lg border border-border cursor-pointer hover:bg-white/10 transition-colors"
                              onClick={() => setSelectedFeature({ name: record.type, value: record.value, type: 'DNS Record' })}
                            >
                              <div className="flex flex-col">
                                <span className="text-[10px] font-bold text-accent uppercase">{record.type}</span>
                                <span className="text-sm font-mono truncate max-w-[200px]">{record.value}</span>
                              </div>
                              <span className="text-[10px] text-muted font-mono">TTL: {record.ttl}</span>
                            </div>

                            {/* Tooltip */}
                            <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 w-64 p-4 bg-black/95 border border-accent/30 rounded-xl text-[10px] text-white opacity-0 group-hover:opacity-100 transition-all duration-200 pointer-events-none group-hover:pointer-events-auto z-[100] shadow-2xl backdrop-blur-md">
                              <div className="font-bold text-accent mb-1 uppercase tracking-wider">{record.type} Record</div>
                              <p className="mb-3 text-white/80 leading-relaxed">
                                {dnsInfo[record.type]?.description || 'A standard DNS record used for domain configuration and mapping.'}
                              </p>
                              <a 
                                href={dnsInfo[record.type]?.link} 
                                target="_blank" 
                                rel="noopener noreferrer" 
                                className="flex items-center gap-1.5 text-accent hover:text-white transition-colors font-bold group/link"
                                onClick={(e) => e.stopPropagation()}
                              >
                                <ExternalLink size={10} className="group-hover/link:translate-x-0.5 group-hover/link:-translate-y-0.5 transition-transform" />
                                Documentation
                              </a>
                              <div className="absolute top-full left-1/2 -translate-x-1/2 border-8 border-transparent border-t-black/95" />
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Security Headers */}
                    <div className="glass-panel p-6 rounded-2xl">
                      <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
                        <Shield size={20} className="text-accent" /> Security Headers
                      </h3>
                      <div className="space-y-3 max-h-[300px] overflow-y-auto no-scrollbar">
                        {intelData.headers.map((header, i) => (
                          <div 
                            key={i} 
                            className="flex items-center justify-between p-3 bg-white/5 rounded-lg border border-border group/header relative cursor-pointer hover:bg-white/10 transition-colors"
                            onClick={() => setSelectedFeature({ ...header, type: 'Security Header' })}
                          >
                            <div className="flex flex-col">
                              <span className="text-sm font-bold">{header.name}</span>
                              <span className="text-[10px] text-muted truncate max-w-[200px]">{header.value}</span>
                            </div>
                            <div className="flex items-center gap-3">
                              <span className={cn(
                                "text-[10px] font-bold uppercase px-2 py-0.5 rounded-md border backdrop-blur-sm",
                                header.status === 'secure' ? 'bg-green-500/10 text-green-500 border-green-500/20' :
                                header.status === 'warning' ? 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20' :
                                'bg-red-500/10 text-red-500 border-red-500/20'
                              )}>
                                {header.status}
                              </span>
                              <div className={cn(
                                "w-2 h-2 rounded-full",
                                header.status === 'secure' ? 'bg-green-500 shadow-[0_0_10px_rgba(34,197,94,0.5)]' :
                                header.status === 'warning' ? 'bg-yellow-500 shadow-[0_0_10px_rgba(234,179,8,0.5)]' :
                                'bg-red-500 shadow-[0_0_10px_rgba(239,68,68,0.5)]'
                              )} />
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Mail Security */}
                    <div className="glass-panel p-6 rounded-2xl">
                      <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
                        <Mail size={20} className="text-accent" /> Mail Security
                      </h3>
                      <div className="space-y-4">
                        <div className="grid grid-cols-3 gap-3">
                          {[
                            { label: 'SPF', status: intelData.mailSecurity.spf },
                            { label: 'DKIM', status: intelData.mailSecurity.dkim },
                            { label: 'DMARC', status: intelData.mailSecurity.dmarc },
                          ].map((item, i) => (
                            <div 
                              key={i} 
                              className={cn(
                                "p-3 rounded-xl border flex flex-col items-center justify-center gap-1 cursor-pointer hover:bg-white/5 transition-colors",
                                item.status ? "bg-green-500/5 border-green-500/20" : "bg-red-500/5 border-red-500/20"
                              )}
                              onClick={() => setSelectedFeature({ name: item.label, value: item.status ? 'Configured' : 'Missing', type: 'Mail Security' })}
                            >
                              <div className="text-[10px] font-bold uppercase text-muted">{item.label}</div>
                              {item.status ? <ShieldCheck size={16} className="text-green-500" /> : <ShieldAlert size={16} className="text-red-500" />}
                            </div>
                          ))}
                        </div>
                        <div className="p-3 bg-white/5 rounded-lg border border-border">
                          <p className="text-xs text-muted leading-relaxed">{intelData.mailSecurity.summary}</p>
                        </div>
                      </div>
                    </div>

                    {/* Tech Stack */}
                    <div className="glass-panel p-6 rounded-2xl">
                      <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
                        <Cpu size={20} className="text-accent" /> Tech Stack
                      </h3>
                      <div className="space-y-4">
                        <div 
                          className="flex items-center justify-between p-3 bg-white/5 rounded-lg border border-border cursor-pointer hover:bg-white/10 transition-colors"
                          onClick={() => setSelectedFeature({ name: 'Server', value: intelData.techStack.server, type: 'Tech Stack' })}
                        >
                          <div className="flex items-center gap-2">
                            <Server size={14} className="text-muted" />
                            <span className="text-xs font-bold text-muted uppercase">Server</span>
                          </div>
                          <span className="text-sm font-mono">{intelData.techStack.server}</span>
                        </div>
                        <div 
                          className="flex items-center justify-between p-3 bg-white/5 rounded-lg border border-border cursor-pointer hover:bg-white/10 transition-colors"
                          onClick={() => setSelectedFeature({ name: 'CMS', value: intelData.techStack.cms, type: 'Tech Stack' })}
                        >
                          <div className="flex items-center gap-2">
                            <Database size={14} className="text-muted" />
                            <span className="text-xs font-bold text-muted uppercase">CMS</span>
                          </div>
                          <span className="text-sm font-mono">{intelData.techStack.cms}</span>
                        </div>
                        <div className="flex flex-wrap gap-2">
                          {intelData.techStack.frameworks.map((fw, i) => (
                            <span 
                              key={i} 
                              className="px-2 py-1 bg-accent/10 text-accent text-[10px] font-bold rounded uppercase border border-accent/20 cursor-pointer hover:bg-accent/20 transition-colors"
                              onClick={() => setSelectedFeature({ name: 'Framework', value: fw, type: 'Tech Stack' })}
                            >
                              {fw}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>

                    {/* Port Scan */}
                    <div className="glass-panel p-6 rounded-2xl">
                      <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
                        <Terminal size={20} className="text-accent" /> Port Scan
                      </h3>
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                        {intelData.ports.map((p, i) => (
                          <div 
                            key={i} 
                            className={cn(
                              "p-3 rounded-xl border flex flex-col items-center justify-center gap-1 cursor-pointer hover:bg-white/10 transition-colors",
                              p.status === 'open' ? "bg-green-500/5 border-green-500/20" : 
                              p.status === 'filtered' ? "bg-yellow-500/5 border-yellow-500/20" : 
                              "bg-white/5 border-border"
                            )}
                            onClick={() => setSelectedFeature({ name: p.port.toString(), value: p.service, status: p.status, type: 'Network Port' })}
                          >
                            <div className="text-[10px] font-bold font-mono">{p.port}</div>
                            <div className="text-[8px] uppercase text-muted truncate w-full text-center">{p.service}</div>
                            <div className={cn(
                              "w-1 h-1 rounded-full mt-1",
                              p.status === 'open' ? "bg-green-500 shadow-[0_0_5px_rgba(34,197,94,0.5)]" : 
                              p.status === 'filtered' ? "bg-yellow-500" : "bg-muted"
                            )} />
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Cookie Security Audit */}
                    <div className="glass-panel p-6 rounded-2xl">
                      <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
                        <Cookie size={20} className="text-accent" /> Cookie Security
                      </h3>
                      <div className="space-y-3">
                        {intelData.cookies.map((cookie, i) => (
                          <div 
                            key={i} 
                            className="p-3 bg-white/5 rounded-lg border border-border cursor-pointer hover:bg-white/10 transition-colors"
                            onClick={() => setSelectedFeature({ name: 'Cookie Security', value: cookie.name, type: 'Cookie Audit' })}
                          >
                            <div className="flex items-center justify-between mb-2">
                              <span className="text-sm font-bold truncate max-w-[150px]">{cookie.name}</span>
                              <div className="flex gap-1">
                                <span className={cn("text-[8px] px-1.5 py-0.5 rounded font-bold uppercase", cookie.secure ? "bg-green-500/10 text-green-500" : "bg-red-500/10 text-red-500")}>Secure</span>
                                <span className={cn("text-[8px] px-1.5 py-0.5 rounded font-bold uppercase", cookie.httpOnly ? "bg-green-500/10 text-green-500" : "bg-red-500/10 text-red-500")}>HttpOnly</span>
                              </div>
                            </div>
                            <div className="text-[10px] text-muted">SameSite: <span className="text-accent font-bold uppercase">{cookie.sameSite}</span></div>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Redirect Path Analysis */}
                    <div className="glass-panel p-6 rounded-2xl">
                      <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
                        <Repeat size={20} className="text-accent" /> Redirect Path
                      </h3>
                      <div className="space-y-4 relative">
                        {intelData.redirects.map((r, i) => (
                          <div key={i} className="relative pl-6">
                            {i < intelData.redirects.length - 1 && (
                              <div className="absolute left-2.5 top-6 bottom-[-16px] w-0.5 bg-accent/20" />
                            )}
                            <div className="absolute left-0 top-1.5 w-5 h-5 rounded-full bg-accent/10 border border-accent/20 flex items-center justify-center text-[10px] font-bold text-accent">
                              {i + 1}
                            </div>
                            <div 
                              className="p-3 bg-white/5 rounded-lg border border-border cursor-pointer hover:bg-white/10 transition-colors"
                              onClick={() => setSelectedFeature({ name: 'Redirect Path', value: `${r.from} -> ${r.to}`, type: 'Redirect Analysis' })}
                            >
                              <div className="text-[10px] font-bold text-muted uppercase mb-1">Status: {r.status}</div>
                              <div className="text-xs font-mono truncate">{r.from}</div>
                              <div className="flex justify-center my-1">
                                <ChevronRight size={12} className="text-muted rotate-90" />
                              </div>
                              <div className="text-xs font-mono truncate text-accent">{r.to}</div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Robots & Sitemap */}
                    <div className="glass-panel p-6 rounded-2xl">
                      <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
                        <FileText size={20} className="text-accent" /> Robots & Sitemap
                      </h3>
                      <div className="grid grid-cols-1 gap-3">
                        {intelData.robots.map((file, i) => (
                          <div 
                            key={i} 
                            className="flex items-center justify-between p-3 bg-white/5 rounded-lg border border-border cursor-pointer hover:bg-white/10 transition-colors"
                            onClick={() => setSelectedFeature({ name: 'Robots & Sitemap', value: file.path, type: 'File Scan' })}
                          >
                            <div className="flex flex-col">
                              <span className="text-xs font-bold font-mono">{file.path}</span>
                              <span className="text-[10px] text-muted uppercase">{file.type}</span>
                            </div>
                            <span className={cn(
                              "text-[10px] font-bold uppercase px-2 py-0.5 rounded",
                              file.status === 'Found' ? "bg-green-500/10 text-green-500" : "bg-red-500/10 text-red-500"
                            )}>
                              {file.status}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Brand Protection */}
                    <div className="glass-panel p-6 rounded-2xl">
                      <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
                        <ShieldAlert size={20} className="text-accent" /> Brand Protection
                      </h3>
                      <div className="space-y-3">
                        {intelData.typosquatting.map((t, i) => (
                          <div 
                            key={i} 
                            className="flex items-center justify-between p-3 bg-white/5 rounded-lg border border-border cursor-pointer hover:bg-white/10 transition-colors"
                            onClick={() => setSelectedFeature({ name: 'Brand Protection', value: t.domain, type: 'Typosquatting' })}
                          >
                            <div className="flex flex-col">
                              <span className="text-xs font-mono">{t.domain}</span>
                              <span className="text-[10px] text-muted">{t.status}</span>
                            </div>
                            <span className={cn(
                              "text-[10px] font-bold uppercase px-2 py-0.5 rounded",
                              t.risk === 'High' ? "bg-red-500/10 text-red-500" : 
                              t.risk === 'Medium' ? "bg-yellow-500/10 text-yellow-500" : 
                              "bg-blue-500/10 text-blue-500"
                            )}>
                              {t.risk} Risk
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* SRI Check */}
                    <div className="glass-panel p-6 rounded-2xl">
                      <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
                        <Fingerprint size={20} className="text-accent" /> SRI Check
                      </h3>
                      <div className="space-y-3">
                        {intelData.sri.map((s, i) => (
                          <div 
                            key={i} 
                            className="p-3 bg-white/5 rounded-lg border border-border cursor-pointer hover:bg-white/10 transition-colors"
                            onClick={() => setSelectedFeature({ name: 'SRI Check', value: s.script, type: 'Integrity Check' })}
                          >
                            <div className="flex items-center justify-between mb-2">
                              <span className="text-xs font-mono truncate max-w-[200px]">{s.script}</span>
                              {s.status ? <ShieldCheck size={14} className="text-green-500" /> : <ShieldAlert size={14} className="text-red-500" />}
                            </div>
                            <div className="text-[8px] font-mono text-muted truncate">{s.hash}</div>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Domain Age & Trust Score */}
                    <div className="glass-panel p-6 rounded-2xl">
                      <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
                        <Award size={20} className="text-accent" /> Trust Score
                      </h3>
                      <div className="flex flex-col items-center justify-center p-4 bg-white/5 rounded-xl border border-border cursor-pointer hover:bg-white/10 transition-colors" onClick={() => setSelectedFeature({ name: 'Trust Score', value: intelData.trustScore.level, type: 'Domain Trust' })}>
                        <div className="relative w-24 h-24 flex items-center justify-center mb-4">
                          <svg className="w-full h-full transform -rotate-90">
                            <circle
                              cx="48"
                              cy="48"
                              r="44"
                              stroke="currentColor"
                              strokeWidth="8"
                              fill="transparent"
                              className="text-white/10"
                            />
                            <circle
                              cx="48"
                              cy="48"
                              r="44"
                              stroke="currentColor"
                              strokeWidth="8"
                              fill="transparent"
                              strokeDasharray={276}
                              strokeDashoffset={276 - (276 * intelData.trustScore.score) / 100}
                              className={cn(
                                "transition-all duration-1000",
                                intelData.trustScore.score > 80 ? "text-green-500" :
                                intelData.trustScore.score > 50 ? "text-yellow-500" : "text-red-500"
                              )}
                            />
                          </svg>
                          <div className="absolute inset-0 flex flex-col items-center justify-center">
                            <span className="text-2xl font-bold">{intelData.trustScore.score}</span>
                            <span className="text-[8px] text-muted uppercase">Trust</span>
                          </div>
                        </div>
                        <div className="text-center">
                          <div className="text-sm font-bold mb-1">{intelData.trustScore.level} Trust Level</div>
                          <div className="text-[10px] text-muted">Domain Age: <span className="text-accent font-bold">{intelData.trustScore.age}</span></div>
                        </div>
                      </div>
                    </div>

                    {/* Subdomains */}
                    <div className="glass-panel p-6 rounded-2xl">
                      <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
                        <Layout size={20} className="text-accent" /> Subdomains
                      </h3>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                        {intelData.subdomains.map((sub, i) => (
                          <div key={i} className="p-2 bg-white/5 rounded-lg border border-border text-xs font-mono text-muted hover:text-accent hover:border-accent/30 transition-colors cursor-default">
                            {sub}
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* WHOIS Summary */}
                    <div className="glass-panel p-6 rounded-2xl">
                      <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
                        <UserIcon size={20} className="text-accent" /> WHOIS Summary
                      </h3>
                      <div className="grid grid-cols-2 gap-4">
                        {[
                          { label: 'Registrar', value: intelData.whois.registrar },
                          { label: 'Owner', value: intelData.whois.owner },
                          { label: 'Abuse Email', value: intelData.whois.abuseContactEmail },
                          { label: 'Created', value: intelData.whois.creationDate },
                          { label: 'Expires', value: intelData.whois.expiryDate },
                          { label: 'NS Managed', value: intelData.whois.nameServerManagementDate },
                        ].map((item, i) => (
                          <div 
                            key={i} 
                            className="p-3 bg-white/5 rounded-lg border border-border cursor-pointer hover:bg-white/10 transition-colors"
                            onClick={() => setSelectedFeature({ name: item.label, value: item.value, type: 'WHOIS Data' })}
                          >
                            <div className="text-[10px] font-bold text-muted uppercase mb-1">{item.label}</div>
                            <div className="text-sm truncate font-mono">{item.value}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* Vulnerabilities & Recommendations */}
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                    <div className="glass-panel p-6 rounded-2xl">
                      <h3 className="text-lg font-bold mb-6 flex items-center gap-2">
                        <AlertTriangle size={20} className="text-red-500" /> Vulnerability Scan
                      </h3>
                      <div className="space-y-4">
                        {intelData.vulnerabilities.map((vuln, i) => (
                          <div key={i} className="p-4 bg-white/5 rounded-xl border border-border relative overflow-hidden cursor-pointer hover:bg-white/10 transition-colors" onClick={() => setSelectedVulnerability(vuln)}>
                            <div className={cn(
                              "absolute left-0 top-0 bottom-0 w-1",
                              vuln.severity === 'Critical' ? 'bg-red-600' :
                              vuln.severity === 'High' ? 'bg-red-500' :
                              vuln.severity === 'Medium' ? 'bg-yellow-500' : 'bg-blue-500'
                            )} />
                            <div className="flex items-center justify-between mb-2">
                              <h4 className="font-bold text-sm">{vuln.title}</h4>
                              <span className={cn(
                                "text-[10px] font-bold px-2 py-0.5 rounded uppercase",
                                vuln.severity === 'Critical' ? 'bg-red-600/20 text-red-600' :
                                vuln.severity === 'High' ? 'bg-red-500/20 text-red-500' :
                                vuln.severity === 'Medium' ? 'bg-yellow-500/20 text-yellow-500' : 'bg-blue-500/20 text-blue-500'
                              )}>
                                {vuln.severity}
                              </span>
                            </div>
                            <p className="text-xs text-muted leading-relaxed mb-3">{vuln.description}</p>
                            <div className="p-3 bg-accent/5 rounded-lg border border-accent/10">
                              <div className="text-[10px] font-bold text-accent uppercase tracking-widest mb-1">Remediation</div>
                              <p className="text-[11px] text-ink/80 leading-relaxed italic">{vuln.remediation}</p>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="glass-panel p-6 rounded-2xl">
                      <h3 className="text-lg font-bold mb-6 flex items-center gap-2">
                        <Zap size={20} className="text-accent" /> Security Recommendations
                      </h3>
                      <div className="space-y-3">
                        {intelData.recommendations.map((rec, i) => (
                          <div key={i} className="flex gap-3 p-4 bg-accent/5 rounded-xl border border-accent/10">
                            <div className="w-5 h-5 rounded-full bg-accent/20 flex items-center justify-center flex-shrink-0 mt-0.5">
                              <CheckCircle2 size={12} className="text-accent" />
                            </div>
                            <p className="text-xs text-ink/90 leading-relaxed">{rec}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </motion.div>
          )}

            {activeTab === 'profile' && (
              <motion.div 
                key="profile"
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.95 }}
                className="max-w-4xl mx-auto"
              >
                <div className="glass-panel p-8 rounded-3xl relative overflow-hidden">
                  <div className="scan-line opacity-10" />
                  
                  <div className="flex flex-col md:flex-row gap-8 items-start">
                    {/* Avatar Section */}
                    <div className="relative group">
                      <div className="w-32 h-32 rounded-2xl bg-accent/10 border-2 border-accent/20 overflow-hidden flex items-center justify-center relative">
                        {profileData?.avatarData || profileData?.avatarUrl ? (
                          <img src={profileData.avatarData || profileData.avatarUrl} alt="Avatar" className="w-full h-full object-cover" />
                        ) : (
                          <UserIcon size={48} className="text-accent/40" />
                        )}
                        {isUploading && (
                          <div className="absolute inset-0 bg-bg/60 backdrop-blur-sm flex items-center justify-center">
                            <Zap className="text-accent animate-spin" size={24} />
                          </div>
                        )}
                      </div>
                      <label className="absolute -bottom-2 -right-2 p-2 bg-accent text-bg rounded-lg cursor-pointer hover:scale-110 transition-transform shadow-lg">
                        <Camera size={16} />
                        <input type="file" className="hidden" accept="image/*" onChange={handleAvatarUpload} disabled={isUploading} />
                      </label>
                    </div>

                    {/* Info Section */}
                    <div className="flex-1 space-y-6 w-full">
                      <div className="flex items-center justify-between">
                        <div>
                          <h2 className="text-2xl font-bold">{profileData?.name || 'Anonymous Agent'}</h2>
                          <p className="text-xs text-muted uppercase tracking-widest mt-1">Agent ID: {user?.id}</p>
                        </div>
                        <button 
                          onClick={() => setIsEditingProfile(!isEditingProfile)}
                          className="px-4 py-2 bg-white/5 border border-border rounded-xl text-xs font-bold hover:bg-white/10 transition-colors"
                        >
                          {isEditingProfile ? 'Cancel' : 'Edit Profile'}
                        </button>
                      </div>

                      <form onSubmit={handleUpdateProfile} className="space-y-4">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div className="space-y-1.5">
                            <label className="text-[10px] uppercase tracking-widest font-bold text-muted ml-1">Full Name</label>
                            <div className="relative">
                              <UserIcon className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" size={14} />
                              <input 
                                type="text" 
                                disabled={!isEditingProfile}
                                value={profileForm.name}
                                onChange={(e) => setProfileForm({ ...profileForm, name: e.target.value })}
                                className="w-full bg-white/5 border border-white/10 rounded-xl py-2.5 pl-9 pr-4 text-sm focus:border-accent outline-none disabled:opacity-50 transition-all"
                              />
                            </div>
                          </div>
                          <div className="space-y-1.5">
                            <label className="text-[10px] uppercase tracking-widest font-bold text-muted ml-1">Email Address</label>
                            <div className="relative">
                              <Mail className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" size={14} />
                              <input 
                                type="email" 
                                disabled
                                value={profileData?.email || ''}
                                className="w-full bg-white/5 border border-white/10 rounded-xl py-2.5 pl-9 pr-4 text-sm opacity-50 cursor-not-allowed"
                              />
                            </div>
                          </div>
                          <div className="space-y-1.5">
                            <label className="text-[10px] uppercase tracking-widest font-bold text-muted ml-1">Mobile Number</label>
                            <div className="relative">
                              <Phone className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" size={14} />
                              <input 
                                type="tel" 
                                disabled={!isEditingProfile}
                                value={profileForm.phone}
                                onChange={(e) => setProfileForm({ ...profileForm, phone: e.target.value })}
                                className="w-full bg-white/5 border border-white/10 rounded-xl py-2.5 pl-9 pr-4 text-sm focus:border-accent outline-none disabled:opacity-50 transition-all"
                              />
                            </div>
                          </div>
                          <div className="space-y-1.5">
                            <label className="text-[10px] uppercase tracking-widest font-bold text-muted ml-1">Account Plan</label>
                            <div className="relative">
                              <Award className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" size={14} />
                              <input 
                                type="text" 
                                disabled
                                value={user?.plan || 'Trial'}
                                className="w-full bg-white/5 border border-white/10 rounded-xl py-2.5 pl-9 pr-4 text-sm opacity-50 cursor-not-allowed capitalize"
                              />
                            </div>
                          </div>
                        </div>

                        {isEditingProfile && (
                          <button 
                            type="submit"
                            className="w-full py-3 bg-accent text-bg font-bold rounded-xl hover:opacity-90 transition-opacity shadow-[0_0_20px_rgba(0,255,65,0.2)]"
                          >
                            Save Changes
                          </button>
                        )}
                      </form>
                    </div>
                  </div>
                </div>

                {/* Security Settings */}
                <div className="glass-panel p-8 rounded-3xl mt-6">
                  <div className="flex items-center gap-3 mb-6">
                    <div className="w-10 h-10 rounded-xl bg-accent/10 flex items-center justify-center">
                      <Shield size={20} className="text-accent" />
                    </div>
                    <div>
                      <h3 className="text-lg font-bold">Security Settings</h3>
                      <p className="text-xs text-muted">Manage your access credentials</p>
                    </div>
                  </div>

                  <form onSubmit={handleChangePassword} className="space-y-4 max-w-md">
                    {passwordError && <div className="p-3 bg-red-500/10 border border-red-500/20 text-red-500 text-xs rounded-xl flex items-center gap-2"><AlertTriangle size={14} />{passwordError}</div>}
                    {passwordSuccess && <div className="p-3 bg-accent/10 border border-accent/20 text-accent text-xs rounded-xl flex items-center gap-2"><CheckCircle2 size={14} />{passwordSuccess}</div>}
                    
                    <div className="space-y-1.5">
                      <label className="text-[10px] uppercase tracking-widest font-bold text-muted ml-1">Current Password</label>
                      <input 
                        type="password" 
                        required
                        value={passwordForm.current}
                        onChange={(e) => setPasswordForm({ ...passwordForm, current: e.target.value })}
                        className="w-full bg-white/5 border border-white/10 rounded-xl py-2.5 px-4 text-sm focus:border-accent outline-none transition-all"
                        placeholder="••••••••"
                      />
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="space-y-1.5">
                        <label className="text-[10px] uppercase tracking-widest font-bold text-muted ml-1">New Password</label>
                        <input 
                          type="password" 
                          required
                          value={passwordForm.new}
                          onChange={(e) => setPasswordForm({ ...passwordForm, new: e.target.value })}
                          className="w-full bg-white/5 border border-white/10 rounded-xl py-2.5 px-4 text-sm focus:border-accent outline-none transition-all"
                          placeholder="••••••••"
                        />
                      </div>
                      <div className="space-y-1.5">
                        <label className="text-[10px] uppercase tracking-widest font-bold text-muted ml-1">Confirm New Password</label>
                        <input 
                          type="password" 
                          required
                          value={passwordForm.confirm}
                          onChange={(e) => setPasswordForm({ ...passwordForm, confirm: e.target.value })}
                          className="w-full bg-white/5 border border-white/10 rounded-xl py-2.5 px-4 text-sm focus:border-accent outline-none transition-all"
                          placeholder="••••••••"
                        />
                      </div>
                    </div>
                    <button 
                      type="submit"
                      className="px-6 py-2.5 bg-accent text-bg font-bold rounded-xl hover:opacity-90 transition-opacity"
                    >
                      Update Password
                    </button>
                  </form>
                </div>

                {/* Security Stats */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-6">
                  {[
                    { label: 'Total Scans', value: results.length, icon: Activity },
                    { label: 'Risk Score', value: 'Low', icon: ShieldCheck },
                    { label: 'Security Level', value: 'Level 4', icon: Lock },
                  ].map((stat, i) => (
                    <div key={i} className="glass-panel p-4 rounded-2xl border border-border flex items-center gap-4">
                      <div className="w-10 h-10 rounded-xl bg-accent/10 flex items-center justify-center">
                        <stat.icon size={20} className="text-accent" />
                      </div>
                      <div>
                        <div className="text-[10px] font-bold text-muted uppercase tracking-widest">{stat.label}</div>
                        <div className="text-lg font-bold">{stat.value}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </motion.div>
            )}
            {activeTab === 'email' && (
              <motion.div 
                key="email"
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.95 }}
                className="glass-panel p-12 rounded-3xl text-center max-w-2xl mx-auto relative overflow-hidden"
              >
                <div className="scan-line opacity-20" />
                <div className="w-20 h-20 bg-accent/10 rounded-full flex items-center justify-center mx-auto mb-6">
                  <Mail className="text-accent" size={40} />
                </div>
                <h2 className="text-3xl font-bold mb-4">Email Exposure Intelligence</h2>
                <p className="text-muted mb-8">Scan the dark web and public breaches for exposed credentials and PII associated with your email addresses.</p>
                <div className="flex flex-col sm:flex-row gap-4">
                  <input 
                    type="email" 
                    placeholder="Enter email address..."
                    className="flex-1 bg-white/5 border border-border rounded-xl px-4 py-3 text-sm focus:outline-none focus:border-accent/50"
                  />
                  <button className="px-8 py-3 bg-accent text-bg font-bold rounded-xl hover:opacity-90 transition-opacity">
                    Scan Email
                  </button>
                </div>
              </motion.div>
            )}

            {activeTab === 'risk' && (
              <motion.div 
                key="risk"
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.95 }}
                className="glass-panel p-12 rounded-3xl text-center max-w-2xl mx-auto relative overflow-hidden"
              >
                <div className="scan-line opacity-20" />
                <div className="w-20 h-20 bg-accent/10 rounded-full flex items-center justify-center mx-auto mb-6">
                  <Activity className="text-accent" size={40} />
                </div>
                <h2 className="text-3xl font-bold mb-4">Risk Engine</h2>
                <p className="text-muted mb-8">Advanced risk scoring based on infrastructure vulnerabilities, data leaks, and compliance gaps.</p>
                <button className="px-12 py-4 bg-accent text-bg font-bold rounded-xl hover:opacity-90 transition-opacity shadow-[0_0_30px_rgba(0,255,65,0.2)]">
                  Generate Full Risk Report
                </button>
              </motion.div>
            )}
            {activeTab === 'billing' && (
              <motion.div 
                key="billing"
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.95 }}
                className="glass-panel p-12 rounded-3xl text-center max-w-2xl mx-auto relative overflow-hidden"
              >
                <div className="scan-line opacity-20" />
                <div className="w-20 h-20 bg-accent/10 rounded-full flex items-center justify-center mx-auto mb-6">
                  <CreditCard className="text-accent" size={40} />
                </div>
                <h2 className="text-3xl font-bold mb-4">Subscription Management</h2>
                <p className="text-muted mb-8">Manage your plan, billing history, and payment methods.</p>
                <div className="p-6 rounded-2xl bg-white/5 border border-border text-left mb-8">
                  <div className="flex items-center justify-between mb-4">
                    <span className="text-sm font-bold">Current Plan</span>
                    <span className="px-3 py-1 bg-accent/10 text-accent text-[10px] font-bold uppercase rounded-full border border-accent/20">
                      {user?.plan || 'Trial'}
                    </span>
                  </div>
                  <div className="text-xs text-muted">Next billing date: April 25, 2026</div>
                </div>
                <button className="w-full py-4 bg-accent text-bg font-bold rounded-xl hover:opacity-90 transition-opacity">
                  Upgrade to Enterprise
                </button>
              </motion.div>
            )}

            {activeTab === 'settings' && (
              <motion.div 
                key="settings"
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.95 }}
                className="glass-panel p-12 rounded-3xl text-center max-w-2xl mx-auto relative overflow-hidden"
              >
                <div className="scan-line opacity-20" />
                <div className="w-20 h-20 bg-accent/10 rounded-full flex items-center justify-center mx-auto mb-6">
                  <Settings className="text-accent" size={40} />
                </div>
                <h2 className="text-3xl font-bold mb-4">Account Settings</h2>
                <p className="text-muted mb-8">Configure your security preferences, notification settings, and API access.</p>
                <div className="space-y-4 text-left">
                  {[
                    { label: 'Two-Factor Authentication', status: 'Disabled' },
                    { label: 'Email Notifications', status: 'Enabled' },
                    { label: 'API Access', status: 'Revoked' },
                  ].map((setting, i) => (
                    <div key={i} className="flex items-center justify-between p-4 rounded-xl bg-white/5 border border-border">
                      <span className="text-sm font-medium">{setting.label}</span>
                      <span className="text-xs text-accent font-bold">{setting.status}</span>
                    </div>
                  ))}
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </main>
      {/* Feature Explanation Modal */}
      <AnimatePresence>
        {selectedFeature && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="absolute inset-0 bg-bg/80 backdrop-blur-md"
              onClick={() => setSelectedFeature(null)}
            />
            <motion.div 
              initial={{ opacity: 0, scale: 0.9, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.9, y: 20 }}
              className="relative w-full max-w-lg dropdown-panel p-8 rounded-3xl border border-accent/20 shadow-[0_0_50px_rgba(0,255,65,0.1)]"
            >
              <button 
                onClick={() => setSelectedFeature(null)}
                className="absolute top-4 right-4 p-2 text-muted hover:text-ink transition-colors"
              >
                <X size={20} />
              </button>

              <div className="flex items-center gap-3 mb-6">
                <div className={cn(
                  "w-12 h-12 rounded-2xl flex items-center justify-center",
                  selectedFeature.status === 'secure' || selectedFeature.status === 'open' ? 'bg-green-500/10 text-green-500' :
                  selectedFeature.status === 'warning' || selectedFeature.status === 'filtered' ? 'bg-yellow-500/10 text-yellow-500' :
                  selectedFeature.status === 'error' ? 'bg-red-500/10 text-red-500' :
                  'bg-accent/10 text-accent'
                )}>
                  {selectedFeature.type === 'DNS Record' ? <Activity size={24} /> :
                   selectedFeature.type === 'Network Port' ? <Terminal size={24} /> :
                   selectedFeature.type === 'Mail Security' ? <Mail size={24} /> :
                   selectedFeature.type === 'IP Intelligence' ? <Globe size={24} /> :
                   selectedFeature.type === 'SSL Certificate' ? <Lock size={24} /> :
                   selectedFeature.type === 'WHOIS Data' ? <UserIcon size={24} /> :
                   selectedFeature.type === 'Threat Intelligence' ? <Radio size={24} /> :
                   <Shield size={24} />}
                </div>
                <div>
                  <h3 className="text-xl font-bold">{featureExplanations[selectedFeature.name]?.title || selectedFeature.name}</h3>
                  <div className="flex items-center gap-2 mt-1">
                    <span className="text-[10px] font-bold text-muted uppercase tracking-widest">{selectedFeature.type}</span>
                    {selectedFeature.status && (
                      <span className={cn(
                        "text-[10px] font-bold uppercase px-2 py-0.5 rounded border",
                        selectedFeature.status === 'secure' || selectedFeature.status === 'open' ? 'bg-green-500/10 text-green-500 border-green-500/20' :
                        selectedFeature.status === 'warning' || selectedFeature.status === 'filtered' ? 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20' :
                        'bg-red-500/10 text-red-500 border-red-500/20'
                      )}>
                        {selectedFeature.status}
                      </span>
                    )}
                  </div>
                </div>
              </div>

              <div className="space-y-6">
                <div>
                  <h4 className="text-xs font-bold text-accent uppercase tracking-widest mb-2">What is this?</h4>
                  <p className="text-sm text-ink/80 leading-relaxed">
                    {featureExplanations[selectedFeature.name]?.description || 'This is a technical data point discovered during the domain analysis.'}
                  </p>
                </div>

                <div>
                  <h4 className="text-xs font-bold text-accent uppercase tracking-widest mb-2">Why it matters</h4>
                  <p className="text-sm text-ink/80 leading-relaxed">
                    {featureExplanations[selectedFeature.name]?.why || 'Understanding this data point helps in assessing the overall security posture of the domain.'}
                  </p>
                </div>

                <div className="p-4 bg-white/5 rounded-xl border border-border">
                  <h4 className="text-[10px] font-bold text-muted uppercase tracking-widest mb-2">Current Value</h4>
                  <code className="text-xs font-mono text-accent break-all">{selectedFeature.value}</code>
                </div>
              </div>

              <button 
                onClick={() => setSelectedFeature(null)}
                className="w-full mt-8 py-3 bg-accent text-bg font-bold rounded-xl hover:opacity-90 transition-opacity"
              >
                Understood
              </button>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
      {/* Vulnerability Details Modal */}
      <AnimatePresence>
        {selectedVulnerability && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="absolute inset-0 bg-bg/80 backdrop-blur-md"
              onClick={() => setSelectedVulnerability(null)}
            />
            <motion.div 
              initial={{ opacity: 0, scale: 0.9, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.9, y: 20 }}
              className="relative w-full max-w-lg dropdown-panel p-8 rounded-3xl border border-accent/20 shadow-[0_0_50px_rgba(0,255,65,0.1)]"
            >
              <button 
                onClick={() => setSelectedVulnerability(null)}
                className="absolute top-4 right-4 p-2 text-muted hover:text-ink transition-colors"
              >
                <X size={20} />
              </button>

              <div className="flex items-center gap-3 mb-6">
                <div className={cn(
                  "w-12 h-12 rounded-2xl flex items-center justify-center",
                  selectedVulnerability.severity === 'Critical' ? 'bg-red-600/10 text-red-600' :
                  selectedVulnerability.severity === 'High' ? 'bg-red-500/10 text-red-500' :
                  selectedVulnerability.severity === 'Medium' ? 'bg-yellow-500/10 text-yellow-500' :
                  'bg-blue-500/10 text-blue-500'
                )}>
                  <AlertTriangle size={24} />
                </div>
                <div>
                  <h3 className="text-xl font-bold">{selectedVulnerability.title}</h3>
                  <div className="flex items-center gap-2 mt-1">
                    <span className={cn(
                      "text-[10px] font-bold uppercase px-2 py-0.5 rounded border",
                      selectedVulnerability.severity === 'Critical' ? 'bg-red-600/20 text-red-600 border-red-600/30' :
                      selectedVulnerability.severity === 'High' ? 'bg-red-500/20 text-red-500 border-red-500/30' :
                      selectedVulnerability.severity === 'Medium' ? 'bg-yellow-500/20 text-yellow-500 border-yellow-500/30' :
                      'bg-blue-500/20 text-blue-500 border-blue-500/30'
                    )}>
                      {selectedVulnerability.severity}
                    </span>
                  </div>
                </div>
              </div>

              <div className="space-y-6">
                <div>
                  <h4 className="text-xs font-bold text-accent uppercase tracking-widest mb-2">The Risk</h4>
                  <p className="text-sm text-ink/80 leading-relaxed">
                    {selectedVulnerability.description}
                  </p>
                </div>

                <div>
                  <h4 className="text-xs font-bold text-accent uppercase tracking-widest mb-2">Remediation</h4>
                  <p className="text-sm text-ink/80 leading-relaxed">
                    {selectedVulnerability.remediation}
                  </p>
                </div>
              </div>

              <button 
                onClick={() => setSelectedVulnerability(null)}
                className="w-full mt-8 py-3 bg-accent text-bg font-bold rounded-xl hover:opacity-90 transition-opacity"
              >
                Understood
              </button>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}

export default function App() {
  return (
    <ErrorBoundary>
      <Router>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/signup" element={<SignupPage />} />
          <Route path="/forgot-password" element={<ForgotPasswordPage />} />
          <Route path="/reset-password" element={<ResetPasswordPage />} />
          <Route path="/dashboard" element={<CybercordApp />} />
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </Router>
    </ErrorBoundary>
  );
}
