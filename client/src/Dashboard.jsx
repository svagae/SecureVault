import React, { useEffect, useState, useRef } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import './App.css';
import { Line } from 'react-chartjs-2';
import { Chart, LineElement, PointElement, LinearScale, CategoryScale } from 'chart.js';

Chart.register(LineElement, PointElement, LinearScale, CategoryScale);

function Dashboard() {
  const [userData, setUserData] = useState(null);
  const [error, setError] = useState('');
  const [threatEvents, setThreatEvents] = useState([]);
  const [isCollapsed, setIsCollapsed] = useState(false);
  const navigate = useNavigate();
  const ws = useRef(null);
  

  useEffect(() => {
    ws.current = new WebSocket('ws://localhost:5000');
    ws.current.onmessage = (event) => {
      const data = JSON.parse(event.data);
      console.log('Received threat event:', data); // Debug log
      if (data.type === 'threat') setThreatEvents((prev) => [data, ...prev].slice(0, 5));
    };
    ws.current.onerror = () => setError('WebSocket connection failed');
    ws.current.onclose = () => setError('WebSocket disconnected');

    const fetchDashboardData = async () => {
      try {
        const response = await axios.get('http://localhost:5000/api/dashboard', { withCredentials: true });
        setUserData(response.data);
        const events = await axios.get('http://localhost:5000/api/threat-events', { withCredentials: true });
        setThreatEvents(events.data);
      } catch (err) {
        setError(err.response?.data?.error || 'Failed to load dashboard');
        if (err.response?.status === 401) await refreshToken();
      }
    };

    const refreshToken = async () => {
      try {
        await axios.post('http://localhost:5000/api/refresh', {}, { withCredentials: true });
        await fetchDashboardData();
      } catch (err) {
        setError('Session expired. Please log in again.');
        navigate('/login');
      }
    };

    fetchDashboardData();

    const timeout = setTimeout(() => {
      setError('Session timed out. Please log in again.');
      navigate('/login');
    }, 15 * 60 * 1000);

    const resetTimeout = () => clearTimeout(timeout);
    window.addEventListener('mousemove', resetTimeout);
    window.addEventListener('keypress', resetTimeout);

    const refreshInterval = setInterval(refreshToken, 5 * 60 * 1000);

    return () => {
      clearTimeout(timeout);
      clearInterval(refreshInterval);
      window.removeEventListener('mousemove', resetTimeout);
      window.removeEventListener('keypress', resetTimeout);
      if (ws.current) ws.current.close();
    };
  }, [navigate]);

  const handleLogout = async () => {
    try {
      await axios.post('http://localhost:5000/api/logout', {}, { withCredentials: true });
      navigate('/login');
    } catch (err) {
      setError('Logout failed. Please try again.');
      navigate('/login');
    }
  };

  const handleRevokeToken = async () => {
    try {
      await axios.post('http://localhost:5000/api/revoke-token', {}, { withCredentials: true });
      setError('Token revoked. Please log in again.');
      navigate('/login');
    } catch (err) {
      setError('Token revocation failed.');
    }
  };

  const simulateTokenReuse = async () => {
    try {
      await axios.post('http://localhost:5000/api/simulate-token-reuse', {}, { withCredentials: true });
      setError('Token reuse simulation triggered.');
    } catch (err) {
      setError(err.response?.data?.error || 'Simulation failed.');
    }
  };

  const toggleSidebar = () => setIsCollapsed((prev) => !prev);

  if (error) return <div className="container"><div className="error">{error}</div></div>;
  if (!userData) return <div className="container"><p>Loading...</p></div>;

  const chartData = {
    labels: threatEvents.map((_, idx) => `T-${idx}`),
    datasets: [
      {
        label: 'Threat Events',
        data: threatEvents.map(() => Math.random() * 100),
        fill: true,
        backgroundColor: 'rgba(139, 92, 246, 0.2)',
        borderColor: '#8b5cf6',
        tension: 0.4,
      },
    ],
  };

  const chartOptions = {
    plugins: { legend: { display: false } },
    scales: {
      x: { grid: { color: '#27272a' }, ticks: { color: '#fff' } },
      y: { grid: { color: '#27272a' }, ticks: { color: '#fff' } },
    },
  };

  return (
    <div className="dashboard-root">
      <aside className={`dashboard-sidebar ${isCollapsed ? 'collapsed' : ''}`}>
        <button className="collapsible-toggle" onClick={toggleSidebar}>⋮</button>
        <div className="sidebar-header">
          <span className="sidebar-icon">🛡️</span>
          <span className="sidebar-title">SecureVault</span>
        </div>
        <nav className="sidebar-nav">
          <div className="sidebar-link active">
            <span className="sidebar-link-icon">🛡️</span>
            <span>Dashboard</span>
            {threatEvents.length > 0 && <span className="threat-badge">{threatEvents.length}</span>}
          </div>
          <div className="sidebar-link">
            <span className="sidebar-link-icon">⚙️</span>
            <span>Settings</span>
          </div>
        </nav>
      </aside>
      <main className="dashboard-main">
        <h1 className="dashboard-title">Dashboard</h1>
        <div className="dashboard-welcome-card">
          <h2>Welcome Back!</h2>
          <p>Here's your security overview. All systems are currently operational.</p>
          {userData && <p>Email: {userData.email}</p>}
        </div>
        <div className="dashboard-cards-row">
          <div className="dashboard-card threat-list">
            <h3>Real-Time Threat Detection</h3>
            <ul>
              {threatEvents.map((event, idx) => (
                <li key={idx} className={event.color === 'red' ? 'threat-red' : 'threat-violet'}>
                  <span className="threat-icon">{event.icon}</span>
                  <span>{event.text}</span>
                  <span className="threat-time">{event.time}</span>
                  <span className="threat-location">IP: {event.ip || 'unknown'}, Country: {event.country || 'unknown'}</span>
                </li>
              ))}
            </ul>
          </div>
          <div className="dashboard-card dashboard-chart">
            <h3>Threat Events</h3>
            <p className="dashboard-chart-desc">A live feed of security events over the last 30 minutes.</p>
            <Line data={chartData} options={chartOptions} height={180} />
          </div>
        </div>
        <div className="dashboard-actions">
          <button
            onClick={handleLogout}
            className="dashboard-btn logout-btn"
          >
            Log Out
          </button>
          <button
            onClick={handleRevokeToken}
            className="dashboard-btn revoke-btn"
          >
            Revoke Token
          </button>
          <button
            onClick={simulateTokenReuse}
            className="dashboard-btn simulate-btn"
          >
            Simulate Token Reuse
          </button>
        </div>
      </main>
    </div>
  );
}

export default Dashboard;