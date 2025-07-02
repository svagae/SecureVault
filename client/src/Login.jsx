
import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import './App.css';

function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleLogin = async () => {
    setError('');
    try {
      const response = await axios.post('http://localhost:5000/api/login', { email, password }, { withCredentials: true });
      if (response.data.message === 'Login successful') {
        navigate('/dashboard');
      } else {
        setError('Login failed due to unexpected response.');
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Login failed. Please try again.');
    }
  };

  return (
    <div className="container">
      <h1>SecureVault</h1>
      <div style={{ marginBottom: 32, textAlign: 'center' }}>
        <svg width="48" height="48" fill="none" stroke="#8b5cf6" strokeWidth="3" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 4.5c-4.97 0-9 2.239-9 5v5c0 2.761 4.03 5 9 5s9-2.239 9-5v-5c0-2.761-4.03-5-9-5z" />
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 12v2m0 0h.01" />
        </svg>
        <h2 style={{ fontWeight: 700, fontSize: 28, margin: 0 }}>Privacy Pass</h2>
        <p style={{ color: '#aaa', margin: 0 }}>Securely access your account</p>
      </div>
      <div style={{
        background: '#18181b',
        borderRadius: 16,
        boxShadow: '0 8px 32px 0 rgba(0,0,0,0.37)',
        border: '1px solid #27272a',
        padding: 32,
        width: 350,
        maxWidth: '90vw',
        color: '#fff',
        margin: '0 auto'
      }}>
        <h3 style={{ fontWeight: 700, fontSize: 24, marginBottom: 8 }}>Sign In</h3>
        <p style={{ color: '#aaa', marginBottom: 24 }}>Enter your credentials to sign in to your account.</p>
        <label htmlFor="email" style={{ display: 'block', color: '#eee', marginBottom: 4 }}>Email</label>
        <input
          id="email"
          type="email"
          value={email}
          onChange={e => setEmail(e.target.value)}
          placeholder="name@example.com"
          className="input"
        />
        <label htmlFor="password" style={{ display: 'block', color: '#eee', marginBottom: 4, marginTop: 16 }}>Password</label>
        <input
          id="password"
          type="password"
          value={password}
          onChange={e => setPassword(e.target.value)}
          placeholder="••••••••"
          className="input"
        />
        <button onClick={handleLogin} className="button" style={{ marginTop: 24 }}>Sign In</button>
        {error && <div className="error">{error}</div>}
        <div style={{ marginTop: 24, textAlign: 'center' }}>
          <a href="/register" style={{ color: '#8b5cf6', textDecoration: 'none', fontSize: 14 }}>Back to Register</a>
        </div>
      </div>
    </div>
  );
}

export default Login;
