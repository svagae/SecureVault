import React, { useState } from 'react';
import axios from 'axios';
import { Link } from 'react-router-dom'; // For navigation (install react-router-dom with `npm install react-router-dom`)
import './App.css';

function Register() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  const handleRegister = async () => {
    setError(''); // Clear previous errors
    try {
      await axios.post('http://localhost:5000/api/register', { email, password, consent: true });
      setError('Registration successful! Please sign in.');
    } catch (err) {
      // Check for already existing account error
      if (err.response && err.response.status === 409) {
        setError('You already have an account. Please sign in.');
      } else if (err.response?.data?.error) {
        setError(err.response.data.error);
      } else {
        setError('Registration failed.');
      }
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
        <p style={{ color: '#aaa', margin: 0 }}>Create your secure account</p>
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
        <h3 style={{ fontWeight: 700, fontSize: 24, marginBottom: 8 }}>Create Account</h3>
        <p style={{ color: '#aaa', marginBottom: 24 }}>Enter your details to get started.</p>
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
        <button onClick={handleRegister} className="button" style={{ marginTop: 24 }}>Register</button>
        {error && <div className="error">{error}</div>}
        <div style={{ marginTop: 24, textAlign: 'center' }}>
          <p style={{ color: '#aaa', margin: 0 }}>Already have an account?</p>
          <Link to="/login" style={{ color: '#8b5cf6', textDecoration: 'none', fontSize: 14 }}>Sign In</Link>
        </div>
      </div>
    </div>
  );
}

export default Register;
