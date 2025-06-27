import React, { useState } from 'react';
import axios from 'axios';
import './App.css';

const App: React.FC = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  const handleRegister = async () => {
    try {
      await axios.post('http://localhost:5000/api/register', { email, password, consent: true });
      setError('Registration successful! Please log in.');
    } catch (err) {
      if (axios.isAxiosError(err)) {
        setError(err.response?.data?.error || 'Registration failed');
      } else {
        setError('Registration failed');
      }
    }
  };

  return (
    <div className="min-h-screen bg-neutral-900 flex flex-col items-center justify-center px-2">
      {/* SecureVault Title */}
      <h1 className="text-5xl font-extrabold text-white mb-4 mt-2 tracking-tight">SecureVault</h1>

      {/* Privacy Pass Card */}
      <div className="flex flex-col items-center mb-2">
        <div className="flex items-center justify-center mb-2">
          <svg className="w-12 h-12 text-violet-500" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 4.5c-4.97 0-9 2.239-9 5v5c0 2.761 4.03 5 9 5s9-2.239 9-5v-5c0-2.761-4.03-5-9-5z" />
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 12v2m0 0h.01" />
          </svg>
        </div>
        <h2 className="text-3xl font-bold text-white text-center">Privacy Pass</h2>
        <p className="text-gray-400 text-center mb-2">Securely access your account</p>
      </div>

      {/* Form Card */}
      <div className="bg-neutral-800 rounded-xl shadow-2xl border border-neutral-700 p-8 w-full max-w-md">
        <h3 className="text-2xl font-bold text-white mb-2">Welcome Back</h3>
        <p className="text-gray-400 mb-6">Enter your credentials to sign in to your account.</p>
        <div className="mb-4">
          <label className="block text-gray-300 mb-1" htmlFor="email">Email</label>
          <input
            id="email"
            type="email"
            autoComplete="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="w-full p-3 rounded bg-neutral-900 border border-neutral-700 text-white focus:outline-none focus:ring-4 focus:ring-violet-500 focus:border-violet-500 transition"
            placeholder="name@example.com"
          />
        </div>
        <div className="mb-6">
          <label className="block text-gray-300 mb-1" htmlFor="password">Password</label>
          <input
            id="password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full p-3 rounded bg-neutral-900 border border-neutral-700 text-white focus:outline-none focus:ring-4 focus:ring-violet-500 focus:border-violet-500 transition"
            placeholder="••••••••"
          />
        </div>
        <button
          onClick={handleRegister}
          className="w-full bg-violet-600 hover:bg-violet-700 text-white font-semibold py-3 rounded transition-colors"
        >
          Sign In
        </button>
        {error && <p className="text-red-500 mt-4 text-center">{error}</p>}
        <div className="mt-6 text-center">
          <a href="#" className="text-gray-400 hover:text-violet-400 text-sm">Forgot your password?</a>
        </div>
      </div>
    </div>
  );
};

export default App;
