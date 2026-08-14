import React from 'react'
import ReactDOM from 'react-dom/client'
// Apply saved theme before render
const savedTheme = localStorage.getItem('em_theme') || 'dark';
document.documentElement.setAttribute('data-theme', savedTheme);

import App from './App.jsx'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)
