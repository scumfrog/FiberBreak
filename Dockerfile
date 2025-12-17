FROM node:18-alpine
WORKDIR /app

# Install system dependencies
RUN apk add --no-cache bash curl netcat-openbsd

# Initialize npm project
RUN npm init -y

# Install vulnerable versions
RUN npm install next@15.0.1 react@19.0.0-rc.0 react-dom@19.0.0-rc.0 --legacy-peer-deps

# Configure Next.js
RUN echo 'module.exports = { experimental: { serverActions: { bodySizeLimit: "10mb" } } }' > next.config.js

# Create app structure
RUN mkdir -p app

# Create vulnerable server action
RUN cat > app/actions.js << 'EOF'
'use server'

export async function processAction(formData) {
  const data = formData.get('input');
  console.log('[SERVER ACTION] Received:', data);
  return { success: true, data };
}
EOF

# Create page
RUN cat > app/page.js << 'EOF'
'use client'

import { processAction } from './actions';
import { useState } from 'react';

export default function Home() {
  const [result, setResult] = useState(null);
  
  async function handleSubmit(e) {
    e.preventDefault();
    const formData = new FormData(e.target);
    const res = await processAction(formData);
    setResult(res);
  }
  
  return (
    <div style={{
      padding: '2rem',
      fontFamily: 'monospace',
      backgroundColor: '#000',
      color: '#0f0',
      minHeight: '100vh'
    }}>
      <h1>CVE-2025-55182 Vulnerable Lab</h1>
      
      <div style={{
        border: '3px solid #f00',
        padding: '1.5rem',
        margin: '1rem 0',
        backgroundColor: '#1a0000',
        borderRadius: '8px'
      }}>
        <p style={{color: '#f00', fontWeight: 'bold', fontSize: '1.2rem'}}>
          VULNERABLE CONFIGURATION
        </p>
        <ul style={{marginTop: '1rem'}}>
          <li>Next.js: 15.0.1</li>
          <li>React: 19.0.0-rc.0</li>
          <li>CVE: 2025-55182 (React2Shell)</li>
          <li>Status: <span style={{color: '#f00'}}>EXPLOITABLE</span></li>
        </ul>
      </div>
      
      <form onSubmit={handleSubmit} style={{marginTop: '2rem'}}>
        <input 
          name="input"
          type="text"
          placeholder="Enter data"
          defaultValue="test"
          style={{
            padding: '0.75rem',
            width: '300px',
            backgroundColor: '#111',
            border: '2px solid #0f0',
            color: '#0f0',
            fontFamily: 'monospace'
          }}
        />
        <button 
          type="submit"
          style={{
            padding: '0.75rem 1.5rem',
            marginLeft: '1rem',
            backgroundColor: '#0f0',
            color: '#000',
            border: 'none',
            fontWeight: 'bold',
            cursor: 'pointer'
          }}
        >
          Execute Action
        </button>
      </form>
      
      {result && (
        <pre style={{
          marginTop: '2rem',
          padding: '1rem',
          backgroundColor: '#1a1a1a',
          border: '2px solid #0f0',
          color: '#0f0'
        }}>
          {JSON.stringify(result, null, 2)}
        </pre>
      )}
      
      <div style={{
        marginTop: '3rem',
        padding: '1rem',
        backgroundColor: '#1a1a00',
        border: '1px solid #ff0',
        borderRadius: '4px',
        fontSize: '0.9rem'
      }}>
        <strong>For Educational Use Only</strong><br/>
        This environment is intentionally vulnerable to CVE-2025-55182.
      </div>
    </div>
  );
}
EOF

# Create layout
RUN cat > app/layout.js << 'EOF'
export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <head><title>CVE-2025-55182 Lab</title></head>
      <body style={{margin: 0}}>{children}</body>
    </html>
  );
}
EOF

# Configure npm scripts
RUN npm pkg set scripts.dev="next dev -H 0.0.0.0"

EXPOSE 3000

CMD ["npm", "run", "dev"]
