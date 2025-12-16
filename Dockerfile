FROM node:18-alpine

WORKDIR /app

# Install system dependencies
RUN apk add --no-cache bash curl

# Initialize npm project
RUN npm init -y

# Install vulnerable Next.js and React versions
# Next.js 15.1.0 is vulnerable to CVE-2025-55182
# React 19.0.0 is vulnerable to CVE-2025-55182
RUN npm install \
    next@15.1.0 \
    react@19.0.0 \
    react-dom@19.0.0 \
    --legacy-peer-deps

# Install TypeScript and types
RUN npm install -D \
    typescript \
    @types/react \
    @types/node \
    --legacy-peer-deps

# Create Next.js configuration
RUN cat > next.config.js << 'EOF'
/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  experimental: {}
}

module.exports = nextConfig
EOF

# Create TypeScript configuration
RUN cat > tsconfig.json << 'EOF'
{
  "compilerOptions": {
    "target": "es5",
    "lib": ["dom", "dom.iterable", "esnext"],
    "allowJs": true,
    "skipLibCheck": true,
    "strict": false,
    "noEmit": true,
    "esModuleInterop": true,
    "module": "esnext",
    "moduleResolution": "bundler",
    "resolveJsonModule": true,
    "isolatedModules": true,
    "jsx": "preserve",
    "incremental": true,
    "plugins": [
      {
        "name": "next"
      }
    ],
    "paths": {
      "@/*": ["./*"]
    }
  },
  "include": ["next-env.d.ts", "**/*.ts", "**/*.tsx", ".next/types/**/*.ts"],
  "exclude": ["node_modules"]
}
EOF

# Create app directory structure (App Router)
RUN mkdir -p app/actions

# Create server action (required for RSC vulnerability)
RUN cat > app/actions/test.ts << 'EOF'
'use server';

export async function testAction(data: string) {
  console.log('Server action called with:', data);
  return { 
    success: true, 
    message: 'Server action executed',
    timestamp: new Date().toISOString()
  };
}
EOF

# Create root layout
RUN cat > app/layout.tsx << 'EOF'
export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <head>
        <meta charSet="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Vulnerable Next.js - CVE-2025-55182</title>
      </head>
      <body style={{ margin: 0, padding: 0 }}>
        {children}
      </body>
    </html>
  )
}
EOF

# Create main page
RUN cat > app/page.tsx << 'EOF'
import { testAction } from './actions/test';

export default async function Home() {
  // Call server action to ensure RSC is active
  const result = await testAction('page-init');
  
  return (
    <main style={{
      minHeight: '100vh',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      backgroundColor: '#0a0a0a',
      color: '#ffffff',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      padding: '2rem'
    }}>
      <div style={{
        textAlign: 'center',
        maxWidth: '800px'
      }}>
        {/* Warning Icon */}
        <div style={{ fontSize: '5rem', marginBottom: '1rem' }}>
          ⚠️
        </div>
        
        {/* Title */}
        <h1 style={{
          fontSize: '3.5rem',
          fontWeight: 'bold',
          marginBottom: '1rem',
          background: 'linear-gradient(135deg, #ff6b6b 0%, #ee5a6f 100%)',
          WebkitBackgroundClip: 'text',
          WebkitTextFillColor: 'transparent',
          backgroundClip: 'text'
        }}>
          Vulnerable Next.js App
        </h1>
        
        {/* Subtitle */}
        <p style={{
          fontSize: '1.5rem',
          color: '#ff6b6b',
          marginBottom: '2rem',
          fontWeight: '500'
        }}>
          CVE-2025-55182 Test Environment
        </p>
        
        {/* Info Box */}
        <div style={{
          backgroundColor: '#1a1a1a',
          border: '2px solid #ff6b6b',
          borderRadius: '12px',
          padding: '2rem',
          marginTop: '2rem'
        }}>
          <h2 style={{
            fontSize: '1.2rem',
            color: '#ffffff',
            marginBottom: '1rem',
            fontWeight: '600'
          }}>
            Environment Details
          </h2>
          
          <div style={{
            display: 'grid',
            gap: '1rem',
            textAlign: 'left'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: '#888' }}>React Version:</span>
              <span style={{ color: '#ff6b6b', fontWeight: 'bold' }}>19.0.0 (VULNERABLE)</span>
            </div>
            
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: '#888' }}>Next.js Version:</span>
              <span style={{ color: '#ff6b6b', fontWeight: 'bold' }}>15.1.0 (VULNERABLE)</span>
            </div>
            
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: '#888' }}>Router:</span>
              <span style={{ color: '#4caf50' }}>App Router (RSC Enabled)</span>
            </div>
            
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: '#888' }}>CVE:</span>
              <span style={{ color: '#ff6b6b', fontWeight: 'bold' }}>CVE-2025-55182</span>
            </div>
            
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: '#888' }}>CVSS Score:</span>
              <span style={{ color: '#ff6b6b', fontWeight: 'bold' }}>10.0 (CRITICAL)</span>
            </div>
            
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: '#888' }}>Status:</span>
              <span style={{ color: '#4caf50', fontWeight: 'bold' }}>✓ READY FOR TESTING</span>
            </div>
          </div>
        </div>
        
        {/* Usage Instructions */}
        <div style={{
          marginTop: '2rem',
          padding: '1.5rem',
          backgroundColor: '#1a1a1a',
          borderRadius: '8px',
          textAlign: 'left',
          fontSize: '0.9rem',
          color: '#aaa'
        }}>
          <p style={{ marginBottom: '0.5rem' }}>
            <strong style={{ color: '#fff' }}>Test with:</strong>
          </p>
          <code style={{
            display: 'block',
            backgroundColor: '#0a0a0a',
            padding: '0.75rem',
            borderRadius: '4px',
            color: '#4caf50',
            fontFamily: 'monospace',
            fontSize: '0.85rem',
            overflowX: 'auto'
          }}>
            python3 fiberbreak.py -u http://localhost:3000 detect
          </code>
        </div>
        
        {/* Server Action Result */}
        <div style={{
          marginTop: '1.5rem',
          fontSize: '0.8rem',
          color: '#666'
        }}>
          Server Action: {result.message} at {result.timestamp}
        </div>
      </div>
    </main>
  )
}
EOF

# Update package.json scripts
RUN npm pkg set scripts.dev="next dev" && \
    npm pkg set scripts.build="next build" && \
    npm pkg set scripts.start="next start"

# Expose port
EXPOSE 3000

# Start Next.js dev server
CMD ["npm", "run", "dev"]
