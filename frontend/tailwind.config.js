/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        vuln: {
          dark: '#070A11',
          panel: '#0D1322',
          card: '#111827',
          border: '#1E293B',
          cyan: '#00E5FF',
          blue: '#3B82F6',
          purple: '#8B5CF6',
          critical: '#EF4444',
          high: '#F97316',
          medium: '#F59E0B',
          low: '#06B6D4',
          info: '#64748B',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      boxShadow: {
        'glow-cyan': '0 0 20px -5px rgba(0, 229, 255, 0.3)',
        'glow-blue': '0 0 20px -5px rgba(59, 130, 246, 0.3)',
        'glow-red': '0 0 20px -5px rgba(239, 68, 68, 0.3)',
      },
    },
  },
  plugins: [],
};
