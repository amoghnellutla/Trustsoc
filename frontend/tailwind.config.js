/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg:      '#0d1117',
        surface: '#161b22',
        border:  '#30363d',
        muted:   '#8b949e',
        accent:  '#58a6ff',
        danger:  '#f85149',
        success: '#3fb950',
        warning: '#d29922',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
    },
  },
  plugins: [],
}
