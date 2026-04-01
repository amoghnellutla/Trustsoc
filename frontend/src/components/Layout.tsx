import { NavLink } from 'react-router-dom'
import { ReactNode } from 'react'

const NAV = [
  { to: '/',          label: 'Overview',  icon: '◉' },
  { to: '/alerts',    label: 'Alerts',    icon: '⚠' },
  { to: '/incidents', label: 'Incidents', icon: '🔗' },
  { to: '/mitre',     label: 'MITRE',     icon: '🗺' },
  { to: '/evidence',  label: 'Evidence',  icon: '🔒' },
]

export default function Layout({ children }: { children: ReactNode }) {
  return (
    <div className="min-h-screen flex bg-bg">
      {/* Sidebar */}
      <aside className="w-56 shrink-0 bg-surface border-r border-border flex flex-col">
        <div className="px-5 py-4 border-b border-border">
          <div className="flex items-center gap-2">
            <span className="text-accent text-xl font-bold">⚡</span>
            <span className="text-white font-semibold tracking-wide">TrustSOC</span>
          </div>
          <p className="text-muted text-xs mt-0.5">SOC Automation</p>
        </div>
        <nav className="flex-1 px-3 py-4 space-y-1">
          {NAV.map(({ to, label, icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${
                  isActive
                    ? 'bg-accent/10 text-accent font-medium'
                    : 'text-muted hover:text-white hover:bg-white/5'
                }`
              }
            >
              <span className="text-base">{icon}</span>
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="px-5 py-4 border-t border-border">
          <p className="text-muted text-xs">v0.1.0 · open-source</p>
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 overflow-auto">
        {children}
      </main>
    </div>
  )
}
