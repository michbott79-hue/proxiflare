import { useState } from 'react';
import { useDaemon } from './hooks/useDaemon';
import MasterPasswordDialog from './components/MasterPasswordDialog';
import Proxies from './pages/Proxies';
import Rules from './pages/Rules';
import Chains from './pages/Chains';
import Log from './pages/Log';
import Inspect from './pages/Inspect';
import Settings from './pages/Settings';

type Tab = 'proxies' | 'rules' | 'chains' | 'log' | 'inspect' | 'settings';

const TABS: { id: Tab; label: string }[] = [
  { id: 'proxies', label: 'Proxies' },
  { id: 'rules', label: 'Rules' },
  { id: 'chains', label: 'Chains' },
  { id: 'log', label: 'Log' },
  { id: 'inspect', label: 'Inspect' },
  { id: 'settings', label: 'Settings' },
];

export default function App() {
  const [activeTab, setActiveTab] = useState<Tab>('proxies');
  const daemon = useDaemon();

  // For dev mode: skip master password if daemon is not connected at all
  const showPasswordDialog = daemon.connected && !daemon.unlocked;

  function renderPage() {
    switch (activeTab) {
      case 'proxies': return <Proxies />;
      case 'rules': return <Rules />;
      case 'chains': return <Chains />;
      case 'log': return <Log />;
      case 'inspect': return <Inspect />;
      case 'settings': return <Settings daemon={daemon} />;
    }
  }

  return (
    <div className="flex h-screen flex-col bg-[#0f1117] text-[#e2e8f0]">
      {/* Header */}
      <header className="flex h-12 shrink-0 items-center justify-between border-b border-[#2d3348] bg-[#1a1d27] px-4">
        <span className="text-sm font-bold tracking-wide">ProxiFlare</span>
        <div className="flex items-center gap-2 text-xs text-[#64748b]">
          {daemon.status && daemon.connected && (
            <span>{daemon.status.connections} conn</span>
          )}
          <span
            className={`inline-block h-2 w-2 rounded-full ${
              daemon.connected
                ? daemon.status?.running
                  ? 'bg-[#22c55e]'
                  : 'bg-[#f59e0b]'
                : 'bg-[#ef4444]'
            }`}
            title={
              daemon.connected
                ? daemon.status?.running
                  ? 'Connected'
                  : 'Daemon stopped'
                : 'Disconnected'
            }
          />
          <span>
            {daemon.connected
              ? daemon.status?.running
                ? 'Connected'
                : 'Stopped'
              : 'Disconnected'}
          </span>
        </div>
      </header>

      {/* Tab bar */}
      <nav className="flex h-10 shrink-0 border-b border-[#2d3348] bg-[#1a1d27]">
        {TABS.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`relative px-5 text-sm font-medium transition-colors ${
              activeTab === tab.id
                ? 'text-[#e2e8f0]'
                : 'text-[#64748b] hover:text-[#e2e8f0]'
            }`}
          >
            {tab.label}
            {activeTab === tab.id && (
              <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-[#6366f1]" />
            )}
          </button>
        ))}
      </nav>

      {/* Content */}
      <main className="flex-1 overflow-auto p-4">
        {renderPage()}
      </main>

      {/* Master password overlay */}
      {showPasswordDialog && (
        <MasterPasswordDialog onUnlocked={() => daemon.setUnlocked(true)} />
      )}
    </div>
  );
}
