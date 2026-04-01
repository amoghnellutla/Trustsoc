export default function ErrorState({ message, onRetry }: { message?: string; onRetry?: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <div className="text-4xl mb-3">⚠️</div>
      <p className="text-danger font-medium mb-1">Failed to load data</p>
      <p className="text-muted text-sm mb-4">{message ?? 'Unknown error'}</p>
      {onRetry && (
        <button
          onClick={onRetry}
          className="px-4 py-2 bg-accent/10 text-accent border border-accent/30 rounded-md text-sm hover:bg-accent/20 transition-colors"
        >
          Retry
        </button>
      )}
    </div>
  )
}
