interface EmptyStateProps {
  icon: React.ReactNode;
  title: string;
  description?: string;
  action?: React.ReactNode;
}

export function EmptyState({
  icon,
  title,
  description,
  action,
}: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center py-16 px-4 animate-fade-in">
      <div className="p-4 rounded-2xl bg-surface-overlay text-text-muted mb-4">
        {icon}
      </div>
      <h3 className="text-sm font-medium text-text-secondary mb-1">{title}</h3>
      {description && (
        <p className="text-xs text-text-muted text-center max-w-xs mb-4">
          {description}
        </p>
      )}
      {action && <div>{action}</div>}
    </div>
  );
}
