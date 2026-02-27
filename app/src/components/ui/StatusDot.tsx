interface StatusDotProps {
  status: "online" | "offline" | "warning" | "syncing";
  size?: "sm" | "md" | "lg";
  label?: string;
}

const colorMap: Record<string, string> = {
  online: "bg-success",
  offline: "bg-text-muted",
  warning: "bg-warning",
  syncing: "bg-accent",
};

const pulseMap: Record<string, string> = {
  online: "bg-success",
  syncing: "bg-accent",
  warning: "",
  offline: "",
};

const sizeMap: Record<string, string> = {
  sm: "h-2 w-2",
  md: "h-2.5 w-2.5",
  lg: "h-3 w-3",
};

const labelMap: Record<string, string> = {
  online: "Online",
  offline: "Offline",
  warning: "Warning",
  syncing: "Syncing",
};

export function StatusDot({
  status,
  size = "md",
  label,
}: StatusDotProps) {
  const showPulse = status === "online" || status === "syncing";

  return (
    <div className="inline-flex items-center gap-2">
      <span className="relative flex">
        <span className={`rounded-full ${colorMap[status]} ${sizeMap[size]}`} />
        {showPulse && (
          <span
            className={`absolute inset-0 rounded-full ${pulseMap[status]} animate-ping opacity-40`}
          />
        )}
      </span>
      {label !== undefined ? (
        <span className="text-xs text-text-secondary">{label}</span>
      ) : (
        <span className="text-xs text-text-secondary">{labelMap[status]}</span>
      )}
    </div>
  );
}
