interface BadgeProps {
  children: React.ReactNode;
  variant?: "default" | "accent" | "success" | "warning" | "danger" | "cyan";
  size?: "sm" | "md";
}

const variantStyles: Record<string, string> = {
  default: "bg-surface-overlay text-text-secondary border-border",
  accent: "bg-accent/10 text-accent border-accent/20",
  success: "bg-success/10 text-success border-success/20",
  warning: "bg-warning/10 text-warning border-warning/20",
  danger: "bg-danger/10 text-danger border-danger/20",
  cyan: "bg-accent-cyan/10 text-accent-cyan border-accent-cyan/20",
};

const sizeStyles: Record<string, string> = {
  sm: "px-1.5 py-0.5 text-[10px]",
  md: "px-2.5 py-1 text-xs",
};

export function Badge({
  children,
  variant = "default",
  size = "md",
}: BadgeProps) {
  return (
    <span
      className={`
        inline-flex items-center font-medium rounded-lg border
        ${variantStyles[variant]}
        ${sizeStyles[size]}
      `}
    >
      {children}
    </span>
  );
}
