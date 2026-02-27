interface SelectProps extends React.SelectHTMLAttributes<HTMLSelectElement> {
  label?: string;
  options: { value: string; label: string }[];
}

export function Select({
  label,
  options,
  className = "",
  ...props
}: SelectProps) {
  return (
    <div className="space-y-1.5">
      {label && (
        <label className="block text-xs font-medium text-text-secondary">
          {label}
        </label>
      )}
      <select
        className={`
          w-full bg-surface border border-border rounded-xl
          px-3 py-2 text-sm text-text-primary
          focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent/30
          transition-colors duration-150
          disabled:opacity-50 disabled:cursor-not-allowed
          appearance-none cursor-pointer
          ${className}
        `}
        {...props}
      >
        {options.map((opt) => (
          <option key={opt.value} value={opt.value}>
            {opt.label}
          </option>
        ))}
      </select>
    </div>
  );
}
