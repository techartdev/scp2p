import React from "react";

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  hint?: string;
  error?: string;
  icon?: React.ReactNode;
}

export function Input({
  label,
  hint,
  error,
  icon,
  className = "",
  ...props
}: InputProps) {
  return (
    <div className="space-y-1.5">
      {label && (
        <label className="block text-xs font-medium text-text-secondary">
          {label}
        </label>
      )}
      <div className="relative">
        {icon && (
          <div className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted">
            {icon}
          </div>
        )}
        <input
          className={`
            w-full bg-surface border border-border rounded-xl
            px-3 py-2 text-sm text-text-primary
            placeholder:text-text-muted
            focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent/30
            transition-colors duration-150
            disabled:opacity-50 disabled:cursor-not-allowed
            ${icon ? "pl-9" : ""}
            ${error ? "border-danger focus:border-danger focus:ring-danger/30" : ""}
            ${className}
          `}
          {...props}
        />
      </div>
      {hint && !error && (
        <p className="text-xs text-text-muted">{hint}</p>
      )}
      {error && <p className="text-xs text-danger">{error}</p>}
    </div>
  );
}

interface TextAreaProps
  extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: string;
  hint?: string;
  error?: string;
}

export function TextArea({
  label,
  hint,
  error,
  className = "",
  ...props
}: TextAreaProps) {
  return (
    <div className="space-y-1.5">
      {label && (
        <label className="block text-xs font-medium text-text-secondary">
          {label}
        </label>
      )}
      <textarea
        className={`
          w-full bg-surface border border-border rounded-xl
          px-3 py-2 text-sm text-text-primary
          placeholder:text-text-muted
          focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent/30
          transition-colors duration-150
          disabled:opacity-50 disabled:cursor-not-allowed
          resize-none
          ${error ? "border-danger focus:border-danger focus:ring-danger/30" : ""}
          ${className}
        `}
        {...props}
      />
      {hint && !error && (
        <p className="text-xs text-text-muted">{hint}</p>
      )}
      {error && <p className="text-xs text-danger">{error}</p>}
    </div>
  );
}
