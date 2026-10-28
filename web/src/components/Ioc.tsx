import { useState } from "react";

type Props = {
  value: string;
  className?: string;
};

export function Ioc({ value, className = "" }: Props) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1200);
    } catch {
      /* clipboard may be denied */
    }
  }

  return (
    <button
      type="button"
      onClick={copy}
      title="Copy"
      className={`font-mono text-[13px] tracking-tight text-paper/90 hover:text-amber transition-colors ${className}`}
    >
      {copied ? "copied" : value}
    </button>
  );
}
