import {
  useEffect,
  useRef,
  useState,
  type ComponentProps,
  type FormEvent,
  type MouseEvent,
  type ReactNode,
  type RefObject,
} from "react";
import { useLocation } from "react-router";

export function Warning({ children }: { children: ReactNode }) {
  return (
    <div className="message message--warning" role="alert">
      <svg className="message__icon" viewBox="0 0 20 20" aria-hidden="true">
        <path d="M10 1 1 18h18zm0 3.9L16.2 16H3.8zM9 8h2v4H9zm0 5h2v2H9z" />
      </svg>
      <div className="message__body">{children}</div>
    </div>
  );
}

export function Notice({ children, label }: { children: ReactNode; label?: string | null }) {
  return (
    <div className={"message message--notice" + (label ? " message--labelled" : "")}>
      {label ? (
        <div className="message__label">
          <InfoIcon />
          {label}
        </div>
      ) : (
        <InfoIcon />
      )}
      <div className="message__body">{children}</div>
    </div>
  );
}

export function InfoIcon() {
  return (
    <svg className="message__icon" viewBox="0 0 20 20" aria-hidden="true">
      <path d="M10 0a10 10 0 1 0 10 10A10 10 0 0 0 10 0zM9 5h2v2H9zm0 4h2v6H9z" />
    </svg>
  );
}

export interface Confirmation {
  form: { ref: RefObject<HTMLFormElement | null>; onSubmit: (event: FormEvent<HTMLFormElement>) => void };
  dialog: RefObject<HTMLDialogElement | null>;
  confirm: () => void;
}

export function useConfirmation(): Confirmation {
  const form = useRef<HTMLFormElement>(null);
  const dialog = useRef<HTMLDialogElement>(null);
  const confirmed = useRef(false);
  return {
    form: {
      ref: form,
      onSubmit(event) {
        if (confirmed.current) return;
        event.preventDefault();
        dialog.current?.showModal();
      },
    },
    dialog,
    confirm() {
      confirmed.current = true;
      dialog.current?.close();
      form.current?.requestSubmit();
    },
  };
}

export function Confirm({
  confirmation,
  title,
  body,
  action,
}: {
  confirmation: Confirmation;
  title: ReactNode;
  body: ReactNode;
  action: ReactNode;
}) {
  return (
    <Dialog className="dialog" ref={confirmation.dialog}>
      <div className="dialog__title">{title}</div>
      <div className="text">{body}</div>
      <div className="dialog__actions">
        <button type="button" className="button button--plain" onClick={() => confirmation.dialog.current?.close()}>
          Cancel
        </button>
        <button type="button" className="button button--danger" onClick={confirmation.confirm}>
          {action}
        </button>
      </div>
    </Dialog>
  );
}

export function CopyButton({
  value,
  ...props
}: { value: string } & Omit<ComponentProps<"button">, "value" | "type" | "className" | "onClick" | "children">) {
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return;
    const timer = setTimeout(() => setCopied(false), 1500);
    return () => clearTimeout(timer);
  }, [copied]);
  return (
    <button
      {...props}
      type="button"
      className={copied ? "button button--small button--done" : "button button--small"}
      onClick={() => navigator.clipboard.writeText(value).then(() => setCopied(true))}
    >
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

export function Dialog(props: ComponentProps<"dialog">) {
  return <dialog {...props} onClick={closeOnBackdrop} />;
}

function closeOnBackdrop(event: MouseEvent<HTMLDialogElement>): void {
  const dialog = event.currentTarget;
  const r = dialog.getBoundingClientRect();
  if (event.clientX < r.left || event.clientX > r.right || event.clientY < r.top || event.clientY > r.bottom) {
    dialog.close();
  }
}

export function Dropdown(props: Omit<ComponentProps<"details">, "ref">) {
  const ref = useRef<HTMLDetailsElement>(null);
  const location = useLocation();
  useEffect(() => {
    if (ref.current) ref.current.open = false;
  }, [location]);
  useEffect(() => {
    const closeOutside = (event: globalThis.MouseEvent) => {
      const details = ref.current;
      if (details?.open && !details.contains(event.target as Node)) details.open = false;
    };
    document.addEventListener("click", closeOutside);
    return () => document.removeEventListener("click", closeOutside);
  }, []);
  return <details {...props} ref={ref} />;
}
