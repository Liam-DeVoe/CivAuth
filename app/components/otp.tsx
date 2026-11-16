import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type ChangeEvent,
  type ClipboardEvent,
  type KeyboardEvent,
  type RefObject,
} from "react";

const LENGTH = 6;

export interface CodeEntry {
  form: RefObject<HTMLFormElement | null>;
  code: string;
  digits: string[];
  setDigits: (update: (digits: string[]) => string[]) => void;
  focus: { index: number } | null;
  setFocus: (focus: { index: number }) => void;
  clear: () => void;
}

const EMPTY: string[] = Array<string>(LENGTH).fill("");

export function useCodeEntry(): CodeEntry {
  const form = useRef<HTMLFormElement>(null);
  const [digits, setDigits] = useState(EMPTY);
  const [focus, setFocus] = useState<{ index: number } | null>(null);
  const submitted = useRef(false);
  const code = digits.join("");
  useEffect(() => {
    if (code.length === LENGTH && !submitted.current) {
      submitted.current = true;
      form.current?.requestSubmit();
    }
  }, [code]);
  const clear = useCallback(() => {
    submitted.current = false;
    setDigits(EMPTY);
    setFocus({ index: 0 });
  }, []);
  return { form, code, digits, setDigits, focus, setFocus, clear };
}

export function OtpDigits({ entry: { digits, setDigits, focus, setFocus } }: { entry: CodeEntry }) {
  const boxes = useRef<(HTMLInputElement | null)[]>([]);
  useLayoutEffect(() => {
    if (focus) boxes.current[focus.index]?.focus();
  }, [focus]);

  function fill(from: number, entered: string) {
    setDigits((current) => {
      const next = [...current];
      for (let i = 0; i < entered.length && from + i < LENGTH; i++) next[from + i] = entered[i]!;
      return next;
    });
    setFocus({ index: Math.min(from + entered.length, LENGTH - 1) });
  }

  function onChange(index: number, event: ChangeEvent<HTMLInputElement>) {
    const entered = event.currentTarget.value.replace(/\D/g, "");
    if (entered.length > 1) {
      fill(index, entered);
      return;
    }
    setDigits((current) => current.map((digit, i) => (i === index ? entered : digit)));
    if (entered && index + 1 < LENGTH) setFocus({ index: index + 1 });
  }

  function onKeyDown(index: number, event: KeyboardEvent<HTMLInputElement>) {
    if (event.key === "Backspace" && !digits[index] && index > 0) {
      setDigits((current) => current.map((digit, i) => (i === index - 1 ? "" : digit)));
      setFocus({ index: index - 1 });
      event.preventDefault();
    }
    if (event.key === "ArrowLeft" && index > 0) boxes.current[index - 1]?.focus();
    if (event.key === "ArrowRight" && index + 1 < LENGTH) boxes.current[index + 1]?.focus();
  }

  function onPaste(index: number, event: ClipboardEvent<HTMLInputElement>) {
    const entered = event.clipboardData.getData("text").replace(/\D/g, "");
    if (entered) {
      event.preventDefault();
      fill(index, entered);
    }
  }

  const box = (index: number) => (
    <input
      key={index}
      ref={(element) => {
        boxes.current[index] = element;
      }}
      className="otp__digit"
      type="text"
      inputMode="numeric"
      pattern="[0-9]"
      maxLength={1}
      aria-label="Code digit"
      autoComplete={index === 0 ? "one-time-code" : undefined}
      value={digits[index]}
      onChange={(event) => onChange(index, event)}
      onKeyDown={(event) => onKeyDown(index, event)}
      onPaste={(event) => onPaste(index, event)}
      onFocus={(event) => event.currentTarget.select()}
    />
  );
  return (
    <div className="otp">
      {box(0)}
      {box(1)}
      {box(2)}
      <span className="otp__gap"></span>
      {box(3)}
      {box(4)}
      {box(5)}
    </div>
  );
}
