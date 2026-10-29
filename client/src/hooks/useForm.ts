import { useState, useCallback } from 'react';

type Rules<T> = Partial<Record<keyof T, (v: unknown) => string | null>>;

export function useForm<T extends Record<string, unknown>>(initial: T, rules?: Rules<T>) {
  const [values, setValues] = useState<T>({ ...initial });
  const [errors, setErrors] = useState<Partial<Record<keyof T, string>>>({});
  const [submitting, setSubmitting] = useState(false);
  const [dirty, setDirty] = useState(false);

  const set = useCallback(<K extends keyof T>(key: K, value: T[K]) => {
    setValues(prev => ({ ...prev, [key]: value }));
    setDirty(true);
    if (rules?.[key]) {
      const err = rules[key]!(value);
      setErrors(prev => ({ ...prev, [key]: err ?? undefined }));
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const validate = useCallback((): boolean => {
    if (!rules) return true;
    const newErrors: Partial<Record<keyof T, string>> = {};
    let valid = true;
    for (const key of Object.keys(rules) as (keyof T)[]) {
      const err = rules[key]!(values[key]);
      if (err) { newErrors[key] = err; valid = false; }
    }
    setErrors(newErrors);
    return valid;
  }, [rules, values]);

  const reset = useCallback((next?: T) => {
    setValues(next ?? { ...initial });
    setErrors({});
    setDirty(false);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return { values, errors, submitting, setSubmitting, dirty, set, validate, reset, setValues };
}
