import { type ChangeEvent, type ReactNode } from 'react';
import { domNodeToReact } from '../../runtime/react-dom-tree';
import { useRunFormState, useRunFormStore } from './store';

const NATIVE_CONTROL_IDS = new Set([
  'batchDomainsInput',
  'batchModeToggle',
  'domainInput',
  'reconProfileSelect',
]);

export function isNativeRunFormControl(element: Element): boolean {
  return NATIVE_CONTROL_IDS.has(element.id)
    || element.matches('input.mod[type="checkbox"]');
}

export function NativeRunFormControl({ element }: { element: Element }): ReactNode {
  const store = useRunFormStore();
  const state = useRunFormState();
  const module = element.matches('input.mod[type="checkbox"]')
    ? String((element as HTMLInputElement).value || '')
    : '';

  return domNodeToReact(element, `run-form-${element.id || module}`, {
    transformElement(current, originalProps) {
      if (current !== element) return originalProps;
      const props = { ...originalProps };
      const originalChange = props.onChange as ((event: ChangeEvent<any>) => void) | undefined;
      delete props.defaultChecked;
      delete props.defaultValue;

      if (module) {
        props.checked = Boolean(state.modules[module]);
        props.value = module;
        props.onChange = (event: ChangeEvent<HTMLInputElement>) => {
          store.setModule(module, event.currentTarget.checked);
          originalChange?.(event);
        };
      } else if (element.id === 'batchModeToggle') {
        props.checked = state.batchMode;
        props.onChange = (event: ChangeEvent<HTMLInputElement>) => {
          store.setBatchMode(event.currentTarget.checked);
          originalChange?.(event);
        };
      } else if (element.id === 'batchDomainsInput') {
        props.value = state.batchDomains;
        props.onChange = (event: ChangeEvent<HTMLTextAreaElement>) => {
          store.setBatchDomains(event.currentTarget.value);
          originalChange?.(event);
        };
      } else if (element.id === 'reconProfileSelect') {
        props.value = state.profile;
        props.onChange = (event: ChangeEvent<HTMLSelectElement>) => {
          store.setProfile(event.currentTarget.value);
          originalChange?.(event);
        };
      } else {
        props.value = state.target;
        props.onChange = (event: ChangeEvent<HTMLInputElement>) => {
          store.setTarget(event.currentTarget.value);
          originalChange?.(event);
        };
      }
      return props;
    },
  });
}
