import {useEffect, useRef} from 'react';

import {getCurrentWindow, LogicalSize} from '@tauri-apps/api/window';

export function useAutoResizeWindow<T extends HTMLElement>(deps: unknown[] = []) {
  const containerRef = useRef<T>(null);

  useEffect(() => {
    if (!containerRef.current) return;

    const resizeWindow = async () => {
      if (!containerRef.current) return;

      // get new height but clamp to [200px, 600px]
      const contentHeight = containerRef.current.scrollHeight;
      const newHeight = Math.min(Math.max(contentHeight, 200), 600);

      try {
        const window = getCurrentWindow();
        const currentSize = await window.innerSize();
        const scaleFactor = await window.scaleFactor();
        const logicalWidth = currentSize.width / scaleFactor;
        // update height but preserve width
        await window.setSize(new LogicalSize(logicalWidth, newHeight));
      } catch (error) {
        console.error('Failed to resize window:', error);
      }
    };

    // Initial resize
    resizeWindow();

    // Listen for content size changes
    const resizeObserver = new ResizeObserver(() => {
      resizeWindow();
    });
    resizeObserver.observe(containerRef.current);

    return () => resizeObserver.disconnect();
  }, deps);

  return containerRef;
}
