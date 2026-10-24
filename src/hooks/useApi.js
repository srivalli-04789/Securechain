import { useCallback, useEffect, useState } from 'react'
export default function useApi(fn, deps = []) {
  const [s, set] = useState({ data: null, loading: true, error: null }), [tick, setTick] = useState(0), reload = useCallback(() => setTick(t => t + 1), [])
  useEffect(() => { let on = true; set(x => ({ ...x, loading: true })); fn().then(d => on && set({ data: d, loading: false, error: null })).catch(e => on && set({ data: null, loading: false, error: e.message })); return () => { on = false } }, [...deps, tick])
  return { ...s, reload }
}
