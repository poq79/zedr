/* 主题：dark-first，light 为变体；选择持久化 */
export type Theme = 'dark' | 'light';

export function getTheme(): Theme {
  return document.documentElement.classList.contains('light') ? 'light' : 'dark';
}

export function applyTheme(t: Theme) {
  document.documentElement.classList.toggle('light', t === 'light');
  localStorage.setItem('hg_theme', t);
}

export function initTheme() {
  applyTheme(localStorage.getItem('hg_theme') === 'light' ? 'light' : 'dark');
}

export function toggleTheme() {
  applyTheme(getTheme() === 'light' ? 'dark' : 'light');
}

/* 紧凑密度：值班大屏一屏多看几行 */
export function isDense() { return document.body.classList.contains('dense'); }
export function toggleDense() {
  document.body.classList.toggle('dense');
  localStorage.setItem('hg_dense', isDense() ? '1' : '0');
  return isDense();
}
export function initDense() {
  if (localStorage.getItem('hg_dense') === '1') document.body.classList.add('dense');
}
