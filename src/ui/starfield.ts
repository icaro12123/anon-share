/**
 * Generative ASCII Starfield Canvas (Ice Palette)
 * Inspired by https://ascii.krackeddevs.com/#e=starfield&k=ice&sp=80&ce=7&ct=112
 * 
 * Engine: 3D Warp Starfield toward viewer with motion blur streaks
 * Look: 'ice' palette gradient stops (deep void -> electric cyan -> frost white)
 * Charset: ASCII luminosity ramp (' .:-=+*#%@')
 */

const ICE_STOPS = [
  [2, 4, 12],
  [10, 30, 90],
  [20, 90, 200],
  [40, 170, 235],
  [150, 225, 250],
  [245, 252, 255]
];

const ASCII_RAMP = ' .:-=+*#%@';

function lerp(a: number, b: number, t: number): number {
  return a + (b - a) * t;
}

function getIceColor(lum: number): string {
  const clamped = Math.max(0, Math.min(1, lum));
  const n = ICE_STOPS.length - 1;
  const f = clamped * n;
  const idx = Math.min(Math.floor(f), n - 1);
  const frac = f - idx;
  const c0 = ICE_STOPS[idx];
  const c1 = ICE_STOPS[idx + 1];
  const r = Math.round(lerp(c0[0], c1[0], frac));
  const g = Math.round(lerp(c0[1], c1[1], frac));
  const b = Math.round(lerp(c0[2], c1[2], frac));
  return `rgb(${r},${g},${b})`;
}

export class AsciiStarfield {
  private canvas: HTMLCanvasElement;
  private ctx: CanvasRenderingContext2D;
  private animId: number | null = null;
  private isRunning: boolean = false;
  private isPausedByVisibility: boolean = false;

  // Starfield parameters matching e=starfield&k=ice&sp=80&ce=7&ct=112
  private cellW: number = 7;
  private cellH: number = 10;
  private speed: number = 0.8; // sp=80
  private contrast: number = 1.12; // ct=112
  private numStars: number = 320;

  private sx: Float32Array = new Float32Array(0);
  private sy: Float32Array = new Float32Array(0);
  private sz: Float32Array = new Float32Array(0);

  private cols: number = 0;
  private rows: number = 0;
  private lum: Float32Array = new Float32Array(0);

  private pointer = { x: -1, y: -1, active: false };
  private lastTime: number = 0;

  constructor(canvas: HTMLCanvasElement) {
    this.canvas = canvas;
    const ctx = canvas.getContext('2d', { alpha: false });
    if (!ctx) throw new Error('Could not get 2D canvas context');
    this.ctx = ctx;

    this.onResize = this.onResize.bind(this);
    this.onVisibilityChange = this.onVisibilityChange.bind(this);
    this.onMouseMove = this.onMouseMove.bind(this);
    this.loop = this.loop.bind(this);

    this.init();
  }

  private init() {
    this.onResize();
    window.addEventListener('resize', this.onResize);
    window.addEventListener('visibilitychange', this.onVisibilityChange);
    window.addEventListener('mousemove', this.onMouseMove);

    // Reduced motion check
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (!prefersReducedMotion) {
      this.start();
    } else {
      this.renderFrame(0.016);
    }
  }

  private onResize() {
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const w = window.innerWidth;
    const h = window.innerHeight;

    this.canvas.width = Math.round(w * dpr);
    this.canvas.height = Math.round(h * dpr);

    this.cols = Math.floor(w / this.cellW);
    this.rows = Math.floor(h / this.cellH);
    if (this.cols <= 0 || this.rows <= 0) return;

    this.lum = new Float32Array(this.cols * this.rows);
    this.numStars = Math.max(160, Math.min(500, Math.floor((this.cols * this.rows) / 10)));

    this.sx = new Float32Array(this.numStars);
    this.sy = new Float32Array(this.numStars);
    this.sz = new Float32Array(this.numStars);

    for (let i = 0; i < this.numStars; i++) {
      this.spawnStar(i, true);
    }
  }

  private spawnStar(i: number, fullDepth: boolean) {
    this.sx[i] = Math.random() * 2 - 1;
    this.sy[i] = Math.random() * 2 - 1;
    this.sz[i] = fullDepth ? Math.random() : 1.0;
  }

  private onMouseMove(e: MouseEvent) {
    this.pointer.x = e.clientX / this.cellW;
    this.pointer.y = e.clientY / this.cellH;
    this.pointer.active = true;
  }

  private onVisibilityChange() {
    if (document.hidden) {
      if (this.isRunning) {
        this.stop();
        this.isPausedByVisibility = true;
      }
    } else {
      if (this.isPausedByVisibility) {
        this.isPausedByVisibility = false;
        this.start();
      }
    }
  }

  public start() {
    if (this.isRunning) return;
    this.isRunning = true;
    this.lastTime = performance.now();
    this.animId = requestAnimationFrame(this.loop);
  }

  public stop() {
    this.isRunning = false;
    if (this.animId !== null) {
      cancelAnimationFrame(this.animId);
      this.animId = null;
    }
  }

  public toggle(): boolean {
    if (this.isRunning) {
      this.stop();
      this.clear();
      return false;
    } else {
      this.start();
      return true;
    }
  }

  public isActive(): boolean {
    return this.isRunning;
  }

  private clear() {
    this.ctx.fillStyle = '#06080d';
    this.ctx.fillRect(0, 0, this.canvas.width, this.canvas.height);
  }

  private loop(now: number) {
    if (!this.isRunning) return;

    const deltaSec = Math.min((now - this.lastTime) / 1000, 0.05);
    this.lastTime = now;

    this.renderFrame(deltaSec);

    this.animId = requestAnimationFrame(this.loop);
  }

  private renderFrame(dt: number) {
    if (this.cols <= 0 || this.rows <= 0) return;

    this.lum.fill(0);

    const aspect = this.cellW / this.cellH;
    let vx = this.cols * 0.5;
    let vy = this.rows * 0.5;

    if (this.pointer.active && this.pointer.x >= 0) {
      vx = this.cols * 0.5 + (this.pointer.x - this.cols * 0.5) * 0.25;
      vy = this.rows * 0.5 + (this.pointer.y - this.rows * 0.5) * 0.25;
    }

    const spread = Math.min(this.cols, this.rows / aspect) * 0.9;
    const warp = dt * (0.35 + this.speed * 0.55);

    for (let i = 0; i < this.numStars; i++) {
      const pz = this.sz[i];
      this.sz[i] -= warp;

      if (this.sz[i] <= 0.02) {
        this.spawnStar(i, false);
        continue;
      }

      const z = this.sz[i];
      const px = vx + (this.sx[i] / z) * spread;
      const py = vy + (this.sy[i] / z) * spread * aspect;
      const cx = px | 0;
      const cy = py | 0;

      let bright = (0.16 + (1 - z) * 0.95) * this.contrast;
      if (bright > 1) bright = 1;

      // Motion blur streak from previous position
      const ppx = vx + (this.sx[i] / pz) * spread;
      const ppy = vy + (this.sy[i] / pz) * spread * aspect;
      const dlen = Math.abs(px - ppx) + Math.abs(py - ppy);
      const steps = Math.min(10, 2 + (dlen | 0));

      for (let s = 0; s <= steps; s++) {
        const tt = s / steps;
        const ix = (px + (ppx - px) * tt) | 0;
        const iy = (py + (ppy - py) * tt) | 0;

        if (ix < 0 || ix >= this.cols || iy < 0 || iy >= this.rows) continue;

        const v = bright * (1 - tt * 0.65);
        const k = iy * this.cols + ix;
        if (v > this.lum[k]) this.lum[k] = v;
      }

      if (cx >= 0 && cx < this.cols && cy >= 0 && cy < this.rows) {
        const ki = cy * this.cols + cx;
        if (bright > this.lum[ki]) this.lum[ki] = bright;
      }
    }

    // Canvas drawing
    const ctx = this.ctx;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const fontPx = Math.round(this.cellH * dpr * 0.92);

    ctx.save();
    ctx.setTransform(1, 0, 0, 1, 0, 0);

    // Deep void background
    ctx.fillStyle = '#06080d';
    ctx.fillRect(0, 0, this.canvas.width, this.canvas.height);

    ctx.font = `700 ${fontPx}px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace`;
    ctx.textBaseline = 'middle';
    ctx.textAlign = 'center';

    const renderW = this.cellW * dpr;
    const renderH = this.cellH * dpr;
    const hw = renderW / 2;
    const hh = renderH / 2;

    const rampLen = ASCII_RAMP.length;
    let prevFill = '';

    let idx = 0;
    for (let y = 0; y < this.rows; y++) {
      const cyp = y * renderH + hh;
      for (let x = 0; x < this.cols; x++, idx++) {
        const v = this.lum[idx];
        if (v <= 0.05) continue;

        const rampIdx = Math.min(rampLen - 1, Math.floor(v * (rampLen - 1)));
        const ch = ASCII_RAMP[rampIdx];
        if (ch === ' ') continue;

        const fill = getIceColor(v);
        if (fill !== prevFill) {
          ctx.fillStyle = fill;
          prevFill = fill;
        }

        ctx.fillText(ch, x * renderW + hw, cyp);
      }
    }

    ctx.restore();
  }

  public destroy() {
    this.stop();
    window.removeEventListener('resize', this.onResize);
    window.removeEventListener('visibilitychange', this.onVisibilityChange);
    window.removeEventListener('mousemove', this.onMouseMove);
  }
}

let activeInstance: AsciiStarfield | null = null;

export function initStarfield(canvasId: string = 'bg-starfield'): AsciiStarfield | null {
  const canvas = document.getElementById(canvasId) as HTMLCanvasElement;
  if (!canvas) return null;
  activeInstance = new AsciiStarfield(canvas);
  return activeInstance;
}

export function getStarfield(): AsciiStarfield | null {
  return activeInstance;
}
